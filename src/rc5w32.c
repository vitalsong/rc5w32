#include "rc5w32.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define NW (32)
#define ROTL(X, Y) (((X) << (Y & (NW - 1))) | ((X) >> (NW - (Y & (NW - 1)))))
#define ROTR(X, Y) (((X) >> (Y & (NW - 1))) | ((X) << (NW - (Y & (NW - 1)))))
#define MAX(X, Y) ((X) >= (Y) ? (X) : (Y))
#define CEIL(X, Y) ((X)/(Y) + (X % Y != 0))

//-------------------------------------------------------------------------------------------------
static void _Setup(RC5w32* self, const uint8_t* key, uint8_t nkey)
{
    int i, j, k;
    static const uint32_t P = 0xb7e15163;
    static const uint32_t Q = 0x9e3779b9;
    uint32_t* S = self->s;
    uint32_t L[255];
    const int w = NW;
    const int r = self->nr;
    const int b = nkey;
    const int u = w / 8;
    const int c = CEIL(MAX(b, 1), u);
    const int t = 2 * (r + 1);
    const int nt = 3 * MAX(t, c);
    int32_t A, B;

    // Converting secret key K from bytes to words
    memset(L, 0, 255 * sizeof(*L));
    for (i = b - 1; i >= 0; --i) {
        L[i / u] = (ROTL(L[i / u], 8)) + key[i];
    }

    // Initializing sub-key S
    S[0] = P;
    for (i = 1; i < 2 * (r + 1); ++i) {
        S[i] = S[i - 1] + Q;
    }

    // Sub-key mixing
    i = j = 0;
    A = B = 0;
    for (k = 0; k < nt; k++) {
        A = S[i] = ROTL((S[i] + A + B), 3);
        B = L[j] = ROTL((L[j] + A + B), (A + B));
        i = (i + 1) % t;
        j = (j + 1) % c;
    }
}

//-------------------------------------------------------------------------------------------------
void RC5w32_Init(RC5w32* self, uint8_t nround, const uint8_t* key, uint8_t nkey, uint8_t* mem, uint16_t nmem)
{
    assert(nmem >= (2 * (nround + 1) * sizeof(uint32_t)));
    assert(sizeof(uint32_t) == 4);

    self->s = (uint32_t*)mem;
    self->nr = nround;

    _Setup(self, key, nkey);
}

#ifndef RC5_EMBEDDED

//-------------------------------------------------------------------------------------------------
RC5w32* RC5w32_Create(uint8_t nround, const uint8_t* key, uint8_t nkey)
{
    RC5w32* self = malloc(sizeof(RC5w32));
    int size = 2 * (nround + 1) * sizeof(uint32_t);
    self->nr = nround;
    self->_pmem = malloc(size);
    RC5w32_Init(self, nround, key, nkey, self->_pmem, size);

    return self;
}

//-------------------------------------------------------------------------------------------------
void RC5w32_Destroy(RC5w32* self)
{
    free(self->_pmem);
    free(self);
}

#endif

//-------------------------------------------------------------------------------------------------
static void _EncryptBlock(RC5w32* self, const uint32_t* pt, uint32_t* ct)
{
    int i;
    uint32_t a, b;
    const uint32_t* s = self->s;

    a = pt[0] + s[0];
    b = pt[1] + s[1];
    for (i = 1; i <= self->nr; i++) {
        a = ROTL(a ^ b, b) + s[2 * i];
        b = ROTL(b ^ a, a) + s[2 * i + 1];
    }

    ct[0] = a;
    ct[1] = b;
}

//-------------------------------------------------------------------------------------------------
static void _DecryptBlock(RC5w32* self, const uint32_t* ct, uint32_t* pt)
{
    int i;
    uint32_t b, a;
    const uint32_t* s = self->s;

    b = ct[1];
    a = ct[0];
    for (i = self->nr; i > 0; i--) {
        b = ROTR(b - s[2 * i + 1], a) ^ a;
        a = ROTR(a - s[2 * i], b) ^ b;
    }

    pt[1] = b - s[1];
    pt[0] = a - s[0];
}

//-------------------------------------------------------------------------------------------------
void RC5w32_Encrypt(RC5w32* self, const uint8_t* in, uint8_t* out, uint16_t size)
{
    int i, n;

    assert(size >= 8);

    memcpy(out, in, size);
    n = size - 8 + 1;
    for (i = 0; i < n; ++i) {
        _EncryptBlock(self, (const uint32_t*)(out + i), (uint32_t*)(out + i));
    }
}

//-------------------------------------------------------------------------------------------------
void RC5w32_Decrypt(RC5w32* self, const uint8_t* in, uint8_t* out, uint16_t size)
{
    int i, n;

    assert(size >= 8);

    memcpy(out, in, size);
    n = size - 8 + 1;
    for (i = 0; i < n; ++i) {
        _DecryptBlock(self, (const uint32_t*)(out + size - i - 8), (uint32_t*)(out + size - i - 8));
    }
}
