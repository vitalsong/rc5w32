# RC5
RC5 encryption algorithm (32bit word size)

It's modified overlap version - no restrictions on the multiples of the data size.

Standart version:

```c
uint8_t data[32];
uint8_t encrypted[32];
uint8_t decrypted[32];
uint32_t key = 0xFFFF7777;
RC5w32* rc = RC5w32_Create(18, (const uint8_t*)&key, sizeof(key));
RC5w32_Encrypt(rc, data, encrypted, 32);
RC5w32_Decrypt(rc, encrypted, decrypted, 32);
int cmp = memcmp((char*)data, (char*)decrypted, 32);
assert(cmp == 0);
RC5w32_Destroy(rc);
```

Embedded version:

* Dynamic memory is not allocated
* Use RC5_EMBEDDED defenition

```c
uint8_t data[32];
uint8_t encrypted[32];
uint8_t decrypted[32];
uint8_t rc_mem[RC5W32_MEM_SIZE(18)];
uint32_t key = 0xFFFF7777;

RC5w32 rc;
RC5w32_Init(&rc, 18, (const uint8_t*)&key, sizeof(key), rc_mem, sizeof(rc_mem));
RC5w32_Encrypt(&rc, data, encrypted, 32);
RC5w32_Decrypt(&rc, encrypted, decrypted, 32);
int cmp = memcmp((char*)data, (char*)decrypted, 32);
assert(cmp == 0);
```
