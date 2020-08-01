#include <rc5w32.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

//-------------------------------------------------------------------------------------------------
void run_test(int nround, int nkey, int data_size)
{
    const int NROUND = nround;
    const int KEY_SIZE = nkey;
    const int DATA_SIZE = data_size;

    uint8_t key[KEY_SIZE];
    uint8_t data[DATA_SIZE];
    uint8_t data_enc[DATA_SIZE];
    uint8_t data_dec[DATA_SIZE];

    for (int i = 0; i < KEY_SIZE; ++i) {
        key[i] = rand() % 255;
    }

    for (int i = 0; i < DATA_SIZE; ++i) {
        data[i] = rand() % 255;
    }

    RC5w32* rc = RC5w32_Create(NROUND, key, KEY_SIZE);
    RC5w32_Encrypt(rc, data, data_enc, DATA_SIZE);
    RC5w32_Decrypt(rc, data_enc, data_dec, DATA_SIZE);
    auto cmp = memcmp((char*)data, (char*)data_dec, DATA_SIZE);
    RC5w32_Destroy(rc);
    assert(cmp == 0);
}

//-------------------------------------------------------------------------------------------------
void assert_not_equal(int nround, int nkey, int data_size, const uint8_t* key1, const uint8_t* key2)
{
    const int NROUND = nround;
    const int DATA_SIZE = data_size;

    uint8_t data[DATA_SIZE];
    uint8_t data_enc[DATA_SIZE];
    uint8_t data_dec1[DATA_SIZE];
    uint8_t data_dec2[DATA_SIZE];

    for (int i = 0; i < DATA_SIZE; ++i) {
        data[i] = rand() % 255;
    }

    RC5w32* rc1 = RC5w32_Create(NROUND, (const uint8_t*)key1, nkey);
    RC5w32* rc2 = RC5w32_Create(NROUND, (const uint8_t*)key2, nkey);

    RC5w32_Encrypt(rc1, data, data_enc, DATA_SIZE);

    // different keys
    RC5w32_Decrypt(rc1, data_enc, data_dec1, DATA_SIZE);
    RC5w32_Decrypt(rc2, data_enc, data_dec2, DATA_SIZE);

    auto cmp1 = memcmp((char*)data, (char*)data_dec1, DATA_SIZE);
    auto cmp2 = memcmp((char*)data, (char*)data_dec2, DATA_SIZE);

    RC5w32_Destroy(rc1);
    RC5w32_Destroy(rc2);

    assert(cmp1 == 0);
    assert(cmp2 != 0);
}

//-------------------------------------------------------------------------------------------------
void TestRC5w32Key4()
{
    for (int i = 0; i < 10000; ++i) {
        run_test(10, 4, 32);
    }
}

//-------------------------------------------------------------------------------------------------
void TestRC5w32Key8()
{
    for (int i = 0; i < 10000; ++i) {
        run_test(9, 8, 32);
    }
}

//-------------------------------------------------------------------------------------------------
void TestRC5w32Key16()
{
    for (int i = 0; i < 10000; ++i) {
        run_test(10, 16, 32);
    }
}

//-------------------------------------------------------------------------------------------------
void TestRC5w32KeyCollisions()
{
    uint8_t key1[255];
    uint8_t key2[255];

    //key size from 1 to 255
    for (int nkey = 1; nkey < 255; ++nkey) {
        //for 1000 random keys and data
        for (int i = 0; i < 1000; ++i) {
            //generate equal key pair
            for (int k = 0; k < nkey; ++k) {
                key1[k] = rand() % 255;
                key2[k] = key1[k];
            }

            //inverse random bit in key
            uint8_t pos = rand() % nkey;
            uint8_t bit = rand() % 8;
            key2[pos] ^= (1 << bit);

            //rounds from 0 to 32
            for (int k = 0; k < 32; ++k) {
                assert_not_equal(k, nkey, 32, key1, key2);
            }
        }
    }
}

//-------------------------------------------------------------------------------------------------
int main()
{
    TestRC5w32Key4();
    TestRC5w32Key8();
    TestRC5w32Key16();
    TestRC5w32KeyCollisions();
    return 0;
}
