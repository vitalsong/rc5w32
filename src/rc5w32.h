#pragma once

#include <stdint.h>

#define RC5W32_MEM_SIZE(NR) (2 * ((NR) + 1) * 4)

typedef struct {
  int nr;      ///< number of rounds
  uint32_t *s; ///< ext-key vector
  void *_pmem;
} RC5w32;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RC5_EMBEDDED

/*!
 * \brief Create encryptor
 * \param nround The number of rounds
 * \param key Key block
 * \param nkey Key size
 * \return Object handle
 */
RC5w32 *RC5w32_Create(uint8_t nround, const uint8_t *key, uint8_t nkey);

/*!
 * \brief Destroy encryptor
 * \param self Object handle
 */
void RC5w32_Destroy(RC5w32 *self);

#else

/*!
 * \brief Init encryptor
 * \warning nmem >= RC5W32_MEM_SIZE(nround)
 * \param self Object handle
 * \param nround The number of rounds
 * \param key Key block
 * \param nkey Key size
 * \param mem Memory block for storing parameters
 * \param nmem Memory block size
 */
void RC5w32_Init(RC5w32 *self, uint8_t nround, const uint8_t *key, uint8_t nkey,
                 uint8_t *mem, uint16_t nmem);

#endif

/*!
 * \brief Data encryption
 * \warning size >= 8
 * \param self Object handle
 * \param in Input data (unencrypted)
 * \param out Output data (encrypted)
 * \param size Data block size
 */
void RC5w32_Encrypt(RC5w32 *self, const uint8_t *in, uint8_t *out,
                    uint16_t size);

/*!
 * \brief Data decryption
 * \warning size >= 8
 * \param self Object handle
 * \param in Input data (encrypted)
 * \param out Output data (unencrypted)
 * \param size Data block size
 */
void RC5w32_Decrypt(RC5w32 *self, const uint8_t *in, uint8_t *out,
                    uint16_t size);

#ifdef __cplusplus
}
#endif
