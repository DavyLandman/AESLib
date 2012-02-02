#ifndef CRYPTOLIB_H
#define CRYPTOLIB_H
#include <stdint.h>
void aes128_encrypt(uint8_t* key, uint8_t* iv, uint8_t* data, uint32_t data_len);

#endif
