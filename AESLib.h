/*
    This file is part of the aeslib.
    Copyright (C) 2012 Davy Landman (davy.landman@gmail.com) 

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef AESLIB_H
#define AESLIB_H
#include <stdint.h>
#ifdef __cplusplus
extern "C"{
#endif
// encrypt multiple blocks of 128bit data, data_len but be mod 16
// key and iv are assumed to be both 128bit thus 16 uint8_t's
void aes128_cbc_enc(const uint8_t* key, const uint8_t* iv, void* data, const uint16_t data_len);

// encrypt multiple blocks of 128bit data, data_len but be mod 16
// key and iv are assumed to be both 192bit thus 24 uint8_t's
void aes192_cbc_enc(const uint8_t* key, const uint8_t* iv, void* data, const uint16_t data_len);

// encrypt single 128bit block. data is assumed to be 16 uint8_t's
// key is assumed to be 128bit thus 16 uint8_t's
void aes128_enc_single(const uint8_t* key, void* data);

// encrypt multiple blocks of 128bit data, data_len but be mod 16
// key is assumed to be 128bit thus 16 uint8_t's
void aes128_enc_multiple(const uint8_t* key, void* data, const uint16_t data_len);

// encrypt single 128bit block. data is assumed to be 16 uint8_t's
// key is assumed to be 256bit thus 32 uint8_t's
void aes256_enc_single(const uint8_t* key, void* data);

// encrypt multiple blocks of 128bit data, data_len but be mod 16
// key is assumed to be 256bit thus 32 uint8_t's
void aes256_enc_multiple(const uint8_t* key, void* data, const uint16_t data_len);

typedef void* aes_context;

// prepare an encrypted to use for encrypting multiple blocks lateron.
// key and iv are assumed to be both 128bit thus 16 uint8_t's
aes_context aes128_cbc_enc_start(const uint8_t* key, const void* iv);

// prepare an encrypted to use for encrypting multiple blocks lateron.
// key and iv are assumed to be both 192bit thus 24 uint8_t's
aes_context aes192_cbc_enc_start(const uint8_t* key, const void* iv);

// encrypt one or more blocks of 128bit data
// data_len should be mod 16
void aes128_cbc_enc_continue(const aes_context ctx, void* data, const uint16_t data_len);

// encrypt one or more blocks of 128bit data
// data_len should be mod 16
void aes192_cbc_enc_continue(const aes_context ctx, void* data, const uint16_t data_len);

// cleanup encryption context
void aes128_cbc_enc_finish(const aes_context ctx);

// cleanup encryption context
void aes192_cbc_enc_finish(const aes_context ctx);

// decrypt multiple blocks of 128bit data, data_len but be mod 16
// key and iv are assumed to be both 128bit thus 16 uint8_t's
void aes128_cbc_dec(const uint8_t* key, const uint8_t* iv, void* data, const uint16_t data_len);

// decrypt multiple blocks of 128bit data, data_len but be mod 16
// key and iv are assumed to be both 192bit thus 24 uint8_t's
void aes192_cbc_dec(const uint8_t* key, const uint8_t* iv, void* data, const uint16_t data_len);

// decrypt single 128bit block. data is assumed to be 16 uint8_t's
// key is assumed to be 128bit thus 16 uint8_t's
void aes128_dec_single(const uint8_t* key, void* data);

// decrypt multiple blocks of 128bit data, data_len but be mod 16
// key is assumed to be 128bit thus 16 uint8_t's
void aes128_dec_multiple(const uint8_t* key, void* data, const uint16_t data_len);

// decrypt single 128bit block. data is assumed to be 16 uint8_t's
// key is assumed to be 256bit thus 32 uint8_t's
void aes256_dec_single(const uint8_t* key, void* data);

// decrypt multiple blocks of 128bit data, data_len but be mod 16
// key is assumed to be 256bit thus 32 uint8_t's
void aes256_dec_multiple(const uint8_t* key, void* data, const uint16_t data_len);

// prepare an decrypter to use for decrypting multiple blocks lateron.
// key and iv are assumed to be both 128bit thus 16 uint8_t's
aes_context aes128_cbc_dec_start(const uint8_t* key, const void* iv);

// prepare an decrypter to use for decrypting multiple blocks lateron.
// key and iv are assumed to be both 192bit thus 24 uint8_t's
aes_context aes192_cbc_dec_start(const uint8_t* key, const void* iv);

// decrypt one or more blocks of 128bit data
// data_len should be mod 16
void aes128_cbc_dec_continue(const aes_context ctx, void* data, const uint16_t data_len);

// decrypt one or more blocks of 128bit data
// data_len should be mod 16
void aes192_cbc_dec_continue(const aes_context ctx, void* data, const uint16_t data_len);

// cleanup decryption context
void aes128_cbc_dec_finish(const aes_context ctx);

// cleanup decryption context
void aes192_cbc_dec_finish(const aes_context ctx);

#ifdef __cplusplus
}
#endif
#endif
