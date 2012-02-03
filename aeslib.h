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
// encrypt multiple blocks of 128bit data, data_len but be mod 16
// key and iv are assumed to be both 128bit thus 16 uint8_t's
void aes128_cbc_enc(uint8_t* key, uint8_t* iv, void* data, uint16_t data_len);

// encrypt single 128bit block. data is assumed to be 16 uint8_t's
// key and iv are assumed to be both 128bit thus 16 uint8_t's
void aes128_enc_single(uint8_t* key, void* data);

typedef void* aes_context;

// prepare an encrypted to use for encrypting multiple blocks lateron.
// key and iv are assumed to be both 128bit thus 16 uint8_t's
aes_context aes128_cbc_enc_start(uint8_t* key, void* iv);

// encrypt one or more blocks of 128bit data
// data_len should be mod 16
void aes128_cbc_enc_continue(aes_context ctx, void* data, uint16_t data_len);

// cleanup encryption context
void aes128_cbc_enc_finish(aes_context ctx);

// decrypt multiple blocks of 128bit data, data_len but be mod 16
// key and iv are assumed to be both 128bit thus 16 uint8_t's
void aes128_cbc_dec(uint8_t* key, uint8_t* iv, void* data, uint16_t data_len);

// decrypt single 128bit block. data is assumed to be 16 uint8_t's
// key and iv are assumed to be both 128bit thus 16 uint8_t's
void aes128_dec_single(uint8_t* key, void* data);

// prepare an decrypter to use for decrypting multiple blocks lateron.
// key and iv are assumed to be both 128bit thus 16 uint8_t's
aes_context aes128_cbc_dec_start(uint8_t* key, void* iv);

// decrypt one or more blocks of 128bit data
// data_len should be mod 16
void aes128_cbc_dec_continue(aes_context ctx, void* data, uint16_t data_len);

// cleanup decryption context
void aes128_cbc_dec_finish(aes_context ctx);
#endif
