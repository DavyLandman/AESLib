Arduino AESLib 
==============

This project is just an Arduino ready extract from the [AVR-Crypto-Lib](https://github.com/cantora/avr-crypto-lib).

It only packages the ASM implementations of AES into a library ready to use in
Arduino IDE.

See the LICENSE file for details of the GPLv3 license in which the AVR-Crypo-Lib
is licensed.


Installation
------------

- Download the files in this repository (using either clone or the download button)
- Copy the `AESLib` folder into `libraries` folder (same level as your `sketch` folder)
- add `#include <AESLib.h>` in your sketch.


Usage
-----

At the moment only 128bit keys are supported, the blocksize is also fixed at 128bit.
This means that the key array and possible iv array should contain exactly 16 bytes (`uint8_t` or `byte`).
Moreover the amount of bytes to encrypt should be mod 16. 
(this means you have to take care of padding yourself).

The library supports 3 kinds of operations.

1. single block encryption/decryption
-  multiple block encryption/decryption using CBC (single call)
-  multiple block encryption/decryption using CBC (multiple calls)

The single block enc/decryption are the following methods:

```c
void aes128_enc_single(const uint8_t* key, void* data);
void aes128_dec_single(const uint8_t* key, void* data);
```

Usage example:
	
```c
Serial.begin(57600);
uint8_t key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
char data[] = "0123456789012345"; //16 chars == 16 bytes
aes128_enc_single(key, data);
Serial.print("encrypted:");
Serial.println(data);
aes128_dec_single(key, data);
Serial.print("decrypted:");
Serial.println(data);
```

Usage example for AES256:
	
```c
Serial.begin(57600);
uint8_t key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
char data[] = "0123456789012345";
aes256_enc_single(key, data);
Serial.print("encrypted:");
Serial.println(data);
aes256_dec_single(key, data);
Serial.print("decrypted:");
Serial.println(data);
```



