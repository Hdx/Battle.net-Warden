#ifndef RC4_H
#define RC4_H

#include "stdint.h"

void __stdcall rc4_init(uint8_t *key_buffer, uint8_t *base, uint32_t base_length);
void __stdcall rc4_crypt(uint8_t *key, uint8_t *data, uint32_t length);
void __stdcall rc4_crypt_data(uint8_t *data, uint32_t data_length, uint8_t *base, uint32_t base_length);

#endif
