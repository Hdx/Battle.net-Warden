#ifndef CREVLOCKDOWN_H
#define CREVLOCKDOWN_H

#include <stdlib.h>
#include <string.h>

#include "crev.h"
#include "types.h"
#include "config.h"
#include "sha1.h"

uint32_t __stdcall crev_ver3( 
	uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, 
	uint8_t *ini_file, uint8_t *ini_header, 
	uint32_t *version, uint32_t *checksum, uint8_t *result);

uint32_t lockdown_shuffle_seed(uint8_t *seed);
void lockdown_word_shifter(uint16_t *word1, uint16_t *word2);
uint32_t lockdown_shuffle_digest(uint8_t *digest);
#endif