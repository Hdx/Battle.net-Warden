#include "crevold.h"
void wwrite_to_file(const uint8_t *data){
	FILE *fp;
	fopen_s(&fp, "WardenLog.txt", "a");
	fwrite(data, 1, strlen(data), fp);
	fclose(fp);
}
uint8_t *tto_hex(uint8_t *data, uint32_t size, BOOLEAN spaces){
	uint8_t *buff = safe_malloc(size * (spaces == TRUE ? 3 : 2));
	uint32_t x = 0;
	
	for(x = 0; x < size; x++){
		if(spaces == TRUE)
			sprintf_s((uint8_t*)(buff + (3 * x)), 4, "%02X ", data[x]);
		else
			sprintf_s((uint8_t*)(buff + (2 * x)), 4, "%02X", data[x]);
	}
	return buff;
}

uint32_t __stdcall crev_ver3(uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, uint8_t *ini_file, uint8_t *ini_header, uint32_t *version, uint32_t *checksum, uint8_t *result){

	uint32_t x = 0;
	uint32_t y = 0;
	uint8_t *files[5];
	uint8_t *tok;
	uint8_t *buff;
	uint8_t *buff2;
	uint32_t archive_rev = 0;
	sha1_context sha;
	const uint8_t *keys[] = {"Exe", "Util", "Network", "Screen"};
	const uint32_t seeds[] = {
		0xA1F3055A, 0x5657124C, 0x1780AB47, 0x80B3A410, 0xAF2179EA, 
		0x0837B808, 0x6F2516C6, 0xE3178148, 0x0FCF90B6, 0xF2F09516, 
		0x378D8D8C, 0x07F8E083, 0xB0EE9741, 0x7923C9AF, 0xCA11A05E, 
		0xD723C016, 0xFD545590, 0xFB600C2E, 0x684C8785, 0x58BEDE0B\
	};

	sha.version = lSHA1;
	sha1_reset(&sha);

	//uint8_t *tmp = safe_malloc(0x200);
	
	if( (archive_name[14] < '0' || archive_name[14] > '1') ||
		(archive_name[15] < '0' || archive_name[15] > '9')){
		return CREV_UNKNOWN_REVISION;
	}

	archive_rev = ((archive_name[14] - '0') * 10) +
				   (archive_name[15] - '0');

	buff = safe_malloc(MAX_PATH);
	read_ini_new(ini_file, ini_header, "Path", "", buff, MAX_PATH);
	files[0] = safe_malloc(MAX_PATH);
	
	if(strstr(buff, ":\\") == NULL){
		tok = safe_malloc(MAX_PATH);
		GetCurrentDirectory(MAX_PATH, tok);
		sprintf_s(files[0], MAX_PATH, "%s\\%s", tok, buff);
		free(tok);
	}else{
		sprintf_s(files[0], MAX_PATH, buff);
	}

	for(x = 1; x < 5; x++){
		read_ini_new(ini_file, ini_header, (uint8_t*)keys[x-1], "\xFF", buff, MAX_PATH);
		if(buff[0] == 0xFF){
			for(y = 0; y < x; y++)
				if(files[y] != NULL) free(files[y]);
			sprintf_s(result, crev_max_result(), "%s\x00", keys[x-1]);
			free(buff);
			return CREV_MISSING_FILENAME;
		}
		files[x] = safe_malloc(MAX_PATH);
		sprintf_s(files[x], MAX_PATH, "%s\\%s", files[0], buff);
	}

	read_ini_new(ini_file, "CRev_Main", "LockdownPath", "", buff, MAX_PATH);
	
	if(strstr(buff, ":\\") == NULL){
		tok = safe_malloc(MAX_PATH);
		GetCurrentDirectory(MAX_PATH, tok);
		sprintf_s(files[0], MAX_PATH, "%s\\%s\\lockdown-IX86-%02d.dll", tok, buff, archive_rev);
		free(tok);
	}else{
		sprintf_s(files[0], MAX_PATH, "%s\\lockdown-IX86-%02d.dll", buff, archive_rev);
	}

	free(buff);
	/*
	 *sprintf_s(tmp, MAX_PATH * 2, "Lib:     %s %d\n", files[0], get_file_size(files[1])); wwrite_to_file(tmp);
	 *sprintf_s(tmp, MAX_PATH * 2, "Exe:     %s %d\n", files[1], get_file_size(files[1])); wwrite_to_file(tmp);
	 *sprintf_s(tmp, MAX_PATH * 2, "Util:    %s %d\n", files[2], get_file_size(files[2])); wwrite_to_file(tmp);
	 *sprintf_s(tmp, MAX_PATH * 2, "Network: %s %d\n", files[3], get_file_size(files[3])); wwrite_to_file(tmp);
	 */

	//wwrite_to_file(tto_hex(seed, strlen(seed), FALSE)); wwrite_to_file("\n");
	lockdown_shuffle_seed(seed);
	//wwrite_to_file(tto_hex(seed, strlen(seed), FALSE)); wwrite_to_file("\n");

	buff = safe_malloc(0x40);
	memset(buff, '6', 0x40);

	for(x = 0; x < 0x10; x++)
		buff[x] ^= seed[x];
	sha1_input(&sha, buff, 0x40);
	free(buff);

    //hash_file(ctx, files[4], files[4]);
    //hash_file(ctx, files[0], files[4]);
    //hash_file(ctx, files[1], files[4]);
    //hash_file(ctx, files[2], files[4]);

	//Hash Screen Buffer
	x = get_file_size(files[4]);
	if(x == 0){
		sprintf_s(result, CREV_MAX_RESULT, files[3]);
		return CREV_MISSING_FILE;
	}
	buff = safe_malloc(x);
	get_file_data(files[4], buff, x, 0);
	sha1_input(&sha, buff, x);
	free(buff);

	sha1_input(&sha, "\x01\x00\x00\x00", 4); //Verify Return Address
	sha1_input(&sha, "\x00\x00\x00\x00", 4); //Verify Module Offset
	buff2 = safe_malloc(sha1_hash_size);
	sha1_digest(&sha, buff2);
    //wwrite_to_file(tto_hex(buff2, sha1_hash_size, FALSE)); wwrite_to_file("\n");

	//Second SHA Pass
	buff = safe_malloc(0x40);
	memset(buff, '\\', 0x40);

	for(x = 0; x < 0x10; x++)
		buff[x] ^= seed[x];
	sha1_reset(&sha);
	sha1_input(&sha, buff, 0x40);
	sha1_input(&sha, buff2, sha1_hash_size);
	memset(buff2, 0, sha1_hash_size);
	sha1_digest(&sha, buff2);
    //wwrite_to_file(tto_hex(buff2, sha1_hash_size, FALSE)); wwrite_to_file("\n");

	lockdown_shuffle_digest((uint8_t*)(&buff2[4]));
    //wwrite_to_file(tto_hex(buff2, sha1_hash_size, FALSE)); wwrite_to_file("\n");

	*version = crev_get_file_version(files[1]);
	*checksum = (*(uint32_t*)&buff2[0]);
	memcpy(result, (uint8_t*)(&buff2[4]), 0x10);
	return CREV_SUCCESS;
}

uint32_t lockdown_shuffle_seed(uint8_t *seed){
	uint32_t pos = 0;
	uint32_t i   = 0;
	uint32_t len = 0;

	uint8_t  addr    = 0;
	uint8_t  shifter = 0;
	uint8_t  b       = 0;
	uint8_t *buf;

	len = strlen(seed);
	buf = safe_malloc(len);

	while(len != 0){
		shifter = 0;
		for(i = 0; i < pos; i++){
			b = buf[i];
			buf[i] = (byte)(shifter - buf[i]);
			shifter = (byte)((((uint32_t)(b << 8) - b) + shifter) >> 8);
		}

		if(shifter != 0){
			if(pos >= 0x10) return 1;
			buf[pos++] = shifter;
		}

		addr = (uint8_t)(seed[len - 1] - 1);
		for(i = 0; i < pos; i++){
			buf[i] += addr; //buf[i] = (uint8_t)((buf[i] + addr) & 0xFF); 
			addr = ((buf[i] < addr) ? 1 : 0);
		}

		if(addr != 0){
			if(pos >= 0x10) return 2;
			buf[pos++] = addr;
		}
		len--;
	}
	memcpy(seed, buf, pos);
	while(pos < 0x10) seed[pos++] = 0x00;
	return 0;
}
void lockdown_word_shifter(uint16_t *word1, uint16_t *word2){
	uint16_t str2 = *word1;
	uint16_t str1 = *word2;

    str2 = (uint16_t)((((str1 >> 8) + (str1 & 0xFF)) >> 8) + (((str1 >> 8) + (str1 & 0xFF)) & 0xFF));
    str2 = (uint16_t)((str2 & 0xFF00) | (((str2+1) & 0xFF) - (((str2 & 0xFF) != 0xFF) ? 1 : 0)));

    str1 = (uint16_t)(((str1 - str2) & 0xFF) | (((((str1 - str2) >> 8) & 0xFF)+1) > 0 ? 0 : 0x100));
    str1 = (uint16_t)((str1 & 0xFF00) | (-str1 & 0xFF));
    
    *word1 = str2;
	*word2 = str1;
}
uint32_t lockdown_shuffle_digest(uint8_t *digest){
	uint16_t word1;
	uint16_t word2;
	uint16_t x   = 0;
	uint16_t y   = 0;
	uint16_t pos = 0;

	uint8_t *ret = safe_malloc(0x18);
	uint8_t *t = safe_malloc(0x20);
	for(x = 0x10; x > 0; ){
		while( x > 0 && digest[x-1] == 0x00) x--;
		if(x > 0){
			word1 = 0;
			for(y = x - 1; y < x; y--){
				word2 = (word1 << 8) + digest[y];
				lockdown_word_shifter(&word1, &word2);
				digest[y] = (uint8_t)(word2 & 0xFF);
			}
			if( (0x10 - x) >= 0xff) return 1;
			ret[pos++] = (uint8_t)((word1+1) & 0xFF);
		}
    }
	while(pos < 0x10) ret[pos++] = 0;
	memcpy(digest, ret, pos);
	return 0;
}