#include "crev.h"

uint32_t __stdcall crev_max_result(){
	return CREV_MAX_RESULT;
}

uint32_t __stdcall check_revision(uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, 
								  uint8_t *ini_file, uint8_t *ini_header, 
								  uint32_t *version, uint32_t *checksum, uint8_t *result){
	uint32_t lret = CREV_SUCCESS;
	switch(strlen(archive_name)){
		case 12: lret = crev_ver1(archive_time, archive_name, seed, ini_file, ini_header, version, checksum, result); break;
		case 14: lret = crev_ver2(archive_time, archive_name, seed, ini_file, ini_header, version, checksum, result); break;
		default: lret = CREV_UNKNOWN_VERSION;
	}
	return lret;
}

uint32_t  __stdcall crev_error_description(uint32_t error, uint8_t *buffer, uint32_t size){
	uint8_t *message;
	switch(error){
		case CREV_SUCCESS:          message = "Success"; break;
		case CREV_UNKNOWN_VERSION:  message = "Unsupported archive version"; break;
		case CREV_UNKNOWN_REVISION: message = "Unsupported archive sub-version"; break;
		case CREV_MALFORMED_SEED:   message = "Seed value was malformed"; break;
		case CREV_MISSING_FILENAME: message = "File name missing from INI file"; break;
		case CREV_MISSING_FILE:     message = "Failed to open file"; break;
		case CREV_FILE_INFO_ERROR:  message = "Failed to get executable information"; break;
		default:                    message = "Unknown Error Code"; break;
	}
	if(strlen(message) > size) return strlen(message);

	memcpy(buffer, message, strlen(message) + 1);
	return 0;
}