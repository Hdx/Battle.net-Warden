#ifndef CREV_H
#define CREV_H

#include "stdint.h"
#include <stdio.h>
#include <windows.h>
#include "crevold.h"

typedef enum{
    CREV_SUCCESS = 0,      //If everything went ok
	CREV_UNKNOWN_VERSION,  //Unknown version, Not lockdown, Or Ver
	CREV_UNKNOWN_REVISION, //Unknown Revision (0-7 for old, 0-19 for lockdown)
	CREV_MALFORMED_SEED,   //If the Seed passed in wasn't able to be translated properly
	CREV_MISSING_FILENAME, //We were not able to get the file path information from the INI file, Result holds more info.
	CREV_MISSING_FILE,     //Was not able to open a file, Result has the File Path
	CREV_FILE_INFO_ERROR,  //And error while trying to get the file info string, Result holds the path of the file
	CREV_MAX = 0xffffffff
};

#define CREV_MAX_RESULT 0x400

uint32_t __stdcall crev_max_result();
uint32_t __stdcall check_revision( 
	uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, 
	uint8_t *ini_file, uint8_t *ini_header, 
	uint32_t *version, uint32_t *checksum, uint8_t *result);
uint32_t  __stdcall crev_error_description(uint32_t error, uint8_t *buffer, uint32_t size);

#endif
