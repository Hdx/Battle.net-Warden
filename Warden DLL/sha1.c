/*
 *  sha1.c
 *
 *  Description:
 *    This file implements the Secure Hashing Algorithm 1 as
 *    defined in FIPS PUB 180-1 published April 17, 1995.
 *
 *    The SHA-1, produces a 160-bit message digest for a given
 *    data stream.  It should take about 2**n steps to find a
 *    message with the same digest as a given message and
 *    2**(n/2) to find any two messages with the same digest,
 *    when n is the digest size in bits.  Therefore, this
 *    algorithm can serve as a means of providing a
 *    "fingerprint" for a message.
 *
 *  Portability Issues:
 *    SHA-1 is defined in terms of 32-bit "words".  This code
 *    uses <stdint.h> (included via "sha1.h" to define 32 and 8
 *    bit unsigned integer types.  If your C compiler does not
 *    support 32 bit unsigned integers, this code is not
 *    appropriate.
 *
 *  Caveats:
 *    SHA-1 is designed to work with messages less than 2^64 bits
 *    long.  Although SHA-1 allows a message digest to be generated
 *    for messages of any number of bits less than 2^64, this
 *    implementation only works with messages with a length that is
 *    a multiple of the size of an 8-bit character.
 *
 *  Notes:
 *    I took this file from BNCSUtil's source, Why? Lazyness. I have modified it a bit but most of its from him. <3
 */

#include "sha1.h"

#define SHA1RoL(bits, word) \
    (((word) << (bits)) | ((word) >> (32-(bits))))
  
#define xSHA1RoL(word, bits) \
    (((word) << (bits)) | ((word) >> (32-(bits))))

#define SHA1batoi(ba, i) \
  ((ba[i] << 24) | (ba[i+1] << 16) | (ba[i+2] << 8) | ba[i+3])
  
#define xSHA1batoi(ba, i) \
  ((ba[i+3] << 24) | (ba[i+2] << 16) | (ba[i+1] << 8) | ba[i])
  
#define SHA1itoba(a, ba, i) \
  (ba[i] = (uint8_t)(a >> 24)); (ba[i+1] = (uint8_t)(a >> 16)); (ba[i+2] = (uint8_t)(a >> 8)); (ba[i+3] = (uint8_t)a);
  
#define xSHA1itoba(a, ba, i) \
  (ba[i+3] = (uint8_t)(a >> 24)); (ba[i+2] = (uint8_t)(a >> 16)); (ba[i+1] = (uint8_t)(a >> 8)); (ba[i] = (uint8_t)a);

/* Local Function Prototyptes */
void sha1_pad_message(sha1_context *);
void sha1_process_message_block(sha1_context *);

/*
 *  SHA1Reset
 *
 *  Description:
 *    This function will initialize the SHA1Context in preparation
 *    for computing a new SHA1 message digest.
 *
 *  Parameters:
 *    context: [in/out]
 *      The context to reset.
 *
 *  Returns:
 *    sha Error Code.
 *
 */
int __stdcall sha1_reset(sha1_context *ctx){
  uint8_t x;
  if (!ctx)
    return shaNull;
  
  ctx->length_low           = 0;
  ctx->length_high          = 0;
  ctx->message_block_index  = 0;

  ctx->intermediate_hash[0] = 0x67452301;
  ctx->intermediate_hash[1] = 0xEFCDAB89;
  ctx->intermediate_hash[2] = 0x98BADCFE;
  ctx->intermediate_hash[3] = 0x10325476;
  ctx->intermediate_hash[4] = 0xC3D2E1F0;

  for(x = 0; x < 64; x++){
    ctx->message_block[x] = 0;
  }
  ctx->computed  = 0;
  ctx->corrupted = 0;

  return shaSuccess;
}

/*
 *  SHA1Result
 *
 *  Description:
 *    This function will return the 160-bit message digest into the
 *    Message_Digest array  provided by the caller.
 *    NOTE: The first octet of hash is stored in the 0th element,
 *      the last octet of hash in the 19th element.
 *
 *  Parameters:
 *    context: [in/out]
 *      The context to use to calculate the SHA-1 hash.
 *    Message_Digest: [out]
 *      Where the digest is returned.
 *
 *  Returns:
 *    sha Error Code.
 *
 */
int __stdcall sha1_digest(sha1_context *ctx, uint8_t *digest){
  int i;

  if (!ctx || !digest)
    return shaNull;

  if (ctx->corrupted)
    return ctx->corrupted;

  if (!ctx->computed){
    sha1_pad_message(ctx);

    ctx->length_low  = 0;
    ctx->length_high = 0;
    ctx->computed    = 1;
  }

  if(ctx->version != SHA1){
    for(i = 0; i < 5; i++){
      xSHA1itoba(ctx->intermediate_hash[i], digest, i * 4);
    }
  }else{
    for(i = 0; i < 5; i++){
      SHA1itoba(ctx->intermediate_hash[i], digest, i * 4);
    }
  }

  return shaSuccess;
}
/*
 *  SHA1Input
 *
 *  Description:
 *    This function accepts an array of octets as the next portion
 *    of the message.
 *
 *  Parameters:
 *    context: [in/out]
 *      The SHA context to update
 *    message_array: [in]
 *      An array of characters representing the next portion of
 *      the message.
 *    length: [in]
 *      The length of the message in message_array
 *
 *  Returns:
 *    sha Error Code.
 *
 */
int __stdcall sha1_input(sha1_context *ctx, const uint8_t *data, uint32_t length){
  uint32_t x;
  if(!length)
    return shaSuccess;
  
  if(!ctx || !data)
      return shaNull;

  if(ctx->computed){
    ctx->corrupted = shaStateError;
    return shaStateError;
  }

  for(x = 0; x < length; x++){
    ctx->message_block[ctx->message_block_index++] = (data[x] & 0xFF);
    ctx->length_low += 8;

    if (ctx->length_low == 0){
      ctx->length_high++;
      if(ctx->length_high == 0){
        ctx->corrupted = shaInputTooLong;
        return shaInputTooLong;
      }
    }

    if (ctx->message_block_index == 64)
      sha1_process_message_block(ctx);
  }

  return shaSuccess;
}

/*
 * SHA1Math
 *
 * Description:
 *   This is simply so I can have a clean way of 
 * doing the Process in one loop insted of 4.
 */
uint32_t sha1_math(uint16_t t, uint32_t B, uint32_t C, uint32_t D){
  if(t < 20)      return ((B & C) | ((~B) & D));
  else if(t < 40) return (B ^ C ^ D);
  else if(t < 60) return ((B & C) | (B & D) | (C & D));
  else            return (B ^ C ^ D);
}
/*
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *    This function will process the next 512 bits of the message
 *    stored in the Message_Block array.
 *
 *  Parameters:
 *    None.
 *
 *  Returns:
 *    Nothing.
 *
 *  Comments:
 *    Many of the variable names in this code, especially the
 *    single character names, were used because those were the
 *    names used in the publication.
 *
 *
 */


void sha1_process_message_block(sha1_context *ctx){
  uint16_t t;             /* Loop counter        */
  uint32_t temp;          /* Temporary word value*/
  uint32_t W[80];         /* Word sequence       */
  uint32_t A, B, C, D, E; /* Word buffers        */
  const uint32_t K[] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
  
  if(ctx->version == xSHA1){
    for(t = 0; t < 16; t++)  W[t] = xSHA1batoi(ctx->message_block, t * 4);
    for(t = 16; t < 80; t++) W[t] = xSHA1RoL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
  }else if(ctx->version == lSHA1){
    for(t = 0; t < 16; t++)  W[t] = xSHA1batoi(ctx->message_block, t * 4);
    for(t = 16; t < 80; t++) W[t] = SHA1RoL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
  }else{
    for(t = 0; t < 16; t++)  W[t] = SHA1batoi(ctx->message_block, t * 4);
    for(t = 16; t < 80; t++) W[t] = SHA1RoL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
  }
  
  A = ctx->intermediate_hash[0];
  B = ctx->intermediate_hash[1];
  C = ctx->intermediate_hash[2];
  D = ctx->intermediate_hash[3];
  E = ctx->intermediate_hash[4];
  
  for(t = 0; t < 80; t++){
    temp = SHA1RoL(5,A) + sha1_math(t, B, C, D) + E + W[t] + K[t / 20];
    E = D;
    D = C;
    C = SHA1RoL(30,B);
    B = A;
    A = temp;
  }
  
  ctx->intermediate_hash[0] += A;
  ctx->intermediate_hash[1] += B;
  ctx->intermediate_hash[2] += C;
  ctx->intermediate_hash[3] += D;
  ctx->intermediate_hash[4] += E;

  ctx->message_block_index = 0;
}


/*
 *  SHA1PadMessage
 *
 *  Description:
 *    According to the standard, the message must be padded to an even
 *    512 bits.  The first padding bit must be a '1'.  The last 64
 *    bits represent the length of the original message.  All bits in
 *    between should be 0.  This function will pad the message
 *    according to those rules by filling the Message_Block array
 *    accordingly.  It will also call the ProcessMessageBlock function
 *    provided appropriately.  When it returns, it can be assumed that
 *    the message digest has been computed.
 *
 *  Parameters:
 *    context: [in/out]
 *      The context to pad
 *    ProcessMessageBlock: [in]
 *      The appropriate SHA*ProcessMessageBlock function
 *  Returns:
 *    Nothing.
 *
 */

void sha1_pad_message(sha1_context *ctx){
  if(ctx->version == xSHA1){
    while(ctx->message_block_index < 64)
      ctx->message_block[ctx->message_block_index++] = 0;
  }else{
    if (ctx->message_block_index > 55){
      ctx->message_block[ctx->message_block_index++] = 0x80;
  
      while(ctx->message_block_index < 64)
        ctx->message_block[ctx->message_block_index++] = 0;
    
      sha1_process_message_block(ctx);
    }else{
      ctx->message_block[ctx->message_block_index++] = 0x80;
    }
  
    while(ctx->message_block_index < 56)
      ctx->message_block[ctx->message_block_index++] = 0;

    if(ctx->version == lSHA1){
      xSHA1itoba(ctx->length_high, ctx->message_block, 60);
      xSHA1itoba(ctx->length_low,  ctx->message_block, 56);
    }else{
      SHA1itoba(ctx->length_high, ctx->message_block, 56);
      SHA1itoba(ctx->length_low,  ctx->message_block, 60);
    }
  }
  sha1_process_message_block(ctx);
}



uint32_t __stdcall sha1_checksum(uint8_t *data, uint32_t length, uint32_t version){
  uint8_t digest[20];
  sha1_context ctx;
  ctx.version = version;
  sha1_reset(&ctx);
  sha1_input(&ctx, data, length);
  sha1_digest(&ctx, digest);
  
  return *((uint32_t*)&digest[0]) ^ *((uint32_t*)&digest[4]) ^ 
     *((uint32_t*)&digest[8]) ^ *((uint32_t*)&digest[12]) ^ *((uint32_t*)&digest[16]);
}