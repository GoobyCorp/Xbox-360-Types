#pragma once

const BYTE XECRYPT_SMC_KEY[] = { 0x42, 0x75, 0x4E, 0x79 };
const BYTE XECRYPT_1BL_KEY[] = { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };
const CHAR XECRYPT_1BL_SALT[] = "XBOX_ROM_B";
const CHAR XECRYPT_SC_SALT[] = "XBOX_ROM_3";
const CHAR XECRYPT_SD_SALT[] = "XBOX_ROM_4";

// XeCrypt
#define SHA_CBLOCK	  64
#define SHA_LBLOCK	  16
#define SHA_BLOCK	  16
#define SHA_LAST_BLOCK    56
#define SHA_LENGTH_BLOCK  8
#define SHA_DIGEST_LENGTH 20

#define XECRYPT_SHA_DIGEST_SIZE     (20)
#define XECRYPT_HMAC_SHA_MAX_KEY_SZ (64)

#define XECRYPT_DES_BLOCK_SIZE      (8)
#define XECRYPT_DES_KEY_SIZE        (8)

#define XECRYPT_DES3_BLOCK_SIZE     (8)
#define XECRYPT_DES3_KEY_SIZE       (24)

#define XECRYPT_MD5_DIGEST_SIZE     (16)

#define KS_LENGTH                   (60)
#define XECRYPT_AES_BLOCK_SIZE      (16)
#define XECRYPT_AES_KEY_SIZE        (16)
#define XECRYPT_AES_FEED_SIZE       (16)

#define XECRYPT_ROTSUM_DIGEST_SIZE	(32)