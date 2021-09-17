#ifndef _XBOX360_H
#define _XBOX360_H

// constants
#define TRUE                        1
#define FALSE                       0
#define SHA_LBLOCK	                16
#define XECRYPT_SHA_DIGEST_SIZE	    20
#define XECRYPT_HMAC_SHA_MAX_KEY_SZ	64
#define XECRYPT_DES_BLOCK_SIZE      8
#define XECRYPT_DES_KEY_SIZE        8
#define XECRYPT_DES3_BLOCK_SIZE     8
#define XECRYPT_DES3_KEY_SIZE       24
#define XECRYPT_MD5_DIGEST_SIZE     16
#define XECRYPT_AES_BLOCK_SIZE      16
#define XECRYPT_AES_KEY_SIZE        16
#define XECRYPT_AES_FEED_SIZE       16
#define XECRYPT_ROTSUM_DIGEST_SIZE	32

#if defined(AES_VAR) || defined(AES_256)
#define KS_LENGTH       60
#elif defined(AES_192)
#define KS_LENGTH       52
#else
#define KS_LENGTH       44
#endif

// primitives:
typedef void               VOID;
// primitives - unsigned
typedef unsigned char      u8, BYTE, UCHAR;
typedef unsigned short     u16, WORD, USHORT;
typedef unsigned int       u32, DWORD, BOOL, UINT;
typedef unsigned long long u64, QWORD, ULONG;
// primitives - signed
typedef char               s8, CHAR;
typedef short              s16;
typedef int                s32;
typedef long long          s64;

// structs - flash
struct FLASH_HDR {
	WORD  Magic;
	WORD  Build;
	WORD  QFE;
	WORD  Flags;
	DWORD EntryPoint;
	DWORD Size;
	BYTE  Copyright[0x40];
	BYTE  Padding[0x10];
	DWORD KvLength;
	DWORD PatchOffset;
	WORD  PatchSlots;
	WORD  KvVersion;
	DWORD KvOffset;
	DWORD PatchSlotSize;
	DWORD SmcConfigOffset;
	DWORD SmcLength;
	DWORD SmcOffset;
};

struct BL_HDR {
	WORD Magic;
	WORD Build;
	WORD QFE;
	WORD Flags;
	DWORD EntryPoint;
	DWORD Size;
};

struct BL_HDR_WITH_NONCE {
	WORD Magic;
	WORD Build;
	WORD QFE;
	WORD Flags;
	DWORD EntryPoint;
	DWORD Size;
	BYTE Nonce[0x10];
};

#define HV_HDR         BL_HDR_WITH_NONCE
#define CBA_SB_2BL_HDR BL_HDR_WITH_NONCE
#define CBB_SC_3BL_HDR BL_HDR_WITH_NONCE
#define CD_SD_4BL_HDR  BL_HDR_WITH_NONCE
#define CE_SE_5BL_HDR  BL_HDR_WITH_NONCE
#define CF_SF_6BL_HDR  BL_HDR_WITH_NONCE

// structs - XeCrypt - hashing
typedef struct {
	DWORD lo, hi;
	DWORD a, b, c, d;
	BYTE  buffer[64];
	DWORD block[16];
} XECRYPT_MD5_STATE;

typedef struct SHAstate_st
{
	DWORD h0, h1, h2, h3, h4;
	DWORD Nl,Nh;
	DWORD data[SHA_LBLOCK];
	int num;
} SHA_CTX;

typedef SHA_CTX XECRYPT_SHA_STATE, *PXECRYPT_SHA_STATE;

// structs - XeCrypt - ciphers
typedef struct rc4_key_st
{
	DWORD x, y;
	DWORD data[256];
} RC4_KEY;

typedef struct des_key {
	DWORD ek[32], dk[32];
} XECRYPT_DES_STATE;

typedef struct des3_key {
	DWORD ek[3][32], dk[3][32];
} XECRYPT_DES3_STATE;

typedef union
{   DWORD l;
    BYTE  b[4];
} aes_inf;

typedef struct
{   DWORD   ks[KS_LENGTH];
    aes_inf inf;
} aes_encrypt_ctx;

typedef aes_encrypt_ctx aes_decrypt_ctx;

typedef RC4_KEY XECRYPT_RC4_STATE, *PXECRYPT_RC4_STATE;
typedef struct{
	aes_encrypt_ctx encCtx;
	aes_decrypt_ctx decCtx;
} XECRYPT_AES_STATE, *PXECRYPT_AES_STATE;

// structs - XeCrypt - PKC (Public Key Cryptography)
typedef struct {
	DWORD         cqw;                // Number of u64 digits in modulus
	DWORD         dwPubExp;           // Public exponent
	QWORD         qwReserved;         // Reserved (was qwMI)
} XECRYPT_RSA, *PXECRYPT_RSA;

typedef struct {
	XECRYPT_RSA   Rsa;                // Common header
	QWORD         aqwM[16];           // [BnQwNe] Modulus
} XECRYPT_RSAPUB_1024, *PXECRYPT_RSAPUB_1024;

typedef struct {
	XECRYPT_RSA   Rsa;                // Common header
	QWORD         aqwM[24];           // [BnQwNe] Modulus
} XECRYPT_RSAPUB_1536, *PXECRYPT_RSAPUB_1536;

typedef struct {
	XECRYPT_RSA   Rsa;                // Common header
	QWORD         aqwM[32];           // [BnQwNe] Modulus
} XECRYPT_RSAPUB_2048, *PXECRYPT_RSAPUB_2048;

typedef struct {
	XECRYPT_RSA   Rsa;                // Common header
	QWORD           aqwM[64];           // [BnQwNe] Modulus
} XECRYPT_RSAPUB_4096, *PXECRYPT_RSAPUB_4096;

typedef struct {
	XECRYPT_RSA   Rsa;                // Common header
	QWORD         aqwM[16];           // [BnQwNe] Modulus
	QWORD         aqwP[8];            // [BnQwNe] Private prime P
	QWORD         aqwQ[8];            // [BnQwNe] Private prime Q
	QWORD         aqwDP[8];           // [BnQwNe] Private exponent P
	QWORD         aqwDQ[8];           // [BnQwNe] Private exponent Q
	QWORD         aqwCR[8];           // [BnQwNe] Private coefficient
} XECRYPT_RSAPRV_1024, *PXECRYPT_RSAPRV_1024;

typedef struct {
	XECRYPT_RSA   Rsa;                // Common header
	QWORD         aqwM[24];           // [BnQwNe] Modulus
	QWORD         aqwP[12];           // [BnQwNe] Private prime P
	QWORD         aqwQ[12];           // [BnQwNe] Private prime Q
	QWORD         aqwDP[12];          // [BnQwNe] Private exponent P
	QWORD         aqwDQ[12];          // [BnQwNe] Private exponent Q
	QWORD         aqwCR[12];          // [BnQwNe] Private coefficient
} XECRYPT_RSAPRV_1536, *PXECRYPT_RSAPRV_1536;

typedef struct {
	XECRYPT_RSA   Rsa;                // Common header
	QWORD         aqwM[32];           // [BnQwNe] Modulus
	QWORD         aqwP[16];           // [BnQwNe] Private prime P
	QWORD         aqwQ[16];           // [BnQwNe] Private prime Q
	QWORD         aqwDP[16];          // [BnQwNe] Private exponent P
	QWORD         aqwDQ[16];          // [BnQwNe] Private exponent Q
	QWORD         aqwCR[16];          // [BnQwNe] Private coefficient
} XECRYPT_RSAPRV_2048, *PXECRYPT_RSAPRV_2048;

typedef struct {
	XECRYPT_RSA   Rsa;                // Common header
	QWORD         aqwM[64];           // [BnQwNe] Modulus
	QWORD         aqwP[32];           // [BnQwNe] Private prime P
	QWORD         aqwQ[32];           // [BnQwNe] Private prime Q
	QWORD         aqwDP[32];          // [BnQwNe] Private exponent P
	QWORD         aqwDQ[32];          // [BnQwNe] Private exponent Q
	QWORD         aqwCR[32];          // [BnQwNe] Private coefficient
} XECRYPT_RSAPRV_4096, *PXECRYPT_RSAPRV_4096;

typedef struct _XECRYPT_SIG { 
	QWORD aqwPad[28]; // 0x0 sz:0xE0
	BYTE  bOne; // 0xE0 sz:0x1
	BYTE  abSalt[10]; // 0xE1 sz:0xA
	BYTE  abHash[20]; // 0xEB sz:0x14
	BYTE  bEnd; // 0xFF sz:0x1
} XECRYPT_SIG, *PXECRYPT_SIG; // size 256

// enums - flash
enum BL_MAGIC {
	CA_1BL     = 0x0342,
	CB_CBA_2BL = 0x4342,
	CC_CBB_3BL = 0x4343,
	CD_4BL     = 0x4344,
	CE_5BL     = 0x4345,
	CF_6BL     = 0x4346,
	CG_7BL     = 0x4347,
	SB_2BL     = 0x5342,
	SC_3BL     = 0x5343,
	SD_4BL     = 0x5344,
	SE_5BL     = 0x5345,
	SF_6BL     = 0x5346,
	SG_7BL     = 0x5347
};

// pointers - flash
typedef FLASH_HDR*         PFLASH_HDR;
typedef BL_HDR*            PBL_HDR;
typedef BL_HDR_WITH_NONCE* PBL_HDR_WITH_NONCE;

// pointers - primitives
typedef void*              PVOID, VOIDP;
typedef CHAR*              PCHAR;
typedef BYTE*              PBYTE, PUCHAR;
typedef WORD*              PWORD;
typedef DWORD*             PDWORD;
typedef QWORD*             PQWORD;

// pointers - XeCrypt - hashing
typedef XECRYPT_MD5_STATE* PXECRYPT_MD5_STATE;

// pointers - XeCrypt - ciphers
typedef XECRYPT_DES_STATE*  PXECRYPT_DES_STATE;
typedef XECRYPT_DES3_STATE* PXECRYPT_DES3_STATE;

// prototypes - XeCrypt
void XeCryptUidEccEncode(PBYTE pbaCpuKey);
int  XeCryptHammingWeight(PBYTE data, DWORD len);
void XeCryptBnQw_SwapDwQwLeBe(const PBYTE pqwInp, PBYTE pqwOut, DWORD cqw);

// prototypes - XeCrypt - PRNG
void XeCryptRandom(PBYTE pbOut, DWORD cbOut);

// prototypes - XeCrypt - checksums
void XeCryptRotSum(PBYTE pbOut, PBYTE pbInp, DWORD cqwInp);

// prototypes - XeCrypt - hashing
void XeCryptMd5Init(PXECRYPT_MD5_STATE pMd5State);
void XeCryptMd5Update(PXECRYPT_MD5_STATE pMd5State, const PBYTE pbInp, DWORD cbInp);
void XeCryptMd5Final(PXECRYPT_MD5_STATE pMd5State, PBYTE pbOut, DWORD cbOut);
void XeCryptMd5(const PBYTE pbInp1, DWORD cbInp1, const PBYTE pbInp2, DWORD cbInp2, const PBYTE pbInp3, DWORD cbInp3, PBYTE pbOut, DWORD cbOut);
void XeCryptShaInit(PXECRYPT_SHA_STATE pShaState);
void XeCryptShaUpdate(PXECRYPT_SHA_STATE pShaState, PBYTE pbInp, DWORD cbInp);
void XeCryptShaFinal(PXECRYPT_SHA_STATE pShaState, PBYTE pbOut, DWORD cbOut);
void XeCryptSha(PBYTE pbInp1, DWORD cbInp1, PBYTE pbInp2, DWORD cbInp2, PBYTE pbInp3, DWORD cbInp3, PBYTE pbOut, DWORD cbOut);
void XeCryptRotSumSha(PBYTE pbInp1, DWORD cbInp1, PBYTE pbInp2, DWORD cbInp2, PBYTE pbOut, DWORD cbOut);

// prototypes - XeCrypt - MAC
void XeCryptHmacSha(const PBYTE pbKey, DWORD cbKey, const PBYTE pbInp1, DWORD cbInp1, const PBYTE pbInp2, DWORD cbInp2, const PBYTE pbInp3, DWORD cbInp3, PBYTE pbOut, DWORD cbOut);

// prototypes - XeCrypt - ciphers
void XeCryptDesKey(PXECRYPT_DES_STATE pDesState, const PBYTE pbKey);
void XeCryptDesEcb(PXECRYPT_DES_STATE pDesState, const PBYTE pbInp, PBYTE pbOut, BOOL fEncrypt);
void XeCryptDesCbc(PXECRYPT_DES_STATE pDesState, const PBYTE pbInp, DWORD cbInp, PBYTE pbOut, PBYTE pbFeed, BOOL fEncrypt);
void XeCryptDes3Key(PXECRYPT_DES3_STATE pDes3State, const PBYTE pbKey);
void XeCryptDes3Ecb(PXECRYPT_DES3_STATE pDes3State, const PBYTE pbInp, PBYTE pbOut, BOOL fEncrypt);
void XeCryptDes3Cbc(PXECRYPT_DES3_STATE pDes3State, const PBYTE pbInp, DWORD cbInp, PBYTE pbOut, PBYTE pbFeed, BOOL fEncrypt);
void XeCryptRc4(PBYTE pbKey, DWORD cbKey, PBYTE pbInpOut, DWORD cbInpOut);
void XeCryptRc4Key(PXECRYPT_RC4_STATE pRc4State, PBYTE pbKey, DWORD cbKey);
void XeCryptRc4Ecb(PXECRYPT_RC4_STATE pRc4State, PBYTE pbInpOut, DWORD cbInpOut);
void XeCryptAesKey(PXECRYPT_AES_STATE pAesState, const PBYTE pbKey);
void XeCryptAesEcb(PXECRYPT_AES_STATE pAesState, PBYTE pbInp, PBYTE pbOut, BOOL fEncrypt);
void XeCryptAesCbc(PXECRYPT_AES_STATE pAesState, PBYTE pbInp, DWORD cbInp, PBYTE pbOut, PBYTE pbFeed, BOOL fEncrypt);

// prototypes - XeCrypt - PKC (Public Key Cryptography)
BOOL XeCryptBnQwNeRsaKeyGen(DWORD cbits, DWORD dwPubExp, PXECRYPT_RSA pRsaPub, PXECRYPT_RSA pRsaPrv);
void XeCryptBnQwBeSigFormat(PXECRYPT_SIG pSig, const PBYTE pbHash, const PBYTE pbSalt);
BOOL XeCryptBnQwBeSigCreate(PXECRYPT_SIG pSig, const PBYTE pbHash, const PBYTE pbSalt, const PXECRYPT_RSA pRsa);
BOOL XeCryptBnQwBeSigVerify(PXECRYPT_SIG pSig, const PBYTE pbHash, const PBYTE pbSalt, const PXECRYPT_RSA pRsa);
BOOL XeCryptBnQwNeModExpRoot(PQWORD pqwOut, const PQWORD pqwIn, const PQWORD pqwPP, const PQWORD pqwQQ, const PQWORD pqwDP, const PQWORD pqwDQ, const PQWORD pqwCR, DWORD cqw);
BOOL XeCryptBnQwNeRsaPrvCrypt(const PQWORD pqwIn, PQWORD pqwOut, const PXECRYPT_RSA pRsa);
BOOL XeCryptBnQwNeRsaPubCrypt(const PQWORD pqwIn, PQWORD pqwOut, const PXECRYPT_RSA pRsa);
void XeCryptBnDwLePkcs1Format(const PBYTE pbHash, DWORD dwType, PBYTE pbSig, DWORD cbSig);
BOOL XeKeysPkcs1Verify(const PBYTE pbHash, const PBYTE pbSig, const PXECRYPT_RSA pRsaPub);

#endif
