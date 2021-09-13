#ifndef _XBOX360_H
#define _XBOX360_H

// constants
#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef MD5_DIGEST_SIZE
#define MD5_DIGEST_SIZE 16
#endif

#ifndef SHA_DIGEST_SIZE
#define SHA_DIGEST_SIZE 20
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

// structs - XeCrypt


// enums - flash
enum BL_MAGIC {
	CA_1BL = 0x0342,
	CB_CBA_2BL = 0x4342,
	CC_CBB_3BL = 0x4343,
	CD_4BL = 0x4344,
	CE_5BL = 0x4345,
	CF_6BL = 0x4346,
	CG_7BL = 0x4347,
	SB_2BL = 0x5342,
	SC_3BL = 0x5343,
	SD_4BL = 0x5344,
	SE_5BL = 0x5345,
	SF_6BL = 0x5346,
	SG_7BL = 0x5347
};

// pointers
typedef FLASH_HDR*         PFLASH_HDR;
typedef BL_HDR*            PBL_HDR;
typedef BL_HDR_WITH_NONCE* PBL_HDR_WITH_NONCE;
typedef void*              PVOID, VOIDP;
typedef CHAR*              PCHAR;
typedef BYTE*              PBYTE, PUCHAR;
typedef WORD*              PWORD;
typedef DWORD*             PDWORD;
typedef QWORD*             PQWORD;

#endif
