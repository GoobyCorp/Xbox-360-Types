#pragma once

// generic C lib
typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING;

// NTOS
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, PRLIST_ENTRY;

typedef struct _CSTRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} CSTRING, *PCSTRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// bootloaders
typedef struct {
    WORD magic;
    WORD build;
    WORD qfe;
    WORD flags;
    DWORD entry;
    DWORD size;
} BLHeader;

typedef struct {
    BLHeader header;
    BYTE nonce[0x10];
} BLHeaderWithNonce;

typedef BLHeaderWithNonce CB_SB_2BL_Header;
typedef BLHeaderWithNonce SC_3BL_Header;
typedef BLHeaderWithNonce CD_SD_4BL_Header;
typedef BLHeaderWithNonce CE_SE_5BL_Header;
typedef BLHeader HVHeader;

// XeCrypt
// RSA
typedef struct {
    QWORD aqwPad[0x28];
    BYTE bOne;
    BYTE abSalt[0xA];
    BYTE abHash[0x14];
    BYTE bEnd;
} XECRYPT_SIG, *PXECRYPT_SIG;

typedef struct {
    DWORD cqw;
    DWORD e;  // public exponent
    QWORD qwReserved;  // precomputed modular inverse
} XECRYPT_RSA, *PXECRYPT_RSA;

// public keys
typedef struct {
    XECRYPT_RSA rsa;
    QWORD n[0x10];  // modulus
} XECRYPT_RSAPUB_1024, *PXECRYPT_RSAPUB_1024;

typedef struct {
    XECRYPT_RSA rsa;
    QWORD n[0x18];  // modulus
} XECRYPT_RSAPUB_1536, *PXECRYPT_RSAPUB_1536;

typedef struct {
    XECRYPT_RSA rsa;
    QWORD n[0x20];  // modulus
} XECRYPT_RSAPUB_2048, *PXECRYPT_RSAPUB_2048;

typedef struct {
    XECRYPT_RSA rsa;
    QWORD n[0x40];  // modulus
} XECRYPT_RSAPUB_4096, *PXECRYPT_RSAPUB_4096;

// private keys
typedef struct {
    XECRYPT_RSA rsa;
    QWORD n[0x10];  // modulus
    QWORD p[8];
    QWORD q[8];
    QWORD dp[8];
    QWORD dq[8];
    QWORD cr[8];
} XECRYPT_RSAPRV_1024, *PXECRYPT_RSAPRV_1024;

typedef struct {
    XECRYPT_RSA rsa;
    QWORD n[0x18];  // modulus
    QWORD p[0xC];
    QWORD q[0xC];
    QWORD dp[0xC];
    QWORD dq[0xC];
    QWORD cr[0xC];
} XECRYPT_RSAPRV_1536, *PXECRYPT_RSAPRV_1536;

typedef struct {
    XECRYPT_RSA rsa;
    QWORD n[0x20];  // modulus
    QWORD p[0x10];
    QWORD q[0x10];
    QWORD dp[0x10];
    QWORD dq[0x10];
    QWORD cr[0x10];
} XECRYPT_RSAPRV_2048, *PXECRYPT_RSAPRV_2048;

typedef struct {
    XECRYPT_RSA rsa;
    QWORD n[0x40];  // modulus
    QWORD p[0x20];
    QWORD q[0x20];
    QWORD dp[0x20];
    QWORD dq[0x20];
    QWORD cr[0x20];
} XECRYPT_RSAPRV_4096, *PXECRYPT_RSAPRV_4096;

typedef struct _XECRYPT_DES_STATE { 
	DWORD keytab[0x10][0x2]; // 0x0 sz:0x80
} XECRYPT_DES_STATE, *PXECRYPT_DES_STATE; // size 128

/* ******************* DES3 stuff ******************* */
typedef struct _XECRYPT_DES3_STATE { 
	XECRYPT_DES_STATE aDesState[0x3]; // 0x0 sz:0x180
} XECRYPT_DES3_STATE, *PXECRYPT_DES3_STATE; // size 384

/* ******************* AES stuff ******************* */
typedef struct _XECRYPT_AES_STATE { 
	BYTE keytabenc[0xB][0x4][0x4]; // 0x0 sz:0xB0
	BYTE keytabdec[0xB][0x4][0x4]; // 0xB0 sz:0xB0
} XECRYPT_AES_STATE, *PXECRYPT_AES_STATE; // size 352

/* ******************* RC4 stuff ******************* */
typedef struct _XECRYPT_RC4_STATE { 
	BYTE S[0x100]; // 0x0 sz:0x100
	BYTE i; // 0x100 sz:0x1
	BYTE j; // 0x101 sz:0x1
} XECRYPT_RC4_STATE, *PXECRYPT_RC4_STATE; // size 258

/* ******************* SHA stuff ******************* */
typedef struct _XECRYPT_SHA_STATE { 
	DWORD count; // 0x0 sz:0x4
	DWORD state[0x5]; // 0x4 sz:0x14
	BYTE buffer[0x40]; // 0x18 sz:0x40
} XECRYPT_SHA_STATE, *PXECRYPT_SHA_STATE; // size 88

/* ******************* HMACSHA stuff ******************* */
typedef struct _XECRYPT_HMACSHA_STATE { 
	XECRYPT_SHA_STATE ShaState[0x2]; // 0x0 sz:0xB0
} XECRYPT_HMACSHA_STATE, *PXECRYPT_HMACSHA_STATE; // size 176

/* ******************* MD5 stuff ******************* */
typedef struct _XECRYPT_MD5_STATE { 
	DWORD count; // 0x0 sz:0x4
	DWORD buf[0x4]; // 0x4 sz:0x10
	BYTE in[0x40]; // 0x14 sz:0x40
} XECRYPT_MD5_STATE, *PXECRYPT_MD5_STATE; // size 84

/* ******************* HMACMD5 stuff ******************* */
typedef struct _XECRYPT_HMACMD5_STATE { 
	XECRYPT_MD5_STATE Md5State[0x2]; // 0x0 sz:0xA8
} XECRYPT_HMACMD5_STATE, *PXECRYPT_HMACMD5_STATE; // size 168

/* ******************* Diffie-Hellman stuff ******************* */
typedef struct _XECRYPT_DH { 
	DWORD cqw; // 0x0 sz:0x4
	DWORD dwReserved; // 0x4 sz:0x4
} XECRYPT_DH, *PXECRYPT_DH; // size 8

typedef struct _XECRYPT_DH_768 { 
	XECRYPT_DH Dh; // 0x0 sz:0x8
	QWORD aqwM[0xC]; // 0x8 sz:0x60
	QWORD aqwG[0xC]; // 0x68 sz:0x60
} XECRYPT_DH_768, *PXECRYPT_DH_768; // size 200

typedef struct _XECRYPT_DH_1024 { 
	XECRYPT_DH Dh; // 0x0 sz:0x8
	QWORD aqwM[0x10]; // 0x8 sz:0x80
	QWORD aqwB[0x10]; // 0x88 sz:0x80
} XECRYPT_DH_1024, *PXECRYPT_DH_1024; // size 264

/* ******************* eliptic curve stuff ******************* */
typedef struct _XECRYPT_ECPUB { 
	DWORD cqw; // 0x0 sz:0x4
	BYTE cbitR; // 0x4 sz:0x1
	BYTE cbitS; // 0x5 sz:0x1
	BYTE cbitA; // 0x6 sz:0x1
	BYTE cbitN; // 0x7 sz:0x1
} XECRYPT_ECPUB, *PXECRYPT_ECPUB; // size 8

typedef struct _XECRYPT_ECPUB_512 { 
	XECRYPT_ECPUB EcPub; // 0x0 sz:0x8
	QWORD aqwM[0x8]; // 0x8 sz:0x40
	QWORD aqwC[0x10]; // 0x48 sz:0x80
	QWORD aqwG[0x10]; // 0xC8 sz:0x80
	QWORD aqwGP[0x10]; // 0x148 sz:0x80
} XECRYPT_ECPUB_512, *PXECRYPT_ECPUB_512; // size 456

typedef struct _LDR_DATA_TABLE_ENTRY { 
	LIST_ENTRY InLoadOrderLinks;  // 0x0 sz:0x8
	LIST_ENTRY InClosureOrderLinks;  // 0x8 sz:0x8
	LIST_ENTRY InInitializationOrderLinks; // 0x10 sz:0x8
	PVOID NtHeadersBase; // 0x18 sz:0x4
	PVOID ImageBase; // 0x1C sz:0x4
	DWORD SizeOfNtImage; // 0x20 sz:0x4
	UNICODE_STRING FullDllName; // 0x24 sz:0x8
	UNICODE_STRING BaseDllName; // 0x2C sz:0x8
	DWORD Flags; // 0x34 sz:0x4
	DWORD SizeOfFullImage; // 0x38 sz:0x4
	PVOID EntryPoint; // 0x3C sz:0x4
	WORD LoadCount; // 0x40 sz:0x2
	WORD ModuleIndex; // 0x42 sz:0x2
	PVOID DllBaseOriginal; // 0x44 sz:0x4
	DWORD CheckSum; // 0x48 sz:0x4
	DWORD ModuleLoadFlags; // 0x4C sz:0x4
	DWORD TimeDateStamp; // 0x50 sz:0x4
	PVOID LoadedImports; // 0x54 sz:0x4
	PVOID XexHeaderBase; // 0x58 sz:0x4
	union{
		STRING LoadFileName; // 0x5C sz:0x8
		struct {
			PVOID ClosureRoot; // 0x5C sz:0x4 LDR_DATA_TABLE_ENTRY
			PVOID TraversalParent; // 0x60 sz:0x4 LDR_DATA_TABLE_ENTRY
		} asEntry;
	} inf;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY; // size 100