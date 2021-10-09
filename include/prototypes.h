#pragma once

// generic C lib
// memory
PVOID memcpy(PVOID dst, PVOID src, DWORD size);
PVOID memset(PVOID dst, DWORD value, DWORD size);
DWORD memcmp(PVOID ptr1, PVOID ptr2, DWORD num);
PVOID malloc(DWORD size);
VOID free(PVOID ptr);
// strings
DWORD strlen(PCHAR str);
// output
VOID printf(PCHAR fmt, ...);
VOID DbgPrint(PCHAR fmt, ...);

// kernel
NTSTATUS XexGetModuleHandle(PCHAR moduleName, PHANDLE hand);
NTSTATUS XexGetProcedureAddress(HANDLE hand, DWORD dwOrdinal, PVOID pvAddress);
PVOID MmGetPhysicalAddress(PVOID addr);
BOOL MmIsAddressValid(PVOID addr);
NTSTATUS XexLoadExecutable(PCHAR szXexName, PHANDLE pHandle, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion );
NTSTATUS XexLoadImage(LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle);
NTSTATUS XexLoadImageFromMemory(PVOID pvXexBuffer, DWORD dwSize, LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle);
PVOID XexPcToFileHeader(PVOID address, PLDR_DATA_TABLE_ENTRY* ldatOut);
VOID XexUnloadImage(HANDLE moduleHandle);

// XeKeys
DWORD HvxExpansionInstall(QWORD addr, DWORD size);
QWORD HvxExpansionCall(DWORD sig, HVPPCommand cmd, QWORD Arg2, QWORD Arg3, QWORD Arg4);

// XeCrypt
VOID XeCryptAesKey(
    PXECRYPT_AES_STATE pAesState,
    PBYTE pbKey
);

VOID XeCryptAesEcb(
    PXECRYPT_AES_STATE pAesState,
    PBYTE pbInp,
    PBYTE pbOut,
    BOOL fEncrypt
);

VOID XeCryptAesCbc(
    PXECRYPT_AES_STATE pAesState,
    PBYTE pbInp,
    DWORD cbInp,
    PBYTE pbOut,
    PBYTE pbFeed,
    BOOL fEncrypt
);

BOOL XeCryptBnDwLeDhEqualBase(
    PDWORD pdwA,
    PXECRYPT_DH pDh
);

BOOL XeCryptBnDwLeDhInvalBase(
    PDWORD pdwA,
    PXECRYPT_DH pDh
);

BOOL XeCryptBnDwLeDhModExp(
    PDWORD pdwA,
    PDWORD pdwB,
    PDWORD pdwC,
    PXECRYPT_DH pDh
);

VOID XeCryptBnDw_Copy(
    PDWORD pdwInp,
    PDWORD pdwOut,
    DWORD cdw
);

VOID XeCryptBnDw_SwapLeBe(
    PDWORD pdwInp,
    PDWORD pdwOut,
    DWORD cdw
);

VOID XeCryptBnDw_Zero(
    PDWORD pdw,
    DWORD cdw
);

VOID XeCryptBnDwLePkcs1Format(
    PBYTE pbHash,
    DWORD dwType,
    PBYTE pbSig,
    DWORD cbSig
);

BOOL XeCryptBnDwLePkcs1Verify(
    PBYTE pbHash,
    PBYTE pbSig,
    DWORD cbSig
);

BOOL XeCryptBnQwBeSigCreate(
    PXECRYPT_SIG pSig,
    PBYTE pbHash,
    PBYTE pbSalt,
    PXECRYPT_RSA pRsa
);

VOID XeCryptBnQwBeSigFormat(
    PXECRYPT_SIG pSig,
    PBYTE pbHash,
    PBYTE pbSalt
);

BOOL XeCryptBnQwBeSigVerify(
    PXECRYPT_SIG pSig,
    PBYTE pbHash,
    PBYTE pbSalt,
    PXECRYPT_RSA pRsa
);

BOOL XeCryptBnQwNeModExp(
    PQWORD pqwOut,
    PQWORD pqwIn,
    PQWORD pqwInExp,
    PQWORD pqwInMod,
    DWORD cqw
);

BOOL XeCryptBnQwNeModExpRoot(
    PQWORD pqwOut,
    PQWORD pqwIn,
    PQWORD pqwPP,
    PQWORD pqwQQ,
    PQWORD pqwDP,
    PQWORD pqwDQ,
    PQWORD pqwCR,
    DWORD cqw
);

QWORD XeCryptBnQwNeModInv(
    QWORD qw
);

VOID XeCryptBnQwNeModMul(
    PQWORD pqwA,
    PQWORD pqwB,
    PQWORD pqwOut,
    QWORD qwMI,
    PQWORD pqwM,
    DWORD cqw
);

BOOL XeCryptBnQwNeRsaKeyGen(
    DWORD cbits,
    DWORD dwPubExp,
    PXECRYPT_RSA pRsaPub,
    PXECRYPT_RSA pRsaPrv
);

BOOL XeCryptBnQwNeRsaPrvCrypt(
    PQWORD pqwIn,
    PQWORD pqwOut,
    PXECRYPT_RSA pRsa
);

BOOL XeCryptBnQwNeRsaPubCrypt(
    PQWORD pqwIn,
    PQWORD pqwOut,
    PXECRYPT_RSA pRsa
);

VOID XeCryptBnQw_Copy(
    PQWORD pqwInp,
    PQWORD pqwOut,
    DWORD cqw
);

VOID XeCryptBnQw_SwapDwQw(
    PQWORD pqwInp,
    PQWORD pqwOut,
    DWORD cqw
);

VOID XeCryptBnQw_SwapDwQwLeBe(
    PQWORD pqwInp,
    PQWORD pqwOut,
    DWORD cqw
);

VOID XeCryptBnQw_SwapLeBe(
    PQWORD pqwInp,
    PQWORD pqwOut,
    DWORD cqw
);

VOID XeCryptBnQw_Zero(
    PQWORD pqw,
    DWORD cqw
);

VOID XeCryptChainAndSumMac(
    PDWORD pdwCD,
    PDWORD pdwAB,
    PDWORD pdwInp,
    DWORD cdwInp,
    PDWORD pdwOut
);

VOID XeCryptDesParity(
    PBYTE pbInp,
    DWORD cbInp,
    PBYTE pbOut
);

VOID XeCryptDesKey(
    PXECRYPT_DES_STATE pDesState,
    PBYTE pbKey
);

VOID XeCryptDesEcb(
    PXECRYPT_DES_STATE pDesState,
    PBYTE pbInp,
    PBYTE pbOut,
    BOOL fEncrypt
);

VOID XeCryptDesCbc(
    PXECRYPT_DES_STATE pDesState,
    PBYTE pbInp,
    DWORD cbInp,
    PBYTE pbOut,
    PBYTE pbFeed,
    BOOL fEncrypt
);

VOID XeCryptDes3Key(
    PXECRYPT_DES3_STATE pDes3State,
    PBYTE pbKey
);

VOID XeCryptDes3Ecb(
    PXECRYPT_DES3_STATE pDes3State,
    PBYTE pbInp,
    PBYTE pbOut,
    BOOL fEncrypt
);

VOID XeCryptDes3Cbc(
    PXECRYPT_DES3_STATE pDes3State,
    PBYTE pbInp,
    DWORD cbInp,
    PBYTE pbOut,
    PBYTE pbFeed,
    BOOL fEncrypt
);

VOID XeCryptHmacMd5Init(
    PXECRYPT_HMACMD5_STATE pHmacMd5State,
    PBYTE pbKey,
    DWORD cbKey
);

VOID XeCryptHmacMd5Update(
    PXECRYPT_HMACMD5_STATE pHmacMd5State,
    PBYTE pbInp,
    DWORD cbInp
);

VOID XeCryptHmacMd5Final(
    PXECRYPT_HMACMD5_STATE pHmacMd5State,
    PBYTE pbOut,
    DWORD cbOut
);

VOID XeCryptHmacMd5(
    PBYTE pbKey,
    DWORD cbKey,
    PBYTE pbInp1,
    DWORD cbInp1,
    PBYTE pbInp2,
    DWORD cbInp2,
    PBYTE pbInp3,
    DWORD cbInp3,
    PBYTE pbOut,
    DWORD cbOut
);

VOID XeCryptHmacShaInit(
    PXECRYPT_HMACSHA_STATE pHmacShaState,
    PBYTE pbKey,
    DWORD cbKey
);

VOID XeCryptHmacShaUpdate(
    PXECRYPT_HMACSHA_STATE pHmacShaState,
    PBYTE pbInp,
    DWORD cbInp
);

VOID XeCryptHmacShaFinal(
    PXECRYPT_HMACSHA_STATE pHmacShaState,
    PBYTE pbOut,
    DWORD cbOut
);

VOID XeCryptHmacSha(
    PBYTE pbKey,
    DWORD cbKey,
    PBYTE pbInp1,
    DWORD cbInp1,
    PBYTE pbInp2,
    DWORD cbInp2,
    PBYTE pbInp3,
    DWORD cbInp3,
    PBYTE pbOut,
    DWORD cbOut
);

BOOL XeCryptHmacShaVerify(
    PBYTE pbKey,
    DWORD cbKey,
    PBYTE pbInp1,
    DWORD cbInp1,
    PBYTE pbInp2,
    DWORD cbInp2,
    PBYTE pbInp3,
    DWORD cbInp3,
    PBYTE pbVer,
    DWORD cbVer
);

VOID XeCryptMd5Init(
    PXECRYPT_MD5_STATE pMd5State
);

VOID XeCryptMd5Update(
    PXECRYPT_MD5_STATE pMd5State,
    PBYTE pbInp,
    DWORD cbInp
);

VOID XeCryptMd5Final(
    PXECRYPT_MD5_STATE pMd5State,
    PBYTE pbOut,
    DWORD cbOut
);

VOID XeCryptMd5(
    PBYTE pbInp1,
    DWORD cbInp1,
    PBYTE pbInp2,
    DWORD cbInp2,
    PBYTE pbInp3,
    DWORD cbInp3,
    PBYTE pbOut,
    DWORD cbOut
);

VOID XeCryptParveEcb(
    PBYTE pbKey,
    PBYTE pbSbox,
    PBYTE pbInp,
    PBYTE pbOut
);

VOID XeCryptParveCbcMac(
    PBYTE pbKey,
    PBYTE pbSbox,
    PBYTE pbIv,
    PBYTE pbInp,
    DWORD cbInp,
    PBYTE pbOut
);

VOID XeCryptRandom(
    PBYTE pb,
    DWORD cb
);

VOID XeCryptRc4Key(
    PXECRYPT_RC4_STATE pRc4State,
    PBYTE pbKey,
    DWORD cbKey
);

VOID XeCryptRc4Ecb(
    PXECRYPT_RC4_STATE pRc4State,
    PBYTE pbInpOut,
    DWORD cbInpOut
);

VOID XeCryptRc4(
    PBYTE pbKey,
    DWORD cbKey,
    PBYTE pbInpOut,
    DWORD cbInpOut
);

VOID XeCryptRotSumSha(
    PBYTE pbInp1,
    DWORD cbInp1,
    PBYTE pbInp2,
    DWORD cbInp2,
    PBYTE pbOut,
    DWORD cbOut
);

VOID XeCryptShaInit(
    PXECRYPT_SHA_STATE pShaState
);

VOID XeCryptShaUpdate(
    PXECRYPT_SHA_STATE pShaState,
    PBYTE pbInp,
    DWORD cbInp
);

VOID XeCryptShaFinal(
    PXECRYPT_SHA_STATE pShaState,
    PBYTE pbOut,
    DWORD cbOut
);

VOID XeCryptSha(
    PBYTE pbInp1,
    DWORD cbInp1,
    PBYTE pbInp2,
    DWORD cbInp2,
    PBYTE pbInp3,
    DWORD cbInp3,
    PBYTE pbOut,
    DWORD cbOut
);

int XeCryptBnQwNeCompare(
    PQWORD pqwA,
    PQWORD pqwB,
    DWORD cqw
);