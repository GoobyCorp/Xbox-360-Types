#include <stdio.h>

#include "xbox360.h"

void HexPrint(PBYTE data, DWORD size) {
    for(int i = 0; i < size; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    printf("test compile!\n");

    HexPrint((PBYTE)XECRYPT_1BL_KEY, 0x10);
    printf("%s\n", XECRYPT_1BL_SALT);
    printf("%s\n", XECRYPT_SC_SALT);
    printf("%s\n", XECRYPT_SD_SALT);

    return 0;
}