#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Wincrypt.h>

int main()
{
    // RSA variables
    HCRYPTPROV hCryptProv;               // Cryptographic context
    HCRYPTKEY hRsaKey;                   // Imported RSA key
    DWORD rsaKeyDataLen = 0x494;         // RSA key length
    BYTE rsaKeyData[0x494];              // RSA data

    // Read RSA key from file
    FILE *rsaKeyFile = fopen("rsa2key.bin", "rb");
    if (rsaKeyFile == NULL) {
        printf("Failed to open rsa2key.bin.\n");
        return -1;
    }

    if (fread(rsaKeyData, rsaKeyDataLen, 1, rsaKeyFile) != 1) {
        printf("Failed to read RSA key from file.\n");
        fclose(rsaKeyFile);
        return -1;
    }
    fclose(rsaKeyFile);

    // Acquire cryptographic context
    if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Failed to acquire crypto context.\n");
        return -1;
    }
    printf("Acquired crypto context.\n");

    // Import RSA key
    if (!CryptImportKey(hCryptProv, rsaKeyData, rsaKeyDataLen, 0, 0, &hRsaKey)) {
        printf("Failed to import RSA key.\n");
        return -1;
    }
    printf("RSA key imported successfully.\n");

    // AES Key Variables (encrypted with RSA)
    BYTE encryptedAesKey[256];        // Encrypted AES key
    DWORD encryptedAesKeyLen = 256;   // Encrypted AES key length

    // Read encrypted AES key from file
    FILE *aesEncryptedFile = fopen("encrypted_aes_key.bin", "rb");
    if (aesEncryptedFile == NULL) {
        printf("Failed to open encrypted_aes_key.bin.\n");
        return -1;
    }

    if (fread(encryptedAesKey, sizeof(encryptedAesKey), 1, aesEncryptedFile) != 1) {
        printf("Failed to read AES key.\n");
        fclose(aesEncryptedFile);
        return -1;
    }
    fclose(aesEncryptedFile);

    // Decrypt AES key with the imported RSA key
    if (!CryptDecrypt(hRsaKey, 0, TRUE, 0, encryptedAesKey, &encryptedAesKeyLen)) {
        printf("Decryption of AES key failed.\n");
        return -1;
    }
    printf("Decryption of AES key successful.\n");

    // Show the decrypted AES key
    printf("AES key:\n");
    for (DWORD i = 0; i < encryptedAesKeyLen; i++) {
        if (i && i % 16 == 0) printf("\n");
        printf("%02x ", encryptedAesKey[i]);
    }
    printf("\n");

    return 0;
}