#include <stdio.h>
#include <string.h>
#include <time.h>
#include "aes.h"

#define LOOP 1   // để 1 cho dễ debug

// ================== HEX -> BYTE ==================
void hex_to_bytes(char *hex, unsigned char *bytes)
{
    for(int i = 0; i < 16; i++)
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);
}

// ================== ENCRYPT ==================
void encrypt_file(char *inputFile, char *outputFile, unsigned char key[16])
{
    FILE *fin = fopen(inputFile, "rb");
    if(fin == NULL)
    {
        printf("Cannot open input file\n");
        return;
    }

    FILE *fout = fopen(outputFile, "wb");
    if(fout == NULL)
    {
        printf("Cannot open output file\n");
        fclose(fin);
        return;
    }

    unsigned char buffer[16];
    unsigned char encrypted[16];
    int bytesRead;

    while((bytesRead = fread(buffer, 1, 16, fin)) > 0)
    {
        unsigned char pad = 16 - bytesRead;

        // padding PKCS7
        if(bytesRead < 16)
        {
            for(int i = bytesRead; i < 16; i++)
                buffer[i] = pad;
        }

        AES_encrypt(buffer, encrypted, key);

        // debug HEX
        printf("Encrypted: ");
        for(int i = 0; i < 16; i++)
            printf("%02x ", encrypted[i]);
        printf("\n");

        fwrite(encrypted, 1, 16, fout);
    }

    fclose(fin);
    fclose(fout);
}

// ================== DECRYPT ==================
void decrypt_file(char *inputFile, char *outputFile, unsigned char key[16])
{
    FILE *fin = fopen(inputFile, "rb");
    if(fin == NULL)
    {
        printf("Cannot open encrypted file\n");
        return;
    }

    FILE *fout = fopen(outputFile, "wb");
    if(fout == NULL)
    {
        printf("Cannot open output file\n");
        fclose(fin);
        return;
    }

    unsigned char buffer[16];
    unsigned char decrypted[16];
    unsigned char prev[16];

    int first = 1;

    while(fread(buffer, 1, 16, fin) == 16)
    {
        AES_decrypt(buffer, decrypted, key);

        if(!first)
            fwrite(prev, 1, 16, fout);

        memcpy(prev, decrypted, 16);
        first = 0;
    }

    int pad = prev[15];

    if(pad < 1 || pad > 16)
    {
        printf("Invalid padding!\n");
        fclose(fin);
        fclose(fout);
        return;
    }

    fwrite(prev, 1, 16 - pad, fout);

    fclose(fin);
    fclose(fout);
}

// ================== MAIN ==================
int main()
{
    unsigned char key[16];
    char hex_input[33];

    printf("Nhap key HEX (32 ky tu): ");
    scanf("%32s", hex_input);

    if(strlen(hex_input) != 32)
    {
        printf("Key phai dung 32 ky tu HEX!\n");
        return 1;
    }

    hex_to_bytes(hex_input, key);

    clock_t start, end;

    start = clock();
    encrypt_file("input.txt", "encrypted.bin", key);
    end = clock();

    printf("Encryption time: %.6f s\n",
           (double)(end - start) / CLOCKS_PER_SEC);

    start = clock();
    decrypt_file("encrypted.bin", "decrypted.txt", key);
    end = clock();

    printf("Decryption time: %.6f s\n",
           (double)(end - start) / CLOCKS_PER_SEC);

    return 0;
}
