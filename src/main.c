#include <stdio.h>
#include "aes.h"
#include <time.h>
#include <string.h>
void print_state(unsigned char state[16])
{
    int i;
    for(i=0;i<16;i++)
    {
        printf("%02x ",state[i]);
    }
    printf("\n");
}

void print_hex(unsigned char data[16])
{
    int i;

    for(i = 0; i < 16; i++)
    {
        printf("%02x ", data[i]);
    }

    printf("\n");
}

void encrypt_file(char *inputFile, char *outputFile, unsigned char key[16])
{
    FILE *fin = fopen(inputFile, "rb");
    FILE *fout = fopen(outputFile, "wb");

    unsigned char buffer[16];
    unsigned char encrypted[16];

    int bytesRead;

    while((bytesRead = fread(buffer, 1, 16, fin)) > 0)
    {
        if(bytesRead < 16)
        {
            unsigned char pad = 16 - bytesRead;
            for(int i = bytesRead; i < 16; i++)
                buffer[i] = pad;
        }

        AES_encrypt(buffer, encrypted, key);
        fwrite(encrypted, 1, 16, fout);
    }

    fclose(fin);
    fclose(fout);
}
void decrypt_file(char *inputFile, char *outputFile, unsigned char key[16])
{
    FILE *fin = fopen(inputFile, "rb");
    FILE *fout = fopen(outputFile, "wb");

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
    fwrite(prev, 1, 16 - pad, fout);

    fclose(fin);
    fclose(fout);
}
int main()
{
 /*   unsigned char state[16] = {
        0,1,2,3,
        4,5,6,7,
        8,9,10,11,
        12,13,14,15
    };

    printf("Before ShiftRows:\n");
    print_state(state);

    ShiftRows(state);

    printf("After ShiftRows:\n");
    print_state(state);

    return 0;

     unsigned char state[16] =
    {
        0xdb,0x13,0x53,0x45,
        0xf2,0x0a,0x22,0x5c,
        0x01,0x01,0x01,0x01,
        0xc6,0xc6,0xc6,0xc6
    };

    printf("Before MixColumns:\n");
    print_state(state);

    MixColumns(state);

    printf("After MixColumns:\n");
    print_state(state);

    return 0;

    unsigned char state[16] =
    {
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,
        0xcc,0xdd,0xee,0xff
    };

    unsigned char key[16] =
    {
        0x0f,0x0e,0x0d,0x0c,
        0x0b,0x0a,0x09,0x08,
        0x07,0x06,0x05,0x04,
        0x03,0x02,0x01,0x00
    };

    printf("Before AddRoundKey:\n");
    print_state(state);

    AddRoundKey(state, key);

    printf("After AddRoundKey:\n");
    print_state(state);

    return 0;
     unsigned char key[16] =
    {
        0x2b,0x7e,0x15,0x16,
        0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,
        0x09,0xcf,0x4f,0x3c
    };

    unsigned char expandedKey[176];

    KeyExpansion(key, expandedKey);

    printf("Expanded Keys:\n");

    for(int i=0;i<176;i++)
    {
        printf("%02x ",expandedKey[i]);

        if((i+1)%16==0)
            printf("\n");
    }

    return 0;
    unsigned char plaintext[16] =
    {
        0x32,0x43,0xf6,0xa8,
        0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,
        0xe0,0x37,0x07,0x34
    };

    unsigned char key[16] =
    {
        0x2b,0x7e,0x15,0x16,
        0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,
        0x09,0xcf,0x4f,0x3c
    };

    unsigned char ciphertext[16];

    AES_encrypt(plaintext, ciphertext, key);

    printf("Plaintext:\n");
    print_hex(plaintext);

    printf("Ciphertext:\n");
    print_hex(ciphertext);

    return 0;*/
    unsigned char key[16] =
    {
        0x2b,0x7e,0x15,0x16,
        0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,
        0x09,0xcf,0x4f,0x3c
    };

    clock_t start, end;

    // Encryption
    start = clock();

    encrypt_file("input.txt", "encrypted.bin", key);

    end = clock();

    double encrypt_time = (double)(end - start) / CLOCKS_PER_SEC;

    printf("Encryption time: %f seconds\n", encrypt_time);

    // Decryption
    start = clock();

    decrypt_file("encrypted.bin", "decrypted.txt", key);

    end = clock();

    double decrypt_time = (double)(end - start) / CLOCKS_PER_SEC;

    printf("Decryption time: %f seconds\n", decrypt_time);

    return 0;
}
