#ifndef AES_H
#define AES_H

#define AES_BLOCK_SIZE 16

#define AES_128 16
#define AES_192 24
#define AES_256 32

void AES_encrypt(const unsigned char *input, unsigned char *output,
                 const unsigned char *key, int keySize);

void AES_decrypt(const unsigned char *input, unsigned char *output,
                 const unsigned char *key, int keySize);

void SubBytes(unsigned char state[16]);
void ShiftRows(unsigned char state[16]);
void MixColumns(unsigned char state[16]);
void AddRoundKey(unsigned char state[16], unsigned char roundKey[16]);

void KeyExpansion(unsigned char *key, unsigned char *expandedKey, int keySize);

#endif
