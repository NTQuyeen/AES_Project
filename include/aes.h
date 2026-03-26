#ifndef AES_H
#define AES_H

#define AES_BLOCK_SIZE 16

void AES_encrypt(unsigned char input[16], unsigned char output[16], unsigned char key[16]);
void AES_decrypt(unsigned char input[16], unsigned char output[16], unsigned char key[16]);

void SubBytes(unsigned char state[16]);
void ShiftRows(unsigned char state[16]);
void MixColumns(unsigned char state[16]);
void AddRoundKey(unsigned char state[16], unsigned char roundKey[16]);
void KeyExpansion(unsigned char key[16], unsigned char expandedKey[176]);

#endif
