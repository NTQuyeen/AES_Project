#ifndef AES_H
#define AES_H

#define AES_BLOCK_SIZE 16
#define AES_MAX_EXPANDED_KEY 240  /* AES-256: 15 * 16 = 240 */

/* keySize: 16 (AES-128), 24 (AES-192), 32 (AES-256) */
int AES_get_num_rounds(int keySize);

void AES_encrypt(unsigned char input[16], unsigned char output[16],
                 unsigned char *key, int keySize);
void AES_decrypt(unsigned char input[16], unsigned char output[16],
                 unsigned char *key, int keySize);

void AES_encrypt_block(unsigned char input[16], unsigned char output[16],
                       unsigned char *expandedKey, int Nr);
void AES_decrypt_block(unsigned char input[16], unsigned char output[16],
                       unsigned char *expandedKey, int Nr);


void SubBytes(unsigned char state[16]);
void ShiftRows(unsigned char state[16]);
void MixColumns(unsigned char state[16]);
void AddRoundKey(unsigned char state[16], unsigned char roundKey[16]);
void KeyExpansion(unsigned char *key, unsigned char *expandedKey, int keySize);
void RotWord(unsigned char *word);
void SubWord(unsigned char *word);

#endif
