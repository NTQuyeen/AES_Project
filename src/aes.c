#include <stdio.h>
#include "aes.h"
#include "aes_tables.h"

/* ========== Helper: get number of rounds from key size ========== */
static int get_num_rounds(int keySize)
{
    if (keySize == 24) return 12;  /* AES-192 */
    if (keySize == 32) return 14;  /* AES-256 */
    return 10;                     /* AES-128 */
}

/* ========== SubBytes ========== */
void SubBytes(unsigned char state[16])
{
    for(int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
}

/* ========== ShiftRows ========== */
void ShiftRows(unsigned char state[16])
{
    unsigned char temp;

    /* Row 1: shift left 1 */
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    /* Row 2: shift left 2 */
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;

    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    /* Row 3: shift left 3 (= shift right 1) */
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

/* ========== xtime ========== */
unsigned char xtime(unsigned char x)
{
    return (x<<1) ^ ((x>>7) * 0x1b);
}

/* ========== MixColumns ========== */
void MixColumns(unsigned char state[16])
{
    unsigned char t, tmp, tm;

    for(int i=0;i<4;i++)
    {
        int col = i*4;

        t = state[col];
        tmp = state[col] ^ state[col+1] ^ state[col+2] ^ state[col+3];

        tm = state[col] ^ state[col+1];
        tm = xtime(tm);
        state[col] ^= tm ^ tmp;

        tm = state[col+1] ^ state[col+2];
        tm = xtime(tm);
        state[col+1] ^= tm ^ tmp;

        tm = state[col+2] ^ state[col+3];
        tm = xtime(tm);
        state[col+2] ^= tm ^ tmp;

        tm = state[col+3] ^ t;
        tm = xtime(tm);
        state[col+3] ^= tm ^ tmp;
    }
}

/* ========== AddRoundKey ========== */
void AddRoundKey(unsigned char state[16], unsigned char roundKey[16])
{
    for(int i = 0; i < 16; i++)
        state[i] ^= roundKey[i];
}

/* ========== RotWord ========== */
void RotWord(unsigned char *word)
{
    unsigned char temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

/* ========== SubWord ========== */
void SubWord(unsigned char *word)
{
    for(int i = 0; i < 4; i++)
        word[i] = sbox[word[i]];
}

/* ==========================================================
   KeyExpansion — Supports AES-128/192/256
   keySize: 16 (AES-128), 24 (AES-192), 32 (AES-256)
   expandedKey size:
     AES-128: 176 bytes (11 round keys)
     AES-192: 208 bytes (13 round keys)
     AES-256: 240 bytes (15 round keys)
   ========================================================== */
void KeyExpansion(unsigned char *key, unsigned char *expandedKey, int keySize)
{
    int Nk = keySize / 4;           /* Number of 32-bit words in key */
    int Nr = get_num_rounds(keySize);
    int expandedKeySize = 16 * (Nr + 1);  /* Total bytes needed */

    /* Copy original key */
    for(int i = 0; i < keySize; i++)
        expandedKey[i] = key[i];

    int bytesGenerated = keySize;
    int rconIteration = 1;
    unsigned char temp[4];

    while(bytesGenerated < expandedKeySize)
    {
        /* Get the last 4 bytes generated */
        for(int i = 0; i < 4; i++)
            temp[i] = expandedKey[bytesGenerated - 4 + i];

        /* At the start of each Nk-word group */
        if(bytesGenerated % keySize == 0)
        {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[rconIteration++];
        }
        /* AES-256 only: extra SubWord when i % Nk == 4 */
        else if(Nk == 8 && (bytesGenerated % keySize) == 16)
        {
            SubWord(temp);
        }

        /* XOR with the word Nk positions earlier */
        for(int i = 0; i < 4; i++)
        {
            expandedKey[bytesGenerated] =
                expandedKey[bytesGenerated - keySize] ^ temp[i];
            bytesGenerated++;
        }
    }
}

/* ==========================================================
   AES Encrypt — Supports AES-128/192/256
   ========================================================== */
void AES_encrypt(unsigned char input[16], unsigned char output[16],
                 unsigned char *key, int keySize)
{
    unsigned char state[16];
    unsigned char expandedKey[AES_MAX_EXPANDED_KEY];
    int Nr = get_num_rounds(keySize);

    for(int i = 0; i < 16; i++)
        state[i] = input[i];

    KeyExpansion(key, expandedKey, keySize);

    /* Initial round: AddRoundKey only */
    AddRoundKey(state, expandedKey);

    /* Main rounds: 1 to Nr-1 */
    for(int round = 1; round <= Nr - 1; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKey + (16 * round));
    }

    /* Final round: no MixColumns */
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKey + (16 * Nr));

    for(int i = 0; i < 16; i++)
        output[i] = state[i];
}

/* ========== InvSubBytes ========== */
void InvSubBytes(unsigned char state[16])
{
    for(int i=0;i<16;i++)
        state[i] = inv_sbox[state[i]];
}

/* ========== InvShiftRows ========== */
void InvShiftRows(unsigned char state[16])
{
    unsigned char temp;

    /* Row 1: shift right 1 */
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    /* Row 2: shift right 2 */
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;

    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    /* Row 3: shift right 3 (= shift left 1) */
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

/* ========== gmul — Galois Field Multiplication ========== */
unsigned char gmul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;

    for(int i=0;i<8;i++)
    {
        if(b & 1) p ^= a;

        unsigned char hi = a & 0x80;
        a <<= 1;

        if(hi) a ^= 0x1b;

        b >>= 1;
    }

    return p;
}

/* ========== InvMixColumns ========== */
void InvMixColumns(unsigned char state[16])
{
    unsigned char temp[16];

    for(int i=0;i<4;i++)
    {
        int col = i*4;

        temp[col+0] =
            gmul(state[col+0],14) ^
            gmul(state[col+1],11) ^
            gmul(state[col+2],13) ^
            gmul(state[col+3],9);

        temp[col+1] =
            gmul(state[col+0],9) ^
            gmul(state[col+1],14) ^
            gmul(state[col+2],11) ^
            gmul(state[col+3],13);

        temp[col+2] =
            gmul(state[col+0],13) ^
            gmul(state[col+1],9) ^
            gmul(state[col+2],14) ^
            gmul(state[col+3],11);

        temp[col+3] =
            gmul(state[col+0],11) ^
            gmul(state[col+1],13) ^
            gmul(state[col+2],9) ^
            gmul(state[col+3],14);
    }

    for(int i=0;i<16;i++)
        state[i] = temp[i];
}

/* ==========================================================
   AES Decrypt — Supports AES-128/192/256
   ========================================================== */
void AES_decrypt(unsigned char input[16], unsigned char output[16],
                 unsigned char *key, int keySize)
{
    unsigned char state[16];
    unsigned char expandedKey[AES_MAX_EXPANDED_KEY];
    int Nr = get_num_rounds(keySize);

    for(int i=0;i<16;i++)
        state[i] = input[i];

    KeyExpansion(key, expandedKey, keySize);

    /* Start from last round key */
    AddRoundKey(state, expandedKey + Nr * 16);

    /* Rounds Nr-1 down to 1 */
    for(int round = Nr - 1; round >= 1; round--)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, expandedKey + round * 16);
        InvMixColumns(state);
    }

    /* Final round */
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, expandedKey);  /* K0 */

    for(int i=0;i<16;i++)
        output[i] = state[i];
}
