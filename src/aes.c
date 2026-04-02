#include <stdio.h>
#include "aes.h"
#include "aes_tables.h"
#include <string.h>

void SubBytes(unsigned char state[16])
{
    for(int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
}

void ShiftRows(unsigned char state[16])
{
    unsigned char temp;

    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;

    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

unsigned char xtime(unsigned char x)
{
    return (x<<1) ^ ((x>>7) * 0x1b);
}

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

void AddRoundKey(unsigned char state[16], unsigned char roundKey[16])
{
    for(int i = 0; i < 16; i++)
        state[i] ^= roundKey[i];
}

void RotWord(unsigned char *word)
{
    unsigned char temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void SubWord(unsigned char *word)
{
    for(int i = 0; i < 4; i++)
        word[i] = sbox[word[i]];
}

void KeyExpansion(unsigned char *key, unsigned char *expandedKey, int keySize)
{
    int Nr = (keySize == 16) ? 10 : (keySize == 24 ? 12 : 14);
    int totalBytes = 16 * (Nr + 1);

    for (int i = 0; i < keySize; i++)
        expandedKey[i] = key[i];

    int bytesGenerated = keySize;
    int rconIteration = 1;
    unsigned char temp[4];

    while (bytesGenerated < totalBytes)
    {
        for (int i = 0; i < 4; i++)
            temp[i] = expandedKey[bytesGenerated - 4 + i];

        if (bytesGenerated % keySize == 0)
        {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[rconIteration++];
        }
        else if (keySize == 32 && bytesGenerated % keySize == 16)
        {
            SubWord(temp);
        }

        for (int i = 0; i < 4; i++)
        {
            expandedKey[bytesGenerated] =
                expandedKey[bytesGenerated - keySize] ^ temp[i];
            bytesGenerated++;
        }
    }
}

void AES_encrypt(const unsigned char *input, unsigned char *output,
                 const unsigned char *key, int keySize)
{
    unsigned char state[16];
    unsigned char expandedKey[240];

    memset(expandedKey, 0, sizeof(expandedKey));

    int Nr = (keySize == 16) ? 10 : (keySize == 24 ? 12 : 14);

    memcpy(state, input, 16);

    KeyExpansion((unsigned char *)key, expandedKey, keySize);

    AddRoundKey(state, expandedKey);

    for (int round = 1; round < Nr; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKey + 16 * round);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKey + 16 * Nr);

    memcpy(output, state, 16);
}
void InvSubBytes(unsigned char state[16])
{
    for(int i=0;i<16;i++)
        state[i] = inv_sbox[state[i]];
}

void InvShiftRows(unsigned char state[16])
{
    unsigned char temp;

    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;

    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

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

void AES_decrypt(const unsigned char *input, unsigned char *output,
                 const unsigned char *key, int keySize)
{
    unsigned char state[16];
    unsigned char expandedKey[240];

    memset(expandedKey, 0, sizeof(expandedKey));

    int Nr = (keySize == 16) ? 10 : (keySize == 24 ? 12 : 14);

    memcpy(state, input, 16);

    KeyExpansion((unsigned char *)key, expandedKey, keySize);

    AddRoundKey(state, expandedKey + 16 * Nr);

    for (int round = Nr - 1; round >= 1; round--)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, expandedKey + 16 * round);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, expandedKey);

    memcpy(output, state, 16);
}
