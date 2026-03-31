#include <stdio.h>
#include "aes.h"
#include "aes_tables.h"

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

void KeyExpansion(unsigned char key[16], unsigned char expandedKey[176])
{
    for(int i = 0; i < 16; i++)
        expandedKey[i] = key[i];

    int bytesGenerated = 16;
    int rconIteration = 1;
    unsigned char temp[4];

    while(bytesGenerated < 176)
    {
        for(int i = 0; i < 4; i++)
            temp[i] = expandedKey[bytesGenerated - 4 + i];

        if(bytesGenerated % 16 == 0)
        {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[rconIteration++];
        }

        for(int i = 0; i < 4; i++)
        {
            expandedKey[bytesGenerated] =
                expandedKey[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }
}

void AES_encrypt(unsigned char input[16], unsigned char output[16], unsigned char key[16])
{
    unsigned char state[16];
    unsigned char expandedKey[176];

    for(int i = 0; i < 16; i++)
        state[i] = input[i];

    KeyExpansion(key, expandedKey);

    AddRoundKey(state, expandedKey);

    for(int round = 1; round <= 9; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKey + (16 * round));
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKey + 160);

    for(int i = 0; i < 16; i++)
        output[i] = state[i];
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

void AES_decrypt(unsigned char input[16],
                 unsigned char output[16],
                 unsigned char key[16])
{
    unsigned char state[16];
    unsigned char expandedKey[176];

    for(int i=0;i<16;i++)
        state[i] = input[i];

    KeyExpansion(key, expandedKey);

    AddRoundKey(state, expandedKey + 160);

    for(int round=9; round>=1; round--)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, expandedKey + round*16);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, expandedKey);

    for(int i=0;i<16;i++)
        output[i] = state[i];
}
