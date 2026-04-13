#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"
#include "aes_tables.h"

/* ========== Helper ========== */
int AES_get_num_rounds(int keySize)
{
    if (keySize == 24) return 12;
    if (keySize == 32) return 14;
    return 10;
}

/* ========== SubBytes ========== */
void SubBytes(unsigned char state[16])
{
    for(int i=0;i<16;i++)
        state[i] = sbox[state[i]];
}

/* ========== InvSubBytes ========== */
void InvSubBytes(unsigned char state[16])
{
    for(int i=0;i<16;i++)
        state[i] = inv_sbox[state[i]];
}

/* ========== ShiftRows ========== */
void ShiftRows(unsigned char state[16])
{
    unsigned char t;

    t=state[1]; state[1]=state[5]; state[5]=state[9]; state[9]=state[13]; state[13]=t;
    t=state[2]; state[2]=state[10]; state[10]=t;
    t=state[6]; state[6]=state[14]; state[14]=t;
    t=state[3]; state[3]=state[15]; state[15]=state[11]; state[11]=state[7]; state[7]=t;
}

/* ========== InvShiftRows ========== */
void InvShiftRows(unsigned char state[16])
{
    unsigned char t;

    t=state[13]; state[13]=state[9]; state[9]=state[5]; state[5]=state[1]; state[1]=t;
    t=state[2]; state[2]=state[10]; state[10]=t;
    t=state[6]; state[6]=state[14]; state[14]=t;
    t=state[3]; state[3]=state[7]; state[7]=state[11]; state[11]=state[15]; state[15]=t;
}

/* ========== xtime ========== */
unsigned char xtime(unsigned char x)
{
    return (x<<1) ^ ((x>>7) * 0x1b);
}

/* ========== AddRoundKey (tối ưu 32-bit) ========== */
void AddRoundKey(unsigned char *state, unsigned char *rk)
{
    uint32_t *s = (uint32_t*)state;
    uint32_t *k = (uint32_t*)rk;

    s[0]^=k[0];
    s[1]^=k[1];
    s[2]^=k[2];
    s[3]^=k[3];
}

/* ========== MixColumns ========== */
void MixColumns(unsigned char state[16])
{
    for(int i=0;i<4;i++)
    {
        int col=i*4;

        unsigned char a=state[col];
        unsigned char b=state[col+1];
        unsigned char c=state[col+2];
        unsigned char d=state[col+3];

        unsigned char t = a ^ b ^ c ^ d;

        state[col]   ^= xtime(a ^ b) ^ t;
        state[col+1] ^= xtime(b ^ c) ^ t;
        state[col+2] ^= xtime(c ^ d) ^ t;
        state[col+3] ^= xtime(d ^ a) ^ t;
    }
}

/* ========== GMUL (OPTIMIZED – KHÔNG IF) ========== */
unsigned char gmul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;

    while (b)
    {
        p ^= a & -(b & 1);

        unsigned char hi = a & 0x80;
        a <<= 1;
        a ^= (0x1b & -(hi >> 7));

        b >>= 1;
    }

    return p;
}

/* ========== InvMixColumns (SIÊU TỐI ƯU) ========== */
void InvMixColumns(unsigned char state[16])
{
    for(int i=0;i<4;i++)
    {
        int col=i*4;

        unsigned char a = state[col];
        unsigned char b = state[col+1];
        unsigned char c = state[col+2];
        unsigned char d = state[col+3];

        unsigned char u = xtime(xtime(a ^ c));
        unsigned char v = xtime(xtime(b ^ d));

        a ^= u;
        b ^= v;
        c ^= u;
        d ^= v;

        unsigned char t = a ^ b ^ c ^ d;

        state[col]   = a ^ t ^ xtime(a ^ b);
        state[col+1] = b ^ t ^ xtime(b ^ c);
        state[col+2] = c ^ t ^ xtime(c ^ d);
        state[col+3] = d ^ t ^ xtime(d ^ a);
    }
}

/* ========== RotWord ========== */
void RotWord(unsigned char *word)
{
    unsigned char t=word[0];
    word[0]=word[1]; word[1]=word[2];
    word[2]=word[3]; word[3]=t;
}

/* ========== SubWord ========== */
void SubWord(unsigned char *word)
{
    for(int i=0;i<4;i++)
        word[i]=sbox[word[i]];
}

/* ========== KeyExpansion ========== */
void KeyExpansion(unsigned char *key, unsigned char *expandedKey, int keySize)
{
    int Nk = keySize/4;
    int Nr = AES_get_num_rounds(keySize);

    memcpy(expandedKey,key,keySize);

    int bytesGenerated=keySize;
    int rconIteration=1;
    unsigned char temp[4];

    while(bytesGenerated < 16*(Nr+1))
    {
        for(int i=0;i<4;i++)
            temp[i]=expandedKey[bytesGenerated-4+i];

        if(bytesGenerated % keySize == 0)
        {
            RotWord(temp);
            SubWord(temp);
            temp[0]^=Rcon[rconIteration++];
        }
        else if(Nk==8 && (bytesGenerated % keySize)==16)
        {
            SubWord(temp);
        }

        for(int i=0;i<4;i++)
        {
            expandedKey[bytesGenerated] =
                expandedKey[bytesGenerated-keySize]^temp[i];
            bytesGenerated++;
        }
    }
}

/* ========== Encrypt ========== */
void AES_encrypt_block(unsigned char input[16], unsigned char output[16],
                       unsigned char *expandedKey, int Nr)
{
    unsigned char state[16];
    memcpy(state, input, 16);

    AddRoundKey(state, expandedKey);

    for(int round=1; round<Nr; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKey + 16*round);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKey + 16*Nr);

    memcpy(output, state, 16);
}

void AES_encrypt(unsigned char input[16], unsigned char output[16],
                 unsigned char *key, int keySize)
{
    unsigned char expandedKey[AES_MAX_EXPANDED_KEY];
    int Nr = AES_get_num_rounds(keySize);
    KeyExpansion(key, expandedKey, keySize);
    AES_encrypt_block(input, output, expandedKey, Nr);
}

/* ========== Decrypt (TỐI ƯU) ========== */
void AES_decrypt_block(unsigned char input[16], unsigned char output[16],
                       unsigned char *expandedKey, int Nr)
{
    unsigned char state[16];
    memcpy(state, input, 16);

    unsigned char *rk = expandedKey + Nr*16;

    AddRoundKey(state, rk);
    rk -= 16;

    for(int round=Nr-1; round>=1; round--)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, rk);
        InvMixColumns(state);
        rk -= 16;
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, expandedKey);

    memcpy(output, state, 16);
}

void AES_decrypt(unsigned char input[16], unsigned char output[16],
                 unsigned char *key, int keySize)
{
    unsigned char expandedKey[AES_MAX_EXPANDED_KEY];
    int Nr = AES_get_num_rounds(keySize);
    KeyExpansion(key, expandedKey, keySize);
    AES_decrypt_block(input, output, expandedKey, Nr);
}
