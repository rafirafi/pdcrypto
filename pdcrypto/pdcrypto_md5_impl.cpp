//
//  pdcrypto_md5_impl.cpp
//  pdcrypto
//
//  Created by rafirafi on 3/17/16.
//  Copyright (c) 2016 rafirafi. All rights reserved.
//
//  adapted from botan/src/lib/hash/md5/md5.cpp
//  Botan  http://botan.randombit.net
//  License :  https://github.com/randombit/botan/blob/master/doc/license.txt

#include <libkern/crypto/md5.h>
#include <corecrypto/ccdigest.h>
#include <sys/systm.h>

#define byte uint8_t
#define u32bit uint32_t

/**
* Load a little-endian word
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th T of in, as a litte-endian value
*/
/*template<typename T>
inline T load_le(const byte in[], size_t off)
*/
static u32bit load_le(const byte in[], size_t off)
{
    in += off * sizeof(u32bit);
    u32bit out = 0;
    for(size_t i = 0; i != sizeof(u32bit); ++i)
        out = (out << 8) | in[sizeof(u32bit)-1-i];
    return out;
}

/**
* Load a variable number of little-endian words
* @param out the output array of words
* @param in the input array of bytes
* @param count how many words are in in
*/
/*
template<typename T>
inline void load_le(T out[],
                    const byte in[],
                    size_t count)
*/
static inline void load_le(u32bit out[],
                           const byte in[],
                           size_t count)
{
    if(count > 0)
    {
        for(size_t i = 0; i != count; ++i)
            out[i] = load_le(in, i);
    }
}

/**
* Bit rotation left
* @param input the input word
* @param rot the number of bits to rotate
* @return input rotated left by rot bits
*/
/*
template<typename T> inline T rotate_left(T input, size_t rot)
*/
static inline u32bit rotate_left(u32bit input, size_t rot)
{
    if(rot == 0)
        return input;
    return static_cast<u32bit>((input << rot) | (input >> (8*sizeof(u32bit)-rot)));;
}

/*
* MD5 FF Function
*/
static inline void FF(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit msg,
                      byte S, u32bit magic)
{
    A += (D ^ (B & (C ^ D))) + msg + magic;
    A  = rotate_left(A, S) + B;
}

/*
* MD5 GG Function
*/
static inline void GG(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit msg,
                      byte S, u32bit magic)
{
    A += (C ^ (D & (B ^ C))) + msg + magic;
    A  = rotate_left(A, S) + B;
}

/*
* MD5 HH Function
*/
static inline void HH(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit msg,
                      byte S, u32bit magic)
{
    A += (B ^ C ^ D) + msg + magic;
    A  = rotate_left(A, S) + B;
}

/*
* MD5 II Function
*/
static inline void II(u32bit& A, u32bit B, u32bit C, u32bit D, u32bit msg,
                      byte S, u32bit magic)
{
    A += (C ^ (B | ~D)) + msg + magic;
    A  = rotate_left(A, S) + B;
}

extern "C"
{

void pdcmd5_compress(ccdigest_state_t s, unsigned long nblocks, const void *data)
{
    //printf("%s\n", __func__);
    
    const byte *input = (const byte *)data;

    uint32_t *state = ccdigest_u32(s);

    u32bit A = state[0], B = state[1], C = state[2], D = state[3];

    u32bit m_M[16];

    for(size_t i = 0; i != nblocks; ++i)
    {
        //load_le(m_M.data(), input, m_M.size());
        load_le(m_M, input, 16);

        FF(A,B,C,D,m_M[ 0], 7,0xD76AA478);   FF(D,A,B,C,m_M[ 1],12,0xE8C7B756);
        FF(C,D,A,B,m_M[ 2],17,0x242070DB);   FF(B,C,D,A,m_M[ 3],22,0xC1BDCEEE);
        FF(A,B,C,D,m_M[ 4], 7,0xF57C0FAF);   FF(D,A,B,C,m_M[ 5],12,0x4787C62A);
        FF(C,D,A,B,m_M[ 6],17,0xA8304613);   FF(B,C,D,A,m_M[ 7],22,0xFD469501);
        FF(A,B,C,D,m_M[ 8], 7,0x698098D8);   FF(D,A,B,C,m_M[ 9],12,0x8B44F7AF);
        FF(C,D,A,B,m_M[10],17,0xFFFF5BB1);   FF(B,C,D,A,m_M[11],22,0x895CD7BE);
        FF(A,B,C,D,m_M[12], 7,0x6B901122);   FF(D,A,B,C,m_M[13],12,0xFD987193);
        FF(C,D,A,B,m_M[14],17,0xA679438E);   FF(B,C,D,A,m_M[15],22,0x49B40821);

        GG(A,B,C,D,m_M[ 1], 5,0xF61E2562);   GG(D,A,B,C,m_M[ 6], 9,0xC040B340);
        GG(C,D,A,B,m_M[11],14,0x265E5A51);   GG(B,C,D,A,m_M[ 0],20,0xE9B6C7AA);
        GG(A,B,C,D,m_M[ 5], 5,0xD62F105D);   GG(D,A,B,C,m_M[10], 9,0x02441453);
        GG(C,D,A,B,m_M[15],14,0xD8A1E681);   GG(B,C,D,A,m_M[ 4],20,0xE7D3FBC8);
        GG(A,B,C,D,m_M[ 9], 5,0x21E1CDE6);   GG(D,A,B,C,m_M[14], 9,0xC33707D6);
        GG(C,D,A,B,m_M[ 3],14,0xF4D50D87);   GG(B,C,D,A,m_M[ 8],20,0x455A14ED);
        GG(A,B,C,D,m_M[13], 5,0xA9E3E905);   GG(D,A,B,C,m_M[ 2], 9,0xFCEFA3F8);
        GG(C,D,A,B,m_M[ 7],14,0x676F02D9);   GG(B,C,D,A,m_M[12],20,0x8D2A4C8A);

        HH(A,B,C,D,m_M[ 5], 4,0xFFFA3942);   HH(D,A,B,C,m_M[ 8],11,0x8771F681);
        HH(C,D,A,B,m_M[11],16,0x6D9D6122);   HH(B,C,D,A,m_M[14],23,0xFDE5380C);
        HH(A,B,C,D,m_M[ 1], 4,0xA4BEEA44);   HH(D,A,B,C,m_M[ 4],11,0x4BDECFA9);
        HH(C,D,A,B,m_M[ 7],16,0xF6BB4B60);   HH(B,C,D,A,m_M[10],23,0xBEBFBC70);
        HH(A,B,C,D,m_M[13], 4,0x289B7EC6);   HH(D,A,B,C,m_M[ 0],11,0xEAA127FA);
        HH(C,D,A,B,m_M[ 3],16,0xD4EF3085);   HH(B,C,D,A,m_M[ 6],23,0x04881D05);
        HH(A,B,C,D,m_M[ 9], 4,0xD9D4D039);   HH(D,A,B,C,m_M[12],11,0xE6DB99E5);
        HH(C,D,A,B,m_M[15],16,0x1FA27CF8);   HH(B,C,D,A,m_M[ 2],23,0xC4AC5665);

        II(A,B,C,D,m_M[ 0], 6,0xF4292244);   II(D,A,B,C,m_M[ 7],10,0x432AFF97);
        II(C,D,A,B,m_M[14],15,0xAB9423A7);   II(B,C,D,A,m_M[ 5],21,0xFC93A039);
        II(A,B,C,D,m_M[12], 6,0x655B59C3);   II(D,A,B,C,m_M[ 3],10,0x8F0CCC92);
        II(C,D,A,B,m_M[10],15,0xFFEFF47D);   II(B,C,D,A,m_M[ 1],21,0x85845DD1);
        II(A,B,C,D,m_M[ 8], 6,0x6FA87E4F);   II(D,A,B,C,m_M[15],10,0xFE2CE6E0);
        II(C,D,A,B,m_M[ 6],15,0xA3014314);   II(B,C,D,A,m_M[13],21,0x4E0811A1);
        II(A,B,C,D,m_M[ 4], 6,0xF7537E82);   II(D,A,B,C,m_M[11],10,0xBD3AF235);
        II(C,D,A,B,m_M[ 2],15,0x2AD7D2BB);   II(B,C,D,A,m_M[ 9],21,0xEB86D391);

        A = (state[0] += A);
        B = (state[1] += B);
        C = (state[2] += C);
        D = (state[3] += D);

        // input += hash_block_size();
        input += 64;

    }
}

} // extern
