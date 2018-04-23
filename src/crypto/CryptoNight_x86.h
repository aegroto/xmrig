/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2018      aegroto     <https://github.com/aegroto>
 * Copyright 2016-2018 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __CRYPTONIGHT_X86_H__
#define __CRYPTONIGHT_X86_H__


#ifdef __GNUC__
#   include <x86intrin.h>
#else
#   include <intrin.h>
#   define __restrict__ __restrict
#endif


#include "crypto/CryptoNight.h"
#include "crypto/CryptoNight_constants.h"
#include "crypto/CryptoNight_monero.h"
#include "crypto/soft_aes.h"


extern "C"
{
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
}


static inline void do_blake_hash(const uint8_t *input, size_t len, uint8_t *output) {
    blake256_hash(output, input, len);
}


static inline void do_groestl_hash(const uint8_t *input, size_t len, uint8_t *output) {
    groestl(input, len * 8, output);
}


static inline void do_jh_hash(const uint8_t *input, size_t len, uint8_t *output) {
    jh_hash(32 * 8, input, 8 * len, output);
}


static inline void do_skein_hash(const uint8_t *input, size_t len, uint8_t *output) {
    xmr_skein(input, output);
}


void (* const extra_hashes[4])(const uint8_t *, size_t, uint8_t *) = {do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};



#if defined(__x86_64__) || defined(_M_AMD64)
#   define EXTRACT64(X) _mm_cvtsi128_si64(X)

#   ifdef __GNUC__
static inline uint64_t __umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
    unsigned __int128 r = (unsigned __int128) a * (unsigned __int128) b;
    *hi = r >> 64;
    return (uint64_t) r;
}
#   else
    #define __umul128 _umul128
#   endif
#elif defined(__i386__) || defined(_M_IX86)
#   define HI32(X) \
    _mm_srli_si128((X), 4)


#   define EXTRACT64(X) \
    ((uint64_t)(uint32_t)_mm_cvtsi128_si32(X) | \
    ((uint64_t)(uint32_t)_mm_cvtsi128_si32(HI32(X)) << 32))

static inline uint64_t __umul128(uint64_t multiplier, uint64_t multiplicand, uint64_t *product_hi) {
    // multiplier   = ab = a * 2^32 + b
    // multiplicand = cd = c * 2^32 + d
    // ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
    uint64_t a = multiplier >> 32;
    uint64_t b = multiplier & 0xFFFFFFFF;
    uint64_t c = multiplicand >> 32;
    uint64_t d = multiplicand & 0xFFFFFFFF;

    //uint64_t ac = a * c;
    uint64_t ad = a * d;
    //uint64_t bc = b * c;
    uint64_t bd = b * d;

    uint64_t adbc = ad + (b * c);
    uint64_t adbc_carry = adbc < ad ? 1 : 0;

    // multiplier * multiplicand = product_hi * 2^64 + product_lo
    uint64_t product_lo = bd + (adbc << 32);
    uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
    *product_hi = (a * c) + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;

    return product_lo;
}
#endif

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
    __m128i tmp4;
    tmp4 = _mm_slli_si128(tmp1, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    return tmp1;
}


template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = _mm_aeskeygenassist_si128(*xout2, rcon);
    xout1  = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1  = _mm_aeskeygenassist_si128(*xout0, 0x00);
    xout1  = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}


template<uint8_t rcon>
static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = soft_aeskeygenassist<rcon>(*xout2);
    xout1  = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1  = soft_aeskeygenassist<0x00>(*xout0);
    xout1  = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}


template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3, __m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
    __m128i xout0 = _mm_load_si128(memory);
    __m128i xout2 = _mm_load_si128(memory + 1);
    *k0 = xout0;
    *k1 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x01>(&xout0, &xout2) : aes_genkey_sub<0x01>(&xout0, &xout2);
    *k2 = xout0;
    *k3 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x02>(&xout0, &xout2) : aes_genkey_sub<0x02>(&xout0, &xout2);
    *k4 = xout0;
    *k5 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x04>(&xout0, &xout2) : aes_genkey_sub<0x04>(&xout0, &xout2);
    *k6 = xout0;
    *k7 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x08>(&xout0, &xout2) : aes_genkey_sub<0x08>(&xout0, &xout2);
    *k8 = xout0;
    *k9 = xout2;
}


template<bool SOFT_AES>
static inline void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
    if (SOFT_AES) {
        *x0 = soft_aesenc((uint32_t*)x0, key);
        *x1 = soft_aesenc((uint32_t*)x1, key);
        *x2 = soft_aesenc((uint32_t*)x2, key);
        *x3 = soft_aesenc((uint32_t*)x3, key);
        *x4 = soft_aesenc((uint32_t*)x4, key);
        *x5 = soft_aesenc((uint32_t*)x5, key);
        *x6 = soft_aesenc((uint32_t*)x6, key);
        *x7 = soft_aesenc((uint32_t*)x7, key);
    }
    else {
        *x0 = _mm_aesenc_si128(*x0, key);
        *x1 = _mm_aesenc_si128(*x1, key);
        *x2 = _mm_aesenc_si128(*x2, key);
        *x3 = _mm_aesenc_si128(*x3, key);
        *x4 = _mm_aesenc_si128(*x4, key);
        *x5 = _mm_aesenc_si128(*x5, key);
        *x6 = _mm_aesenc_si128(*x6, key);
        *x7 = _mm_aesenc_si128(*x7, key);
    }
}


inline void mix_and_propagate(__m128i& x0, __m128i& x1, __m128i& x2, __m128i& x3, __m128i& x4, __m128i& x5, __m128i& x6, __m128i& x7)
{
    __m128i tmp0 = x0;
    x0 = _mm_xor_si128(x0, x1);
    x1 = _mm_xor_si128(x1, x2);
    x2 = _mm_xor_si128(x2, x3);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_xor_si128(x4, x5);
    x5 = _mm_xor_si128(x5, x6);
    x6 = _mm_xor_si128(x6, x7);
    x7 = _mm_xor_si128(x7, tmp0);
}


template<xmrig::Algo ALGO, size_t MEM, bool SOFT_AES>
static inline void cn_explode_scratchpad(const __m128i *input, __m128i *output)
{
    __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xin0 = _mm_load_si128(input + 4);
    xin1 = _mm_load_si128(input + 5);
    xin2 = _mm_load_si128(input + 6);
    xin3 = _mm_load_si128(input + 7);
    xin4 = _mm_load_si128(input + 8);
    xin5 = _mm_load_si128(input + 9);
    xin6 = _mm_load_si128(input + 10);
    xin7 = _mm_load_si128(input + 11);

    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
        for (size_t i = 0; i < 16; i++) {
            aes_round<SOFT_AES>(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

            mix_and_propagate(xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
        }
    }

    const __m128i *outputTmpLimit = output + (MEM / sizeof(__m128i));

    for (__m128i *outputTmp = output; outputTmp < outputTmpLimit; outputTmp += 8) {
        aes_round<SOFT_AES>(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

        _mm_store_si128(outputTmp,     xin0);
        _mm_store_si128(outputTmp + 1, xin1);
        _mm_store_si128(outputTmp + 2, xin2);
        _mm_store_si128(outputTmp + 3, xin3);
        _mm_store_si128(outputTmp + 4, xin4);
        _mm_store_si128(outputTmp + 5, xin5);
        _mm_store_si128(outputTmp + 6, xin6);
        _mm_store_si128(outputTmp + 7, xin7);
    }
}


template<xmrig::Algo ALGO, size_t MEM, bool SOFT_AES>
static inline void cn_implode_scratchpad(const __m128i *input, __m128i *output)
{
    __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xout0 = _mm_load_si128(output + 4);
    xout1 = _mm_load_si128(output + 5);
    xout2 = _mm_load_si128(output + 6);
    xout3 = _mm_load_si128(output + 7);
    xout4 = _mm_load_si128(output + 8);
    xout5 = _mm_load_si128(output + 9);
    xout6 = _mm_load_si128(output + 10);
    xout7 = _mm_load_si128(output + 11);

    const __m128i *inputTmpLimit = (__m128i*) input + MEM / sizeof(__m128i);

    for (__m128i *inputTmp = (__m128i*) input; inputTmp < inputTmpLimit; inputTmp += 8) {
        xout0 = _mm_xor_si128(_mm_load_si128(inputTmp), xout0);
        xout1 = _mm_xor_si128(_mm_load_si128(inputTmp + 1), xout1);
        xout2 = _mm_xor_si128(_mm_load_si128(inputTmp + 2), xout2);
        xout3 = _mm_xor_si128(_mm_load_si128(inputTmp + 3), xout3);
        xout4 = _mm_xor_si128(_mm_load_si128(inputTmp + 4), xout4);
        xout5 = _mm_xor_si128(_mm_load_si128(inputTmp + 5), xout5);
        xout6 = _mm_xor_si128(_mm_load_si128(inputTmp + 6), xout6);
        xout7 = _mm_xor_si128(_mm_load_si128(inputTmp + 7), xout7);

        aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
        for (__m128i *inputTmp = (__m128i*) input; inputTmp < inputTmpLimit; inputTmp += 8) {
            xout0 = _mm_xor_si128(_mm_load_si128(inputTmp), xout0);
            xout1 = _mm_xor_si128(_mm_load_si128(inputTmp + 1), xout1);
            xout2 = _mm_xor_si128(_mm_load_si128(inputTmp + 2), xout2);
            xout3 = _mm_xor_si128(_mm_load_si128(inputTmp + 3), xout3);
            xout4 = _mm_xor_si128(_mm_load_si128(inputTmp + 4), xout4);
            xout5 = _mm_xor_si128(_mm_load_si128(inputTmp + 5), xout5);
            xout6 = _mm_xor_si128(_mm_load_si128(inputTmp + 6), xout6);
            xout7 = _mm_xor_si128(_mm_load_si128(inputTmp + 7), xout7);

            aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }

        for (size_t i = 0; i < 16; i++) {
            aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    _mm_store_si128(output + 4, xout0);
    _mm_store_si128(output + 5, xout1);
    _mm_store_si128(output + 6, xout2);
    _mm_store_si128(output + 7, xout3);
    _mm_store_si128(output + 8, xout4);
    _mm_store_si128(output + 9, xout5);
    _mm_store_si128(output + 10, xout6);
    _mm_store_si128(output + 11, xout7);
}


static inline void cryptonight_monero_tweak(uint64_t* mem_out, __m128i tmp)
{
    mem_out[0] = EXTRACT64(tmp);

    tmp = _mm_castps_si128(_mm_movehl_ps(_mm_castsi128_ps(tmp), _mm_castsi128_ps(tmp)));
    uint64_t vh = EXTRACT64(tmp);

    uint8_t x = vh >> 24;
    static const uint16_t table = 0x7531;
    vh ^= ((table >> ((((x >> 3) & 6) | (x & 1)) << 1)) & 0x3) << 28;

    mem_out[1] = vh;
}


template<xmrig::Algo ALGO, bool SOFT_AES, int VARIANT>
inline void cryptonight_single_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();

    if (VARIANT > 0 && size < 43) {
        memset(output, 0, 32);
        return;
    }

    keccak(input, (int) size, ctx[0]->state, 200);

    VARIANT1_INIT(0)

    cn_explode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) ctx[0]->state, (__m128i*) ctx[0]->memory);

    const uint8_t* l0 = ctx[0]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);

    uint64_t idx0 = h0[0] ^ h0[4];
    void* mp = ((uint8_t*) l0) + ((idx0) & MASK);
    
    for (size_t i = 0; i < ITERATIONS; i++) {
        __m128i cx;

        if (SOFT_AES) {
            cx = soft_aesenc((uint32_t*) mp, _mm_set_epi64x(ah0, al0)); 
        } else {  
            cx = _mm_load_si128((__m128i *) mp);
            cx = _mm_aesenc_si128(cx, _mm_set_epi64x(ah0, al0));
        }

        _mm_store_si128((__m128i *) mp, _mm_xor_si128(bx0, cx));
        VARIANT1_1(mp);        
        mp = ((uint8_t*) l0) + ((idx0 = EXTRACT64(cx)) & MASK);        
        bx0 = cx;

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*) mp)[0];
        ch = ((uint64_t*) mp)[1];
        lo = __umul128(idx0, cl, &hi);

        al0 += hi;
        ah0 += lo;

        VARIANT1_2(ah0, 0);
        ((uint64_t*) mp)[0] = al0;
        ((uint64_t*) mp)[1] = ah0;
        VARIANT1_2(ah0, 0);

        ah0 ^= ch;
        al0 ^= cl;
        mp = ((uint8_t*) l0) + ((al0) & MASK); 

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            int64_t n  = ((int64_t*)mp)[0];
            int32_t d  = ((int32_t*)mp)[2];
            int64_t q = n / (d | 0x5);
            ((int64_t*) mp)[0] = n ^ q; 
        }
    }

    cn_implode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) ctx[0]->memory, (__m128i*) ctx[0]->state);

    keccakf(h0, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
}


template<xmrig::Algo ALGO, bool SOFT_AES, int VARIANT>
inline void cryptonight_double_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();

    if (VARIANT > 0 && size < 43) {
        memset(output, 0, 64);
        return;
    }

    keccak(input,        (int) size, ctx[0]->state, 200);
    keccak(input + size, (int) size, ctx[1]->state, 200);

    VARIANT1_INIT(0);
    VARIANT1_INIT(1);

    const uint8_t* l0 = ctx[0]->memory;
    const uint8_t* l1 = ctx[1]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);

    cn_explode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) h0, (__m128i*) l0);
    cn_explode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) h1, (__m128i*) l1);

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t al1 = h1[0] ^ h1[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    uint64_t ah1 = h1[1] ^ h1[5];

    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);

    uint64_t idx0 = al0;
    uint64_t idx1 = al1;

    void* mp0 = ((uint8_t*) l0) + ((idx0) & MASK);
    void* mp1 = ((uint8_t*) l1) + ((idx1) & MASK);

    for (size_t i = 0; i < ITERATIONS; i++) {
        __m128i cx0, cx1;

        if (SOFT_AES) {
            cx0 = soft_aesenc((uint32_t*) mp0, _mm_set_epi64x(ah0, al0));
            cx1 = soft_aesenc((uint32_t*) mp1, _mm_set_epi64x(ah1, al1));
        } else {
            cx0 = _mm_load_si128((__m128i *) mp0);
            cx1 = _mm_load_si128((__m128i *)mp1);
            cx0 = _mm_aesenc_si128(cx0, _mm_set_epi64x(ah0, al0));
            cx1 = _mm_aesenc_si128(cx1, _mm_set_epi64x(ah1, al1));
        }

        if (VARIANT > 0) {
            cryptonight_monero_tweak((uint64_t*)mp0, _mm_xor_si128(bx0, cx0));
            cryptonight_monero_tweak((uint64_t*)mp1, _mm_xor_si128(bx1, cx1));
        } else {
            _mm_store_si128((__m128i *) mp0, _mm_xor_si128(bx0, cx0));
            _mm_store_si128((__m128i *) mp1, _mm_xor_si128(bx1, cx1));
        }

        mp0 = ((uint8_t*) l0) + ((idx0 = EXTRACT64(cx0)) & MASK);
        mp1 = ((uint8_t*) l1) + ((idx1 = EXTRACT64(cx1)) & MASK);

        bx0 = cx0;
        bx1 = cx1;

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*) mp0)[0];
        ch = ((uint64_t*) mp0)[1];
        lo = __umul128(idx0, cl, &hi);

        al0 += hi;
        ah0 += lo;

        VARIANT1_2(ah0, 0);
        ((uint64_t*) mp0)[0] = al0;
        ((uint64_t*) mp0)[1] = ah0;
        VARIANT1_2(ah0, 0);

        ah0 ^= ch;
        al0 ^= cl;
        mp0 = ((uint8_t*) l0) + ((al0) & MASK);

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            int64_t n  = ((int64_t*)mp0)[0];
            int32_t d  = ((int32_t*)mp0)[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*) mp0)[0] = n ^ q;
        }

        cl = ((uint64_t*) mp1)[0];
        ch = ((uint64_t*) mp1)[1];
        lo = __umul128(idx1, cl, &hi);

        al1 += hi;
        ah1 += lo;

        VARIANT1_2(ah1, 1);
        ((uint64_t*) mp1)[0] = al1;
        ((uint64_t*) mp1)[1] = ah1;
        VARIANT1_2(ah1, 1);

        ah1 ^= ch;
        al1 ^= cl;
        mp1 = ((uint8_t*) l1) + ((al1) & MASK);

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            int64_t n  = ((int64_t*)mp1)[0];
            int32_t d  = ((int32_t*)mp1)[2];
            int64_t q = n / (d | 0x5);

            ((int64_t*)mp1)[0] = n ^ q;
        }
    }

    cn_implode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) l0, (__m128i*) h0);
    cn_implode_scratchpad<ALGO, MEM, SOFT_AES>((__m128i*) l1, (__m128i*) h1);

    keccakf(h0, 24);
    keccakf(h1, 24);

    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
    extra_hashes[ctx[1]->state[0] & 3](ctx[1]->state, 200, output + 32);
}


#define CN_STEP1(a, b, c, l, ptr, idx)                \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    c = _mm_load_si128(ptr);


#define CN_STEP2(a, b, c, l, ptr, idx)                                 \
    if (SOFT_AES) {                                                    \
        c = soft_aesenc(c, a);                                         \
    } else {                                                           \
        c = _mm_aesenc_si128(c, a);                                    \
    }                                                                  \
                                                                       \
    b = _mm_xor_si128(b, c);                                           \
                                                                       \
    if (VARIANT > 0) {                                                 \
        cryptonight_monero_tweak(reinterpret_cast<uint64_t*>(ptr), b); \
    } else {                                                           \
        _mm_store_si128(ptr, b);                                       \
    }


#define CN_STEP3(a, b, c, l, ptr, idx)                \
    idx = EXTRACT64(c);                               \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    b = _mm_load_si128(ptr);


#define CN_STEP4(a, b, c, l, mc, ptr, idx)              \
    lo = __umul128(idx, EXTRACT64(b), &hi);             \
    a = _mm_add_epi64(a, _mm_set_epi64x(lo, hi));       \
                                                        \
    if (VARIANT > 0) {                                  \
        _mm_store_si128(ptr, _mm_xor_si128(a, mc));     \
    } else {                                            \
        _mm_store_si128(ptr, a);                        \
    }                                                   \
                                                        \
    a = _mm_xor_si128(a, b);                            \
    idx = EXTRACT64(a);                                 \
                                                        \
    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {             \
        int64_t n = ((int64_t*)&l[idx & MASK])[0];      \
        int32_t d = ((int32_t*)&l[idx & MASK])[2];      \
        int64_t q = n / (d | 0x5);                      \
        ((int64_t*)&l[idx & MASK])[0] = n ^ q;          \
        idx = d ^ q;                                    \
    }


#define CONST_INIT(ctx, n)                                                                       \
    __m128i mc##n;                                                                               \
    if (VARIANT > 0) {                                                                           \
        mc##n = _mm_set_epi64x(*reinterpret_cast<const uint64_t*>(input + n * size + 35) ^       \
                               *(reinterpret_cast<const uint64_t*>((ctx)->state) + 24), 0);      \
    }


template<xmrig::Algo ALGO, bool SOFT_AES, int VARIANT>
inline void cryptonight_triple_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();

    if (VARIANT > 0 && size < 43) {
        memset(output, 0, 32 * 3);
        return;
    }

    for (size_t i = 0; i < 3; i++) {
        keccak(input + size * i, static_cast<int>(size), ctx[i]->state, 200);
        cn_explode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);

    __m128i ax0 = _mm_set_epi64x(h0[1] ^ h0[5], h0[0] ^ h0[4]);
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i ax1 = _mm_set_epi64x(h1[1] ^ h1[5], h1[0] ^ h1[4]);
    __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
    __m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
    __m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
    __m128i cx0 = _mm_set_epi64x(0, 0);
    __m128i cx1 = _mm_set_epi64x(0, 0);
    __m128i cx2 = _mm_set_epi64x(0, 0);

    uint64_t idx0, idx1, idx2;
    idx0 = EXTRACT64(ax0);
    idx1 = EXTRACT64(ax1);
    idx2 = EXTRACT64(ax2);

    for (size_t i = 0; i < ITERATIONS / 2; i++) {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2;

        // EVEN ROUND
        CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);

        CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);

        CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);

        CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);

        // ODD ROUND
        CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);

        CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);

        CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);

        CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
    }

    for (size_t i = 0; i < 3; i++) {
        cn_implode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}


template<xmrig::Algo ALGO, bool SOFT_AES, int VARIANT>
inline void cryptonight_quad_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();

    if (VARIANT > 0 && size < 43) {
        memset(output, 0, 32 * 4);
        return;
    }

    for (size_t i = 0; i < 4; i++) {
        keccak(input + size * i, static_cast<int>(size), ctx[i]->state, 200);
        cn_explode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    CONST_INIT(ctx[3], 3);

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint8_t* l3  = ctx[3]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);

    __m128i ax0 = _mm_set_epi64x(h0[1] ^ h0[5], h0[0] ^ h0[4]);
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i ax1 = _mm_set_epi64x(h1[1] ^ h1[5], h1[0] ^ h1[4]);
    __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
    __m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
    __m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
    __m128i ax3 = _mm_set_epi64x(h3[1] ^ h3[5], h3[0] ^ h3[4]);
    __m128i bx3 = _mm_set_epi64x(h3[3] ^ h3[7], h3[2] ^ h3[6]);
    __m128i cx0 = _mm_set_epi64x(0, 0);
    __m128i cx1 = _mm_set_epi64x(0, 0);
    __m128i cx2 = _mm_set_epi64x(0, 0);
    __m128i cx3 = _mm_set_epi64x(0, 0);

    uint64_t idx0, idx1, idx2, idx3;
    idx0 = EXTRACT64(ax0);
    idx1 = EXTRACT64(ax1);
    idx2 = EXTRACT64(ax2);
    idx3 = EXTRACT64(ax3);

    for (size_t i = 0; i < ITERATIONS / 2; i++)
    {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2, *ptr3;

        // EVEN ROUND
        CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP1(ax3, bx3, cx3, l3, ptr3, idx3);

        CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP2(ax3, bx3, cx3, l3, ptr3, idx3);

        CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP3(ax3, bx3, cx3, l3, ptr3, idx3);

        CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);
        CN_STEP4(ax3, bx3, cx3, l3, mc3, ptr3, idx3);

        // ODD ROUND
        CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP1(ax3, cx3, bx3, l3, ptr3, idx3);

        CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP2(ax3, cx3, bx3, l3, ptr3, idx3);

        CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP3(ax3, cx3, bx3, l3, ptr3, idx3);

        CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
        CN_STEP4(ax3, cx3, bx3, l3, mc3, ptr3, idx3);
    }

    for (size_t i = 0; i < 4; i++) {
        cn_implode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}


template<xmrig::Algo ALGO, bool SOFT_AES, int VARIANT>
inline void cryptonight_penta_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    
    if (VARIANT > 0 && size < 43) {
        memset(output, 0, 32 * 5);
        return;
    }

    for (size_t i = 0; i < 5; i++) {
        keccak(input + size * i, static_cast<int>(size), ctx[i]->state, 200);
        cn_explode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    CONST_INIT(ctx[3], 3);
    CONST_INIT(ctx[4], 4);

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint8_t* l3  = ctx[3]->memory;
    uint8_t* l4  = ctx[4]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);
    uint64_t* h4 = reinterpret_cast<uint64_t*>(ctx[4]->state);

    __m128i ax0 = _mm_set_epi64x(h0[1] ^ h0[5], h0[0] ^ h0[4]);
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i ax1 = _mm_set_epi64x(h1[1] ^ h1[5], h1[0] ^ h1[4]);
    __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
    __m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
    __m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
    __m128i ax3 = _mm_set_epi64x(h3[1] ^ h3[5], h3[0] ^ h3[4]);
    __m128i bx3 = _mm_set_epi64x(h3[3] ^ h3[7], h3[2] ^ h3[6]);
    __m128i ax4 = _mm_set_epi64x(h4[1] ^ h4[5], h4[0] ^ h4[4]);
    __m128i bx4 = _mm_set_epi64x(h4[3] ^ h4[7], h4[2] ^ h4[6]);
    __m128i cx0 = _mm_set_epi64x(0, 0);
    __m128i cx1 = _mm_set_epi64x(0, 0);
    __m128i cx2 = _mm_set_epi64x(0, 0);
    __m128i cx3 = _mm_set_epi64x(0, 0);
    __m128i cx4 = _mm_set_epi64x(0, 0);

    uint64_t idx0, idx1, idx2, idx3, idx4;
    idx0 = EXTRACT64(ax0);
    idx1 = EXTRACT64(ax1);
    idx2 = EXTRACT64(ax2);
    idx3 = EXTRACT64(ax3);
    idx4 = EXTRACT64(ax4);

    for (size_t i = 0; i < ITERATIONS / 2; i++)
    {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2, *ptr3, *ptr4;

        // EVEN ROUND
        CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP1(ax3, bx3, cx3, l3, ptr3, idx3);
        CN_STEP1(ax4, bx4, cx4, l4, ptr4, idx4);

        CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP2(ax3, bx3, cx3, l3, ptr3, idx3);
        CN_STEP2(ax4, bx4, cx4, l4, ptr4, idx4);

        CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP3(ax3, bx3, cx3, l3, ptr3, idx3);
        CN_STEP3(ax4, bx4, cx4, l4, ptr4, idx4);

        CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);
        CN_STEP4(ax3, bx3, cx3, l3, mc3, ptr3, idx3);
        CN_STEP4(ax4, bx4, cx4, l4, mc4, ptr4, idx4);

        // ODD ROUND
        CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP1(ax3, cx3, bx3, l3, ptr3, idx3);
        CN_STEP1(ax4, cx4, bx4, l4, ptr4, idx4);

        CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP2(ax3, cx3, bx3, l3, ptr3, idx3);
        CN_STEP2(ax4, cx4, bx4, l4, ptr4, idx4);

        CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP3(ax3, cx3, bx3, l3, ptr3, idx3);
        CN_STEP3(ax4, cx4, bx4, l4, ptr4, idx4);

        CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
        CN_STEP4(ax3, cx3, bx3, l3, mc3, ptr3, idx3);
        CN_STEP4(ax4, cx4, bx4, l4, mc4, ptr4, idx4);
    }

    for (size_t i = 0; i < 5; i++) {
        cn_implode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}

template<xmrig::Algo ALGO, bool SOFT_AES, int VARIANT>
inline void cryptonight_decapenta_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MASK       = xmrig::cn_select_mask<ALGO>();
    constexpr size_t ITERATIONS = xmrig::cn_select_iter<ALGO>();
    constexpr size_t MEM        = xmrig::cn_select_memory<ALGO>();
    // printf("decapenta hash %d %d %d\n", ALGO, SOFT_AES, VARIANT);
    if (VARIANT > 0 && size < 43) {
        memset(output, 0, 32 * 15);
        return;
    }
    
    for (size_t i = 0; i < 15; i++) {
        keccak(input + size * i, static_cast<int>(size), ctx[i]->state, 200);
        cn_explode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    CONST_INIT(ctx[3], 3);
    CONST_INIT(ctx[4], 4);
    CONST_INIT(ctx[5], 5);
    CONST_INIT(ctx[6], 6);
    CONST_INIT(ctx[7], 7);
    CONST_INIT(ctx[8], 8);
    CONST_INIT(ctx[9], 9);
    CONST_INIT(ctx[10], 10);
    CONST_INIT(ctx[11], 11);
    CONST_INIT(ctx[12], 12);
    CONST_INIT(ctx[13], 13);
    CONST_INIT(ctx[14], 14);

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint8_t* l3  = ctx[3]->memory;
    uint8_t* l4  = ctx[4]->memory;
    uint8_t* l5  = ctx[5]->memory;
    uint8_t* l6  = ctx[6]->memory;
    uint8_t* l7  = ctx[7]->memory;
    uint8_t* l8  = ctx[8]->memory;
    uint8_t* l9  = ctx[9]->memory;
    uint8_t* l10  = ctx[10]->memory;
    uint8_t* l11  = ctx[11]->memory;
    uint8_t* l12  = ctx[12]->memory;
    uint8_t* l13  = ctx[13]->memory;
    uint8_t* l14  = ctx[14]->memory;

    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);
    uint64_t* h4 = reinterpret_cast<uint64_t*>(ctx[4]->state);
    uint64_t* h5 = reinterpret_cast<uint64_t*>(ctx[5]->state);
    uint64_t* h6 = reinterpret_cast<uint64_t*>(ctx[6]->state);
    uint64_t* h7 = reinterpret_cast<uint64_t*>(ctx[7]->state);
    uint64_t* h8 = reinterpret_cast<uint64_t*>(ctx[8]->state);
    uint64_t* h9 = reinterpret_cast<uint64_t*>(ctx[9]->state);
    uint64_t* h10 = reinterpret_cast<uint64_t*>(ctx[10]->state);
    uint64_t* h11 = reinterpret_cast<uint64_t*>(ctx[11]->state);
    uint64_t* h12 = reinterpret_cast<uint64_t*>(ctx[12]->state);
    uint64_t* h13 = reinterpret_cast<uint64_t*>(ctx[13]->state);
    uint64_t* h14 = reinterpret_cast<uint64_t*>(ctx[14]->state);

    __m128i ax0 = _mm_set_epi64x(h0[1] ^ h0[5], h0[0] ^ h0[4]);
    __m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);

    __m128i ax1 = _mm_set_epi64x(h1[1] ^ h1[5], h1[0] ^ h1[4]);
    __m128i bx1 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
    
    __m128i ax2 = _mm_set_epi64x(h2[1] ^ h2[5], h2[0] ^ h2[4]);
    __m128i bx2 = _mm_set_epi64x(h2[3] ^ h2[7], h2[2] ^ h2[6]);
    
    __m128i ax3 = _mm_set_epi64x(h3[1] ^ h3[5], h3[0] ^ h3[4]);
    __m128i bx3 = _mm_set_epi64x(h3[3] ^ h3[7], h3[2] ^ h3[6]);
    
    __m128i ax4 = _mm_set_epi64x(h4[1] ^ h4[5], h4[0] ^ h4[4]);
    __m128i bx4 = _mm_set_epi64x(h4[3] ^ h4[7], h4[2] ^ h4[6]);

    __m128i ax5 = _mm_set_epi64x(h5[1] ^ h5[5], h5[0] ^ h5[4]);
    __m128i bx5 = _mm_set_epi64x(h5[3] ^ h5[7], h5[2] ^ h5[6]);

    __m128i ax6 = _mm_set_epi64x(h6[1] ^ h6[5], h6[0] ^ h6[4]);
    __m128i bx6 = _mm_set_epi64x(h6[3] ^ h6[7], h6[2] ^ h6[6]);

    __m128i ax7 = _mm_set_epi64x(h7[1] ^ h7[5], h7[0] ^ h7[4]);
    __m128i bx7 = _mm_set_epi64x(h7[3] ^ h7[7], h7[2] ^ h7[6]);

    __m128i ax8 = _mm_set_epi64x(h8[1] ^ h8[5], h8[0] ^ h8[4]);
    __m128i bx8 = _mm_set_epi64x(h8[3] ^ h8[7], h8[2] ^ h8[6]);

    __m128i ax9 = _mm_set_epi64x(h9[1] ^ h9[5], h9[0] ^ h9[4]);
    __m128i bx9 = _mm_set_epi64x(h9[3] ^ h9[7], h9[2] ^ h9[6]);

    __m128i ax10 = _mm_set_epi64x(h10[1] ^ h10[5], h10[0] ^ h10[4]);
    __m128i bx10 = _mm_set_epi64x(h10[3] ^ h10[7], h10[2] ^ h10[6]);

    __m128i ax11 = _mm_set_epi64x(h11[1] ^ h11[5], h11[0] ^ h11[4]);
    __m128i bx11 = _mm_set_epi64x(h11[3] ^ h11[7], h11[2] ^ h11[6]);

    __m128i ax12 = _mm_set_epi64x(h12[1] ^ h12[5], h12[0] ^ h12[4]);
    __m128i bx12 = _mm_set_epi64x(h12[3] ^ h12[7], h12[2] ^ h12[6]);

    __m128i ax13 = _mm_set_epi64x(h13[1] ^ h13[5], h13[0] ^ h13[4]);
    __m128i bx13 = _mm_set_epi64x(h13[3] ^ h13[7], h13[2] ^ h13[6]);

    __m128i ax14 = _mm_set_epi64x(h14[1] ^ h14[5], h14[0] ^ h14[4]);
    __m128i bx14 = _mm_set_epi64x(h14[3] ^ h14[7], h14[2] ^ h14[6]);

    __m128i cx0 = _mm_set_epi64x(0, 0);
    __m128i cx1 = _mm_set_epi64x(0, 0);
    __m128i cx2 = _mm_set_epi64x(0, 0);
    __m128i cx3 = _mm_set_epi64x(0, 0);
    __m128i cx4 = _mm_set_epi64x(0, 0);
    __m128i cx5 = _mm_set_epi64x(0, 0);
    __m128i cx6 = _mm_set_epi64x(0, 0);
    __m128i cx7 = _mm_set_epi64x(0, 0);
    __m128i cx8 = _mm_set_epi64x(0, 0);
    __m128i cx9 = _mm_set_epi64x(0, 0);
    __m128i cx10 = _mm_set_epi64x(0, 0);
    __m128i cx11 = _mm_set_epi64x(0, 0);
    __m128i cx12 = _mm_set_epi64x(0, 0);
    __m128i cx13 = _mm_set_epi64x(0, 0);
    __m128i cx14 = _mm_set_epi64x(0, 0);

    uint64_t idx0, idx1, idx2, idx3, idx4, idx5, idx6, idx7, idx8, idx9, idx10, idx11, idx12, idx13, idx14;
    idx0 = EXTRACT64(ax0);
    idx1 = EXTRACT64(ax1);
    idx2 = EXTRACT64(ax2);
    idx3 = EXTRACT64(ax3);
    idx4 = EXTRACT64(ax4);
    idx5 = EXTRACT64(ax5);
    idx6 = EXTRACT64(ax6);
    idx7 = EXTRACT64(ax7);
    idx8 = EXTRACT64(ax8);
    idx9 = EXTRACT64(ax9);
    idx10 = EXTRACT64(ax10);
    idx11 = EXTRACT64(ax11);
    idx12 = EXTRACT64(ax12);
    idx13 = EXTRACT64(ax13);
    idx14 = EXTRACT64(ax14);

for (size_t i = 0; i < ITERATIONS / 2; i++)
    {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2, *ptr3, *ptr4, *ptr5, *ptr6, *ptr7, *ptr8, *ptr9, *ptr10, *ptr11, *ptr12, *ptr13, *ptr14;

        // EVEN ROUND
        CN_STEP1(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP1(ax3, bx3, cx3, l3, ptr3, idx3);
        CN_STEP1(ax4, bx4, cx4, l4, ptr4, idx4);
        CN_STEP1(ax5, bx5, cx5, l5, ptr5, idx5);
        CN_STEP1(ax6, bx6, cx6, l6, ptr6, idx6);
        CN_STEP1(ax7, bx7, cx7, l7, ptr7, idx7);
        CN_STEP1(ax8, bx8, cx8, l8, ptr8, idx8);
        CN_STEP1(ax9, bx9, cx9, l9, ptr9, idx9);
        CN_STEP1(ax10, bx10, cx10, l10, ptr10, idx10);
        CN_STEP1(ax11, bx11, cx11, l11, ptr11, idx11);
        CN_STEP1(ax12, bx12, cx12, l12, ptr12, idx12);
        CN_STEP1(ax13, bx13, cx13, l13, ptr13, idx13);
        CN_STEP1(ax14, bx14, cx14, l14, ptr14, idx14);

        CN_STEP2(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP2(ax3, bx3, cx3, l3, ptr3, idx3);
        CN_STEP2(ax4, bx4, cx4, l4, ptr4, idx4);
        CN_STEP2(ax5, bx5, cx5, l5, ptr5, idx5);
        CN_STEP2(ax6, bx6, cx6, l6, ptr6, idx6);
        CN_STEP2(ax7, bx7, cx7, l7, ptr7, idx7);
        CN_STEP2(ax8, bx8, cx8, l8, ptr8, idx8);
        CN_STEP2(ax9, bx9, cx9, l9, ptr9, idx9);
        CN_STEP2(ax10, bx10, cx10, l10, ptr10, idx10);
        CN_STEP2(ax11, bx11, cx11, l11, ptr11, idx11);
        CN_STEP2(ax12, bx12, cx12, l12, ptr12, idx12);
        CN_STEP2(ax13, bx13, cx13, l13, ptr13, idx13);
        CN_STEP2(ax14, bx14, cx14, l14, ptr14, idx14);

        CN_STEP3(ax0, bx0, cx0, l0, ptr0, idx0);
        CN_STEP3(ax1, bx1, cx1, l1, ptr1, idx1);
        CN_STEP3(ax2, bx2, cx2, l2, ptr2, idx2);
        CN_STEP3(ax3, bx3, cx3, l3, ptr3, idx3);
        CN_STEP3(ax4, bx4, cx4, l4, ptr4, idx4);
        CN_STEP3(ax5, bx5, cx5, l5, ptr5, idx5);
        CN_STEP3(ax6, bx6, cx6, l6, ptr6, idx6);
        CN_STEP3(ax7, bx7, cx7, l7, ptr7, idx7);
        CN_STEP3(ax8, bx8, cx8, l8, ptr8, idx8);
        CN_STEP3(ax9, bx9, cx9, l9, ptr9, idx9);
        CN_STEP3(ax10, bx10, cx10, l10, ptr10, idx10);
        CN_STEP3(ax11, bx11, cx11, l11, ptr11, idx11);
        CN_STEP3(ax12, bx12, cx12, l12, ptr12, idx12);
        CN_STEP3(ax13, bx13, cx13, l13, ptr13, idx13);
        CN_STEP3(ax14, bx14, cx14, l14, ptr14, idx14);

        CN_STEP4(ax0, bx0, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, bx1, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, bx2, cx2, l2, mc2, ptr2, idx2);
        CN_STEP4(ax3, bx3, cx3, l3, mc3, ptr3, idx3);
        CN_STEP4(ax4, bx4, cx4, l4, mc4, ptr4, idx4);
        CN_STEP4(ax5, bx5, cx5, l5, mc5, ptr5, idx5);
        CN_STEP4(ax6, bx6, cx6, l6, mc6, ptr6, idx6);
        CN_STEP4(ax7, bx7, cx7, l7, mc7, ptr7, idx7);
        CN_STEP4(ax8, bx8, cx8, l8, mc8, ptr8, idx8);
        CN_STEP4(ax9, bx9, cx9, l9, mc9, ptr9, idx9);
        CN_STEP4(ax10, bx10, cx10, l10, mc10, ptr10, idx10);
        CN_STEP4(ax11, bx11, cx11, l11, mc11, ptr11, idx11);
        CN_STEP4(ax12, bx12, cx12, l12, mc12, ptr12, idx12);
        CN_STEP4(ax13, bx13, cx13, l13, mc13, ptr13, idx13);
        CN_STEP4(ax14, bx14, cx14, l14, mc14, ptr14, idx14);

        // ODD ROUND
        CN_STEP1(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP1(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP1(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP1(ax3, cx3, bx3, l3, ptr3, idx3);
        CN_STEP1(ax4, cx4, bx4, l4, ptr4, idx4);
        CN_STEP1(ax5, cx5, bx5, l5, ptr5, idx5);
        CN_STEP1(ax6, cx6, bx6, l6, ptr6, idx6);
        CN_STEP1(ax7, cx7, bx7, l7, ptr7, idx7);
        CN_STEP1(ax8, cx8, bx8, l8, ptr8, idx8);
        CN_STEP1(ax9, cx9, bx9, l9, ptr9, idx9);
        CN_STEP1(ax10, cx10, bx10, l10, ptr10, idx10);
        CN_STEP1(ax11, cx11, bx11, l11, ptr11, idx11);
        CN_STEP1(ax12, cx12, bx12, l12, ptr12, idx12);
        CN_STEP1(ax13, cx13, bx13, l13, ptr13, idx13);
        CN_STEP1(ax14, cx14, bx14, l14, ptr14, idx14);

        CN_STEP2(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP2(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP2(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP2(ax3, cx3, bx3, l3, ptr3, idx3);
        CN_STEP2(ax4, cx4, bx4, l4, ptr4, idx4);
        CN_STEP2(ax5, cx5, bx5, l5, ptr5, idx5);
        CN_STEP2(ax6, cx6, bx6, l6, ptr6, idx6);
        CN_STEP2(ax7, cx7, bx7, l7, ptr7, idx7);
        CN_STEP2(ax8, cx8, bx8, l8, ptr8, idx8);
        CN_STEP2(ax9, cx9, bx9, l9, ptr9, idx9);
        CN_STEP2(ax10, cx10, bx10, l10, ptr10, idx10);
        CN_STEP2(ax11, cx11, bx11, l11, ptr11, idx11);
        CN_STEP2(ax12, cx12, bx12, l12, ptr12, idx12);
        CN_STEP2(ax13, cx13, bx13, l13, ptr13, idx13);
        CN_STEP2(ax14, cx14, bx14, l14, ptr14, idx14);

        CN_STEP3(ax0, cx0, bx0, l0, ptr0, idx0);
        CN_STEP3(ax1, cx1, bx1, l1, ptr1, idx1);
        CN_STEP3(ax2, cx2, bx2, l2, ptr2, idx2);
        CN_STEP3(ax3, cx3, bx3, l3, ptr3, idx3);
        CN_STEP3(ax4, cx4, bx4, l4, ptr4, idx4);
        CN_STEP3(ax5, cx5, bx5, l5, ptr5, idx5);
        CN_STEP3(ax6, cx6, bx6, l6, ptr6, idx6);
        CN_STEP3(ax7, cx7, bx7, l7, ptr7, idx7);
        CN_STEP3(ax8, cx8, bx8, l8, ptr8, idx8);
        CN_STEP3(ax9, cx9, bx9, l9, ptr9, idx9);
        CN_STEP3(ax10, cx10, bx10, l10, ptr10, idx10);
        CN_STEP3(ax11, cx11, bx11, l11, ptr11, idx11);
        CN_STEP3(ax12, cx12, bx12, l12, ptr12, idx12);
        CN_STEP3(ax13, cx13, bx13, l13, ptr13, idx13);
        CN_STEP3(ax14, cx14, bx14, l14, ptr14, idx14);

        CN_STEP4(ax0, cx0, bx0, l0, mc0, ptr0, idx0);
        CN_STEP4(ax1, cx1, bx1, l1, mc1, ptr1, idx1);
        CN_STEP4(ax2, cx2, bx2, l2, mc2, ptr2, idx2);
        CN_STEP4(ax3, cx3, bx3, l3, mc3, ptr3, idx3);
        CN_STEP4(ax4, cx4, bx4, l4, mc4, ptr4, idx4);
        CN_STEP4(ax5, cx5, bx5, l5, mc5, ptr5, idx5);
        CN_STEP4(ax6, cx6, bx6, l6, mc6, ptr6, idx6);
        CN_STEP4(ax7, cx7, bx7, l7, mc7, ptr7, idx7);
        CN_STEP4(ax8, cx8, bx8, l8, mc8, ptr8, idx8);
        CN_STEP4(ax9, cx9, bx9, l9, mc9, ptr9, idx9);
        CN_STEP4(ax10, cx10, bx10, l10, mc10, ptr10, idx10);
        CN_STEP4(ax11, cx11, bx11, l11, mc11, ptr11, idx11);
        CN_STEP4(ax12, cx12, bx12, l12, mc12, ptr12, idx12);
        CN_STEP4(ax13, cx13, bx13, l13, mc13, ptr13, idx13);
        CN_STEP4(ax14, cx14, bx14, l14, mc14, ptr14, idx14);
    }

    for (size_t i = 0; i < 15; i++) {
        cn_implode_scratchpad<ALGO, MEM, SOFT_AES>(reinterpret_cast<__m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}

#endif /* __CRYPTONIGHT_X86_H__ */
