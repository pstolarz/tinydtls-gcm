/* dtls -- a very basic DTLS implementation
 *
 * Copyright (C) 2011--2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 *  Galois/Counter Mode for 128-bit block ciphers
 *
 *  This implementation bases on mbed TLS project (https://tls.mbed.org)
 *  licensed under Apache License, Version 2.0:
 *    http://www.apache.org/licenses/LICENSE-2.0
 */

#include <string.h>
#include "debug.h"
#include "gcm.h"

/*
 * 32-bit integer manipulation macros (big endian)
 */
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}

#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}

/* Precompute small multiples of H, that is set
     HH[i] || HL[i] = H times i,
   where i is seen as a field element as in [MGV], ie high-order bits
   correspond to low powers of P. The result is stored in the same way, that
   is the high-order bit of HH corresponds to P^0 and the low-order bit of HL
   corresponds to P^127.
 */
static void gcm_gen_table(gcm_ctx_t *ctx)
{
    int i, j;
    uint64_t hi, lo;
    uint64_t vl, vh;
    unsigned char h[16];

    memset(h, 0, sizeof(h));
    rijndael_encrypt(&ctx->aes, h, h);

    /* pack h as two 64-bits ints, big-endian */
    GET_UINT32_BE(hi, h, 0);
    GET_UINT32_BE(lo, h, 4);
    vh = (uint64_t)hi << 32 | lo;

    GET_UINT32_BE(hi, h,  8);
    GET_UINT32_BE(lo, h,  12);
    vl = (uint64_t)hi << 32 | lo;

    /* 8 = 1000 corresponds to 1 in GF(2^128) */
    ctx->HL[8] = vl;
    ctx->HH[8] = vh;

    /* 0 corresponds to 0 in GF(2^128) */
    ctx->HH[0] = 0;
    ctx->HL[0] = 0;

    for (i=4; i>0; i>>=1) {
        uint32_t T = (vl & 1)*0xe1000000U;
        vl  = (vh << 63) | (vl >> 1);
        vh  = (vh >> 1) ^ ((uint64_t)T << 32);

        ctx->HL[i] = vl;
        ctx->HH[i] = vh;
    }

    for (i=2; i<=8; i*=2) {
        uint64_t *HiL=ctx->HL+i, *HiH=ctx->HH+i;
        vh = *HiH;
        vl = *HiL;
        for(j=1; j<i; j++) {
            HiH[j] = vh ^ ctx->HH[j];
            HiL[j] = vl ^ ctx->HL[j];
        }
    }
}

/* Shoup's method for multiplication use this table with
    last4[x] = x times P^128
   where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
 */
static const uint64_t last4[16] =
{
    0x0000, 0x1c20, 0x3840, 0x2460,
    0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560,
    0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

/* Sets out to x times H using the precomputed tables.
   x and out are seen as elements of GF(2^128) as in [MGV].
 */
static void gcm_mult(
    gcm_ctx_t *ctx, const unsigned char x[16], unsigned char out[16])
{
    int i=0;
    unsigned char lo, hi, rem;
    uint64_t zh, zl;

    lo = x[15] & 0xf;

    zh = ctx->HH[lo];
    zl = ctx->HL[lo];

    for (i=15; i>=0; i--)
    {
        lo = x[i] & 0xf;
        hi = x[i] >> 4;

        if (i != 15)
        {
            rem = (unsigned char)zl & 0xf;
            zl = (zh << 60) | (zl >> 4);
            zh = (zh >> 4);
            zh ^= (uint64_t)last4[rem] << 48;
            zh ^= ctx->HH[lo];
            zl ^= ctx->HL[lo];

        }

        rem = (unsigned char)zl & 0xf;
        zl = (zh << 60) | (zl >> 4);
        zh = (zh >> 4);
        zh ^= (uint64_t)last4[rem] << 48;
        zh ^= ctx->HH[hi];
        zl ^= ctx->HL[hi];
    }

    PUT_UINT32_BE(zh >> 32, out, 0);
    PUT_UINT32_BE(zh, out, 4);
    PUT_UINT32_BE(zl >> 32, out, 8);
    PUT_UINT32_BE(zl, out, 12);
}

int gcm_starts(gcm_ctx_t *ctx, int mode, const unsigned char *iv,
    size_t iv_len, const unsigned char *add, size_t add_len)
{
    unsigned char work_buf[16];
    size_t i;
    const unsigned char *p;
    size_t use_len;

    /* IV and AD are limited to 2^64 bits, so 2^61 bytes */
    if(((uint64_t)iv_len)>>61 != 0 || ((uint64_t)add_len)>>61 != 0)
        return -1;

    memset(ctx->y, 0x00, sizeof(ctx->y));
    memset(ctx->buf, 0x00, sizeof(ctx->buf));

    ctx->mode = mode;
    ctx->len = 0;
    ctx->add_len = 0;

    if (iv_len == 12) {
        memcpy(ctx->y, iv, iv_len);
        ctx->y[15] = 1;
    } else {
        memset(work_buf, 0x00, 16);
        PUT_UINT32_BE(iv_len * 8, work_buf, 12);

        p = iv;
        while (iv_len > 0)
        {
            use_len = (iv_len < 16) ? iv_len : 16;

            for (i=0; i<use_len; i++) ctx->y[i] ^= p[i];

            gcm_mult(ctx, ctx->y, ctx->y);

            iv_len -= use_len;
            p += use_len;
        }

        for (i=0; i<16; i++) ctx->y[i] ^= work_buf[i];

        gcm_mult(ctx, ctx->y, ctx->y);
    }

    rijndael_encrypt(&ctx->aes, ctx->y, ctx->base_ectr);

    ctx->add_len = add_len;
    p = add;
    while (add_len > 0) {
        use_len = (add_len < 16) ? add_len : 16;

        for (i=0; i<use_len; i++) ctx->buf[i]^=p[i];

        gcm_mult(ctx, ctx->buf, ctx->buf);

        add_len -= use_len;
        p += use_len;
    }

    return 0;
}

int gcm_update(
    gcm_ctx_t *ctx, size_t length, const unsigned char *in, unsigned char *out)
{
    unsigned char ectr[16];
    size_t i;
    const unsigned char *p;
    unsigned char *out_p=out;
    size_t use_len;

    if (out>in && (size_t)(out-in) < length) return -1;

    /* Total length is restricted to 2^39 - 256 bits, ie 2^36 - 2^5 bytes
     * Also check for possible overflow */
    if (ctx->len+length < ctx->len || (uint64_t)ctx->len+length > 0x03FFFFE0ull)
        return -1;

    ctx->len += length;

    p = in;
    while (length > 0)
    {
        use_len = (length<16) ? length : 16;

        for (i=16; i>12; i--) if (++ctx->y[i-1] != 0) break;

        rijndael_encrypt(&ctx->aes, ctx->y, ectr);

        for (i=0; i<use_len; i++) {
            if(ctx->mode == GCM_DECRYPT) ctx->buf[i]^=p[i];
            out_p[i] = ectr[i]^p[i];
            if(ctx->mode == GCM_ENCRYPT) ctx->buf[i]^=out_p[i];
        }

        gcm_mult(ctx, ctx->buf, ctx->buf);

        length -= use_len;
        p += use_len;
        out_p += use_len;
    }

    return 0;
}

int gcm_finish(gcm_ctx_t *ctx, unsigned char *tag, size_t tag_len)
{
    size_t i;
    unsigned char work_buf[16];
    uint64_t orig_len=ctx->len*8;
    uint64_t orig_add_len=ctx->add_len*8;

    if (tag_len>16 || tag_len<4) return -1;

    if (tag_len != 0) memcpy(tag, ctx->base_ectr, tag_len);

    if (orig_len || orig_add_len)
    {
        memset(work_buf, 0x00, 16);

        PUT_UINT32_BE((orig_add_len >> 32), work_buf, 0);
        PUT_UINT32_BE((orig_add_len      ), work_buf, 4);
        PUT_UINT32_BE((orig_len     >> 32), work_buf, 8);
        PUT_UINT32_BE((orig_len          ), work_buf, 12);

        for (i=0; i<16; i++) ctx->buf[i]^=work_buf[i];

        gcm_mult(ctx, ctx->buf, ctx->buf);

        for (i=0; i<tag_len; i++) tag[i]^=ctx->buf[i];
    }

    return 0;
}

int gcm_setkey(gcm_ctx_t *ctx, const unsigned char *key, size_t keybits)
{
    int ret;

    memset(ctx, 0, sizeof(gcm_ctx_t));

    ret = rijndael_set_key_enc_only(&ctx->aes, key, keybits);
    if (ret < 0) {
      dtls_warn("cannot set rijndael key\n");
    } else {
      gcm_gen_table(ctx);
      ret = 0;
    }
    return ret;
}

int gcm_crypt_and_tag(
    gcm_ctx_t *ctx, int mode, size_t length,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *add, size_t add_len,
    const unsigned char *in, unsigned char *out,
    size_t tag_len, unsigned char *tag)
{
    int ret;

    if ((ret = gcm_starts(ctx, mode, iv, iv_len, add, add_len)) != 0)
        return ret;

    if ((ret = gcm_update(ctx, length, in, out)) != 0)
        return ret;

    if ((ret = gcm_finish(ctx, tag, tag_len)) != 0)
        return ret;

    return 0;
}

int gcm_auth_decrypt(
    gcm_ctx_t *ctx, size_t length,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *add, size_t add_len,
    const unsigned char *tag, size_t tag_len,
    const unsigned char *in, unsigned char *out)
{
    int ret;
    size_t i;
    int diff;
    unsigned char check_tag[16];

    if ((ret = gcm_crypt_and_tag(ctx, GCM_DECRYPT, length,
        iv, iv_len, add, add_len, in, out, tag_len, check_tag)) != 0)
        return ret;

    /* Check tag in "constant-time" */
    for (diff=0, i=0; i<tag_len; i++) diff |= tag[i]^check_tag[i];

    if (diff != 0) {
        /* MAC authentication failed */
        memset(out, 0, length);
        return -1;
    }

    return 0;
}

long dtls_gcm_encrypt_message(
    gcm_ctx_t *ctx, size_t tag_len,
    const unsigned char *iv, size_t iv_len,
    unsigned char *msg, size_t lm,
    const unsigned char *aad, size_t la)
{
    long ret=-1;
    size_t i;
    unsigned char tag[16];

    if (tag_len > sizeof(tag)) goto finish;

    if (gcm_crypt_and_tag(ctx,
        GCM_ENCRYPT, lm, iv, iv_len, aad, la, msg, msg, sizeof(tag), tag) != 0)
        goto finish;

    msg += lm;
    for (i=0; i<tag_len; i++) *msg++ = tag[i];
    ret = lm + tag_len;

finish:
    return ret;
}

long dtls_gcm_decrypt_message(
    gcm_ctx_t *ctx, size_t tag_len,
    const unsigned char *iv, size_t iv_len,
    unsigned char *msg, size_t lm,
    const unsigned char *aad, size_t la)
{
    long ret=-1;
    unsigned char tag[16];

    if (tag_len>sizeof(tag) || lm<tag_len) goto finish;
    lm-=tag_len;

    /* last tag_len octets constitutes MAC */
    memcpy(tag, msg+lm, tag_len);

    if (gcm_auth_decrypt(
        ctx, lm, iv, iv_len, aad, la, tag, tag_len, msg, msg) != 0)
        goto finish;

    ret=lm;

finish:
    return ret;
}
