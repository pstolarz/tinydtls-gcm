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

#ifndef _DTLS_GSM_H_
#define _DTLS_GSM_H_

#include "aes/rijndael.h"

#define GCM_ENCRYPT     0
#define GCM_DECRYPT     1

typedef struct {
    rijndael_ctx aes;           /**< AES-128 encryption context */
    uint64_t HL[16];            /**< Precalculated HTable */
    uint64_t HH[16];            /**< Precalculated HTable */
    uint64_t len;               /**< Total data length */
    uint64_t add_len;           /**< Total add length */
    unsigned char base_ectr[16];/**< First ECTR for tag */
    unsigned char y[16];        /**< Y working value */
    unsigned char buf[16];      /**< buf working value */
    int mode;                   /**< Encrypt or Decrypt */
} gcm_ctx_t;

/* GCM stream start function
 */
int gcm_starts(gcm_ctx_t *ctx, int mode, const unsigned char *iv,
    size_t iv_len, const unsigned char *add, size_t add_len);

/* GCM update function. Encrypts/decrypts using the given context. Expects input
   to be a multiple of 16 bytes! Only the last call before gcm_finish()
   can be less than 16 bytes!
 */
int gcm_update(
    gcm_ctx_t *ctx, size_t length, const unsigned char *in, unsigned char *out);

/* GCM finalisation function. Wraps up the GCM stream and generates the tag.
   The tag can have a maximum length of 16 bytes.
 */
int gcm_finish(gcm_ctx_t *ctx, unsigned char *tag, size_t tag_len);

/* Initializes GCM context with a given key */
int gcm_setkey(gcm_ctx_t *ctx, const unsigned char *key, size_t keybits);

/* GCM buffer encryption/decryption using a block cipher */
int gcm_crypt_and_tag(
    gcm_ctx_t *ctx, int mode, size_t length,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *add, size_t add_len,
    const unsigned char *in, unsigned char *out,
    size_t tag_len, unsigned char *tag);

/* GCM buffer authenticated decryption using a block cipher */
int gcm_auth_decrypt(
    gcm_ctx_t *ctx, size_t length,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *add, size_t add_len,
    const unsigned char *tag, size_t tag_len,
    const unsigned char *in, unsigned char *out);

/* tinyDTLS GCM encryption interface */
long dtls_gcm_encrypt_message(
    gcm_ctx_t *ctx, size_t tag_len,
    const unsigned char *iv, size_t iv_len,
    unsigned char *msg, size_t lm,
    const unsigned char *aad, size_t la);

/* tinyDTLS GCM decryption interface */
long dtls_gcm_decrypt_message(
    gcm_ctx_t *ctx, size_t tag_len,
    const unsigned char *iv, size_t iv_len,
    unsigned char *msg, size_t lm,
    const unsigned char *aad, size_t la);

#endif /* _DTLS_GSM_H_ */
