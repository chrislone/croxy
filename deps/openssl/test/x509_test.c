/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/x509.h>
#include "testutil.h"

static EVP_PKEY *pubkey = NULL;
static EVP_PKEY *privkey = NULL;
static EVP_MD *signmd = NULL;

/* EC key pair used for signing */
static const unsigned char privkeydata[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x7d, 0x2b, 0xfe, 0x5c, 0xcb, 0xcb, 0x27, 0xd6, 0x28,
    0xfe, 0x98, 0x34, 0x84, 0x4a, 0x13, 0x6f, 0x70, 0xc4, 0x1a, 0x0b, 0xfc, 0xde, 0xb0, 0xb2, 0x32,
    0xb1, 0xdd, 0x4f, 0x0e, 0xbc, 0xdf, 0x89, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xbf, 0x82, 0xd9, 0xc9, 0x4b, 0x19, 0x43,
    0x45, 0x6b, 0xd4, 0x50, 0x64, 0x9b, 0xd5, 0x8d, 0x5a, 0xd9, 0xdc, 0xc9, 0x24, 0x23, 0x7a, 0x3b,
    0x48, 0x23, 0xe2, 0x2a, 0x24, 0xf2, 0x9c, 0x6f, 0x87, 0xd0, 0xc4, 0x0f, 0xcc, 0x7e, 0x7c, 0x8d,
    0xfc, 0x08, 0x46, 0x37, 0x85, 0x4f, 0x5b, 0x3a, 0x0b, 0x97, 0xd7, 0x57, 0x2a, 0x5a, 0x6b, 0x7a,
    0x0b, 0xe4, 0xe8, 0x9c, 0x4a, 0xbb, 0xbf, 0x09, 0x4d
};

static const unsigned char pubkeydata[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xbf, 0x82, 0xd9, 0xc9, 0x4b,
    0x19, 0x43, 0x45, 0x6b, 0xd4, 0x50, 0x64, 0x9b, 0xd5, 0x8d, 0x5a, 0xd9, 0xdc, 0xc9, 0x24, 0x23,
    0x7a, 0x3b, 0x48, 0x23, 0xe2, 0x2a, 0x24, 0xf2, 0x9c, 0x6f, 0x87, 0xd0, 0xc4, 0x0f, 0xcc, 0x7e,
    0x7c, 0x8d, 0xfc, 0x08, 0x46, 0x37, 0x85, 0x4f, 0x5b, 0x3a, 0x0b, 0x97, 0xd7, 0x57, 0x2a, 0x5a,
    0x6b, 0x7a, 0x0b, 0xe4, 0xe8, 0x9c, 0x4a, 0xbb, 0xbf, 0x09, 0x4d
};

/* Self signed cert using ECDSA-SHA256 with the keypair listed above */
static const unsigned char certdata[] = {
    0x30, 0x82, 0x01, 0x86, 0x30, 0x82, 0x01, 0x2d, 0x02, 0x14, 0x75, 0xd6, 0x04, 0xd2, 0x80, 0x61,
    0xd3, 0x32, 0xbc, 0xae, 0x38, 0x58, 0xfe, 0x12, 0x42, 0x81, 0x7a, 0xdd, 0x0b, 0x99, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21,
    0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
    0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74,
    0x64, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x31, 0x30, 0x31, 0x32, 0x30, 0x37, 0x32, 0x37, 0x35,
    0x35, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x35, 0x30, 0x30, 0x32, 0x32, 0x37, 0x30, 0x37, 0x32, 0x37,
    0x35, 0x35, 0x5a, 0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x41, 0x55, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d,
    0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a,
    0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67, 0x69,
    0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
    0x07, 0x03, 0x42, 0x00, 0x04, 0xbf, 0x82, 0xd9, 0xc9, 0x4b, 0x19, 0x43, 0x45, 0x6b, 0xd4, 0x50,
    0x64, 0x9b, 0xd5, 0x8d, 0x5a, 0xd9, 0xdc, 0xc9, 0x24, 0x23, 0x7a, 0x3b, 0x48, 0x23, 0xe2, 0x2a,
    0x24, 0xf2, 0x9c, 0x6f, 0x87, 0xd0, 0xc4, 0x0f, 0xcc, 0x7e, 0x7c, 0x8d, 0xfc, 0x08, 0x46, 0x37,
    0x85, 0x4f, 0x5b, 0x3a, 0x0b, 0x97, 0xd7, 0x57, 0x2a, 0x5a, 0x6b, 0x7a, 0x0b, 0xe4, 0xe8, 0x9c,
    0x4a, 0xbb, 0xbf, 0x09, 0x4d, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
    0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x5f, 0x45, 0x7f, 0xa4, 0x6a, 0x03, 0xfd, 0xe7,
    0xf3, 0x42, 0x43, 0x38, 0x5b, 0x81, 0x08, 0x1a, 0x47, 0x8e, 0x59, 0x3a, 0x28, 0x5b, 0x97, 0x67,
    0x47, 0x66, 0x2a, 0x16, 0xf5, 0xce, 0xf5, 0x92, 0x02, 0x20, 0x22, 0x0e, 0xab, 0x35, 0xdf, 0x49,
    0xb1, 0x86, 0xa3, 0x3b, 0x26, 0xda, 0x7e, 0x8b, 0x44, 0x45, 0xc6, 0x46, 0x14, 0x04, 0x22, 0x2b,
    0xe5, 0x2a, 0x62, 0x84, 0xc5, 0x94, 0xa0, 0x1b, 0xaa, 0xa9
};

/* Some simple CRL data */
static const unsigned char crldata[] = {
    0x30, 0x81, 0x8B, 0x30, 0x31, 0x02, 0x01, 0x01, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x04, 0x03, 0x02, 0x05, 0x00, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x54, 0x65, 0x73, 0x74, 0x17, 0x0D, 0x32, 0x32, 0x31, 0x30, 0x31, 0x32, 0x30,
    0x35, 0x33, 0x34, 0x30, 0x31, 0x5A, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,
    0x03, 0x02, 0x05, 0x00, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x75, 0xAC, 0xA9, 0xB5, 0xFE,
    0x63, 0x09, 0x8B, 0x57, 0x4F, 0xBB, 0xC6, 0x0C, 0xA9, 0x9A, 0x7C, 0x55, 0x89, 0xF9, 0x9C, 0x48,
    0xE9, 0xF3, 0xED, 0xE5, 0xC2, 0x88, 0xCE, 0xEC, 0xB1, 0x51, 0xF1, 0x02, 0x21, 0x00, 0x8B, 0x93,
    0xC5, 0xA6, 0x28, 0x48, 0x5A, 0x4E, 0x10, 0x52, 0x82, 0x12, 0x2F, 0xC4, 0x62, 0x2D, 0x3F, 0x5A,
    0x62, 0x7F, 0x9D, 0x1B, 0x12, 0xC5, 0x36, 0x25, 0x73, 0x03, 0xF4, 0xDE, 0x62, 0x24
};

/*
 * Test for Regression discussed in PR #19388
 * In order for this simple test to fail, it requires the digest used for
 * signing to be different from the alg within the loaded cert.
 */
static int test_x509_tbs_cache(void)
{
    int ret;
    X509 *x = NULL;
    const unsigned char *p = certdata;

    ret = TEST_ptr(x = d2i_X509(NULL, &p, sizeof(certdata)))
          && TEST_int_gt(X509_sign(x, privkey, signmd), 0)
          && TEST_int_eq(X509_verify(x, pubkey), 1);
    X509_free(x);
    return ret;
}

/*
 * Test for Regression discussed in PR #19388
 * In order for this simple test to fail, it requires the digest used for
 * signing to be different from the alg within the loaded cert.
 */
static int test_x509_crl_tbs_cache(void)
{
    int ret;
    X509_CRL *crl = NULL;
    const unsigned char *p = crldata;

    ret = TEST_ptr(crl = d2i_X509_CRL(NULL, &p, sizeof(crldata)))
          && TEST_int_gt(X509_CRL_sign(crl, privkey, signmd), 0)
          && TEST_int_eq(X509_CRL_verify(crl, pubkey), 1);

    X509_CRL_free(crl);
    return ret;
}

int setup_tests(void)
{
    const unsigned char *p;

    p = pubkeydata;
    pubkey = d2i_PUBKEY(NULL, &p, sizeof(pubkeydata));

    p = privkeydata;
    privkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(privkeydata));

    if (pubkey == NULL || privkey == NULL) {
        BIO_printf(bio_err, "Failed to create keys\n");
        return 0;
    }

    /* Note this digest is different from the certificate digest */
    signmd = EVP_MD_fetch(NULL, "SHA384", NULL);
    if (signmd == NULL) {
        BIO_printf(bio_err, "Failed to fetch digest\n");
        return 0;
    }

    ADD_TEST(test_x509_tbs_cache);
    ADD_TEST(test_x509_crl_tbs_cache);
    return 1;
}

void cleanup_tests(void)
{
    EVP_MD_free(signmd);
    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(privkey);
}
