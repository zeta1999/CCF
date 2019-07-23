// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>

#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>

// The following functions are defined in Open Enclave's standard
// library headers but lack a corresponding implementation.


// The following functions are used by libcurl's mbedtls module.

int mbedtls_x509_crt_parse_file( mbedtls_x509_crt *chain, const char *path )
{
  abort();
}

int mbedtls_x509_crt_parse_path( mbedtls_x509_crt *chain, const char *path )
{
  abort();
}

int mbedtls_pk_parse_keyfile( mbedtls_pk_context *ctx, const char *path, const char *password )
{
  abort();
}

int mbedtls_x509_crl_parse_file( mbedtls_x509_crl *chain, const char *path )
{
  abort();
}

// Additional from CCF hacks

void mbedtls_ssl_conf_renegotiation (mbedtls_ssl_config *conf, int renegotiation)
{
  abort();
}
