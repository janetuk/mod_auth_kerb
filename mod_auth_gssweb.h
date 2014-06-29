/*
 * Copyright (c) 2010 CESNET
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of CESNET nor the names of its contributors may
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __MOD_AUTH_GSSAPI_H__
#define __MOD_AUTH_GSSAPI_H__

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include <apr_base64.h>
#include <apr_strings.h>

#include <gssapi.h>
/* XXX */
#define GSS_KRB5_NT_PRINCIPAL_NAME 0xdeaddead

#ifndef GSSAPI_SUPPORTS_SPNEGO
#include "spnegokrb5.h"
#endif

#define SERVICE_NAME "HTTP"

typedef struct {
    const char *service_name;
    const char *krb5_keytab;
} gss_auth_config;

typedef struct gss_conn_ctx_t {
    gss_ctx_id_t context;
    enum {
	GSS_CTX_EMPTY,
    	GSS_CTX_IN_PROGRESS,
    	GSS_CTX_ESTABLISHED,
    } state;
    char *user;
} *gss_conn_ctx;

void
gss_log(const char *file, int line, int level, int status,
        const request_rec *r, const char *fmt, ...);

int
gss_authenticate(request_rec *r, gss_auth_config *conf, gss_conn_ctx ctx,
                 const char *auth_line, char **negotiate_ret_value);
#endif
