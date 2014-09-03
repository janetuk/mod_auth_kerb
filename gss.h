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

#ifndef __GSS_H__
#define __GSS_H__

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

#include <apr_base64.h>
#include <apr_strings.h>

#include <gssapi.h>

#define SERVICE_NAME "HTTP"

typedef struct {
    const char *service_name;
    const char *krb5_keytab;
} gss_auth_config;

typedef struct gss_conn_ctx_t {
  gss_ctx_id_t context;
  gss_cred_id_t server_creds;
  enum {
    GSS_CTX_EMPTY,
    GSS_CTX_IN_PROGRESS,
    GSS_CTX_FAILED,
    GSS_CTX_ESTABLISHED,
  } state;
  enum {
    GSS_FILT_NEW,
    GSS_FILT_INPROGRESS,
    GSS_FILT_ERROR,
  } filter_stat;

  char *user;
  gss_buffer_desc output_token;
  unsigned int nonce;
} *gss_conn_ctx;

void
gss_log(const char *file, int line, int level, int status,
        const request_rec *r, const char *fmt, ...);

apr_status_t
gss_cleanup_conn_ctx(void *data);

gss_conn_ctx
gss_retrieve_conn_ctx(request_rec *r);

gss_conn_ctx
gss_create_conn_ctx(request_rec *r, gss_auth_config *conf);

void *
gss_config_dir_create(apr_pool_t *p, char *d);

const char *
get_gss_error(request_rec *r, OM_uint32 err_maj, OM_uint32 err_min, char *prefix);

int
get_gss_creds(request_rec *r, gss_auth_config *conf, gss_cred_id_t *server_creds);

int
cmp_gss_type(gss_buffer_t token, gss_OID oid);

#endif
