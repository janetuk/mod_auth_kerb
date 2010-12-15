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
