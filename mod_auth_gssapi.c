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

#include "mod_auth_gssapi.h"

module AP_MODULE_DECLARE_DATA auth_gssapi_module;

#define command(name, func, var, type, usage)           \
  AP_INIT_ ## type (name, (void*) func,                 \
        (void*)APR_OFFSETOF(gss_auth_config, var),      \
        OR_AUTHCFG | RSRC_CONF, usage)

static const command_rec gss_config_cmds[] = {
    command("GSSServiceName", ap_set_string_slot, service_name,
            TAKE1, "Service name used for Apache authentication."),

    command("GSSKrb5Keytab", ap_set_string_slot, krb5_keytab,
            TAKE1, "Location of Kerberos V5 keytab file."),

    { NULL }
};

static void *
gss_config_dir_create(apr_pool_t *p, char *d)
{
    gss_auth_config *conf;

    conf = (gss_auth_config *) apr_pcalloc(p, sizeof(*conf));
    return conf;
}

void
gss_log(const char *file, int line, int level, int status,
        const request_rec *r, const char *fmt, ...)
{
    char errstr[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(errstr, sizeof(errstr), fmt, ap);
    va_end(ap);
   
    ap_log_rerror(file, line, level | APLOG_NOERRNO, status, r, "%s", errstr);
}

static void
set_http_headers(request_rec *r, const gss_auth_config *conf,
      		 char *negotiate_ret_value)
{
    char *negoauth_param;
    const char *header_name = (r->proxyreq == PROXYREQ_PROXY) ?
        "Proxy-Authenticate" : "WWW-Authenticate";

    if (negotiate_ret_value == NULL)
	return;

    negoauth_param = (*negotiate_ret_value == '\0') ? "GSSAPI" :
        apr_pstrcat(r->pool, "GSSAPI ", negotiate_ret_value, NULL);
    apr_table_add(r->err_headers_out, header_name, negoauth_param);
}

static apr_status_t
cleanup_conn_ctx(void *data)
{
    gss_conn_ctx ctx = (gss_conn_ctx) data;
    OM_uint32 minor_status;

    if (ctx && ctx->context != GSS_C_NO_CONTEXT)
	gss_delete_sec_context(&minor_status, &ctx->context, GSS_C_NO_BUFFER);

    return APR_SUCCESS;
}

static gss_conn_ctx
gss_get_conn_ctx(request_rec *r)
{
    char key[1024];
    gss_conn_ctx ctx = NULL;

    snprintf(key, sizeof(key), "mod_auth_gssapi:conn_ctx");
    apr_pool_userdata_get((void **)&ctx, key, r->connection->pool);
    /* XXX LOG */
    if (ctx == NULL) {
	ctx = (gss_conn_ctx) apr_palloc(r->connection->pool, sizeof(*ctx));
	if (ctx == NULL)
	    return NULL;
	ctx->context = GSS_C_NO_CONTEXT;
	ctx->state = GSS_CTX_EMPTY;
	ctx->user = NULL;
	apr_pool_userdata_set(ctx, key, cleanup_conn_ctx, r->connection->pool);
    }
    return ctx;
}

static int
gss_authenticate_user(request_rec *r)
{
    gss_auth_config *conf = 
        (gss_auth_config *) ap_get_module_config(r->per_dir_config,
						&auth_gssapi_module);
    const char *auth_line = NULL;
    const char *type = NULL;
    char *auth_type = NULL;
    char *negotiate_ret_value = NULL;
    gss_conn_ctx conn_ctx = NULL;
    int ret;

    gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "Entering GSSAPI authentication");
   
    /* get the type specified in Apache configuration */
    type = ap_auth_type(r);
    if (type == NULL || strcmp(type, "GSSAPI") != 0) {
        gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
		"AuthType '%s' is not for us, bailing out",
		(type) ? type : "(NULL)");

        return DECLINED;
    }

    /* get what the user sent us in the HTTP header */
    auth_line = apr_table_get(r->headers_in, (r->proxyreq == PROXYREQ_PROXY)
 	                                    ? "Proxy-Authorization"
					    : "Authorization");
    if (auth_line == NULL) {
        gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
		"Client hasn't sent any authentication data, giving up");
        set_http_headers(r, conf, "\0");
        return HTTP_UNAUTHORIZED;
    }

    auth_type = ap_getword_white(r->pool, &auth_line);
    if (strcasecmp(auth_type, "GSSAPI") != 0) {
        gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
		"Unsupported authentication type (%s) requested by client",
		(auth_type) ? auth_type : "(NULL)");
        set_http_headers(r, conf, "\0");
        return HTTP_UNAUTHORIZED;
    }

    conn_ctx = gss_get_conn_ctx(r);
    if (conn_ctx == NULL) {
	gss_log(APLOG_MARK, APLOG_ERR, 0, r,
		"Failed to create internal context: probably not enough memory");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* optimizing hack */
    if (conn_ctx->state == GSS_CTX_ESTABLISHED && auth_line == NULL) {
	r->user = apr_pstrdup(r->pool, conn_ctx->user);
	r->ap_auth_type = "GSSAPI";
	return OK;
    }

    /* XXXX subrequests ignored, only successful accesses taken into account! */
    if (!ap_is_initial_req(r) && conn_ctx->state == GSS_CTX_ESTABLISHED) {
	r->user = apr_pstrdup(r->pool, conn_ctx->user);
	r->ap_auth_type = "GSSAPI";
	return OK;
    }

    ret = gss_authenticate(r, conf, conn_ctx,
	                   auth_line, &negotiate_ret_value);
    if (ret == HTTP_UNAUTHORIZED || ret == OK) {
        /* LOG?? */
        set_http_headers(r, conf, negotiate_ret_value);
    }

    if (ret == OK) {
	r->user = apr_pstrdup(r->pool, conn_ctx->user);
	r->ap_auth_type = "GSSAPI";
    }

    /* debug LOG ??? */

    return ret;
}

static void
gss_register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(gss_authenticate_user, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_gssapi_module = {
    STANDARD20_MODULE_STUFF,
    gss_config_dir_create,
    NULL,
    NULL,
    NULL,
    gss_config_cmds,
    gss_register_hooks
};
