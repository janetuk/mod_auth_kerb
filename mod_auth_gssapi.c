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

    AP_INIT_RAW_ARGS("GssapiNameAttributes", mag_name_attrs, NULL, OR_AUTHCFG | RSRC_CONF,
                     "Name Attributes to be exported as environ variables"),
    { NULL }
};

static void
set_http_headers(request_rec *r, const gss_auth_config *conf,
      		 char *negotiate_ret_value)
{
    char *negoauth_param;
    const char *header_name = (r->proxyreq == PROXYREQ_PROXY) ?
        "Proxy-Authenticate" : "WWW-Authenticate";

    if (negotiate_ret_value == NULL)
	return;

    negoauth_param = (*negotiate_ret_value == '\0') ? "Negotiate" :
        apr_pstrcat(r->pool, "Negotiate ", negotiate_ret_value, NULL);
    apr_table_add(r->err_headers_out, header_name, negoauth_param);
}

static int
gss_authenticate(request_rec *r, gss_auth_config *conf, gss_conn_ctx ctx,
		 const char *auth_line, char **negotiate_ret_value)
{
  OM_uint32 major_status, minor_status, minor_status2;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  const char *auth_param = NULL;
  int ret;
  gss_name_t client_name = GSS_C_NO_NAME;
  gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
  gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
  OM_uint32 ret_flags = 0;
  gss_OID_desc spnego_oid;
  OM_uint32 (*accept_sec_context)
		(OM_uint32 *, gss_ctx_id_t *, const gss_cred_id_t,
		 const gss_buffer_t, const gss_channel_bindings_t,
		 gss_name_t *, gss_OID *, gss_buffer_t, OM_uint32 *,
		 OM_uint32 *, gss_cred_id_t *);

  *negotiate_ret_value = "\0";

  spnego_oid.length = 6;
  spnego_oid.elements = (void *)"\x2b\x06\x01\x05\x05\x02";

  if (conf->krb5_keytab) {
     char *ktname;
     /* we don't use the ap_* calls here, since the string passed to putenv()
      * will become part of the enviroment and shouldn't be free()ed by apache
      */
     ktname = malloc(strlen("KRB5_KTNAME=") + strlen(conf->krb5_keytab) + 1);
     if (ktname == NULL) {
	gss_log(APLOG_MARK, APLOG_ERR, 0, r, "malloc() failed: not enough memory");
	ret = HTTP_INTERNAL_SERVER_ERROR;
	goto end;
     }
     sprintf(ktname, "KRB5_KTNAME=%s", conf->krb5_keytab);
     putenv(ktname);
#ifdef HEIMDAL
     /* Seems to be also supported by latest MIT */
     gsskrb5_register_acceptor_identity(conf->krb_5_keytab);
#endif
  }

  /* ap_getword() shifts parameter */
  auth_param = ap_getword_white(r->pool, &auth_line);
  if (auth_param == NULL) {
     gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	     "No Authorization parameter in request from client");
     ret = HTTP_UNAUTHORIZED;
     goto end;
  }

  if (ctx->state == GSS_CTX_ESTABLISHED) {
      gss_delete_sec_context(&minor_status, &ctx->context, GSS_C_NO_BUFFER);
      ctx->context = GSS_C_NO_CONTEXT;
      ctx->state = GSS_CTX_EMPTY;
  }

  input_token.length = apr_base64_decode_len(auth_param) + 1;
  input_token.value = apr_pcalloc(r->connection->pool, input_token.length);
  if (input_token.value == NULL) {
     gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	     "ap_pcalloc() failed (not enough memory)");
     ret = HTTP_INTERNAL_SERVER_ERROR;
     goto end;
  }
  input_token.length = apr_base64_decode(input_token.value, auth_param);

  /* LOG length, type */

#ifdef GSSAPI_SUPPORTS_SPNEGO
  accept_sec_context = gss_accept_sec_context;
#else
  accept_sec_context = (cmp_gss_type(&input_token, &spnego_oid) == 0) ?
		      gss_accept_sec_context_spnego : gss_accept_sec_context;
#endif

  major_status = accept_sec_context(&minor_status,
				  &ctx->context,
				  server_creds,
				  &input_token,
				  GSS_C_NO_CHANNEL_BINDINGS,
				  NULL,
				  NULL,
				  &output_token,
				  &ret_flags,
				  NULL,
				  &delegated_cred);
  gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
	  "Client %s us their credential",
	  (ret_flags & GSS_C_DELEG_FLAG) ? "delegated" : "didn't delegate");
  if (output_token.length) {
     char *token = NULL;
     size_t len;

     len = apr_base64_encode_len(output_token.length) + 1;
     token = apr_pcalloc(r->connection->pool, len + 1);
     if (token == NULL) {
	gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	        "ap_pcalloc() failed (not enough memory)");
        ret = HTTP_INTERNAL_SERVER_ERROR;
	gss_release_buffer(&minor_status2, &output_token);
	goto end;
     }
     apr_base64_encode(token, output_token.value, output_token.length);
     token[len] = '\0';
     *negotiate_ret_value = token;
     gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
	     "GSS-API token of length %d bytes will be sent back",
	     output_token.length);
     gss_release_buffer(&minor_status2, &output_token);
  }

  if (GSS_ERROR(major_status)) {
     // at least this error should be populated, to provider further information
     // to the user (maybe)
     char *error = get_gss_error(r, major_status, minor_status, "Failed to establish authentication");
     apr_table_set(r->subprocess_env, "GSS_ERROR_STR", error);
     gss_log(APLOG_MARK, APLOG_ERR, 0, r, error);
#if 0
     /* Don't offer the Negotiate method again if call to GSS layer failed */
     /* XXX ... which means we don't return the "error" output */
     *negotiate_ret_value = NULL;
#endif
     gss_delete_sec_context(&minor_status, &ctx->context, GSS_C_NO_BUFFER);
     ctx->context = GSS_C_NO_CONTEXT;
     ctx->state = GSS_CTX_EMPTY;
     ret = HTTP_UNAUTHORIZED;
     goto end;
  }

  if (major_status & GSS_S_CONTINUE_NEEDED) {
     ctx->state = GSS_CTX_IN_PROGRESS;
     ret = HTTP_UNAUTHORIZED;
     goto end;
  }

  major_status = gss_inquire_context(&minor_status, ctx->context, &client_name,
				     NULL, NULL, NULL, NULL, NULL, NULL);
  if (GSS_ERROR(major_status)) {
      gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	      "%s", get_gss_error(r, major_status, minor_status, "gss_inquire_context() failed"));
      ret = HTTP_INTERNAL_SERVER_ERROR;
      goto end;
  }

  major_status = gss_display_name(&minor_status, client_name, &output_token, NULL);
  ctx->user = apr_pstrndup(r->pool, output_token.value, output_token.length);

  if (conf->name_attributes) {
    mag_get_name_attributes(r, conf, client_name, ctx);
    mag_set_req_data(r, conf, ctx);
  }


  gss_release_name(&minor_status, &client_name);
  if (GSS_ERROR(major_status)) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	    "%s", get_gss_error(r, major_status, minor_status,
		                "gss_display_name() failed"));
    ret = HTTP_INTERNAL_SERVER_ERROR;
    goto end;
  }

  ctx->state = GSS_CTX_ESTABLISHED;
  gss_release_buffer(&minor_status, &output_token);

  ret = OK;

end:
  if (delegated_cred)
     gss_release_cred(&minor_status, &delegated_cred);

  if (output_token.length)
     gss_release_buffer(&minor_status, &output_token);

  if (client_name != GSS_C_NO_NAME)
     gss_release_name(&minor_status, &client_name);

  if (server_creds != GSS_C_NO_CREDENTIAL)
     gss_release_cred(&minor_status, &server_creds);

  return ret;
}

static int mag_post_config(apr_pool_t *cfgpool, apr_pool_t *log,
                           apr_pool_t *temp, server_rec *s)
{
    ap_add_version_component(cfgpool, "Moonshot mod_auth_gssapi");
    return OK;
}

#define MAG_ERROR_NO_AUTH_DATA    "NO_AUTH_DATA"
#define MAG_ERROR_UNSUP_AUTH_TYPE "UNSUP_AUTH_TYPE"
#define MAG_ERROR_GSS_MECH        "GSS_MECH_ERROR"

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
    if (type == NULL || strcmp(type, "Negotiate") != 0) {
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
        apr_table_set(r->subprocess_env, "MAG_ERROR", MAG_ERROR_NO_AUTH_DATA);
        return HTTP_UNAUTHORIZED;
    }

    auth_type = ap_getword_white(r->pool, &auth_line);
    if (strcasecmp(auth_type, "Negotiate") != 0) {
        gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
		"Unsupported authentication type (%s) requested by client",
		(auth_type) ? auth_type : "(NULL)");
        set_http_headers(r, conf, "\0");
        apr_table_set(r->subprocess_env, "MAG_ERROR", MAG_ERROR_UNSUP_AUTH_TYPE);
        return HTTP_UNAUTHORIZED;
    }

    if ((NULL == (conn_ctx = gss_retrieve_conn_ctx(r))) &&
	(NULL == (conn_ctx = gss_create_conn_ctx(r, conf)))) {
	gss_log(APLOG_MARK, APLOG_ERR, 0, r,
		"Failed to create internal context: probably not enough memory");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* optimizing hack */
    if (conn_ctx->state == GSS_CTX_ESTABLISHED && auth_line == NULL) {
	r->user = apr_pstrdup(r->pool, conn_ctx->user);
	r->ap_auth_type = "Negotiate";
	return OK;
    }

    /* XXXX subrequests ignored, only successful accesses taken into account! */
    if (!ap_is_initial_req(r) && conn_ctx->state == GSS_CTX_ESTABLISHED) {
	r->user = apr_pstrdup(r->pool, conn_ctx->user);
	r->ap_auth_type = "Negotiate";
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
	r->ap_auth_type = "Negotiate";
    } else {
      apr_table_set(r->subprocess_env, "MAG_ERROR", MAG_ERROR_GSS_MECH);
    }
    /* debug LOG ??? */

    return ret;
}

static void
gss_register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(gss_authenticate_user, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(mag_post_config, NULL, NULL, APR_HOOK_MIDDLE);
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
