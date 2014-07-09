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

#include "mod_auth_gssweb.h"

module AP_MODULE_DECLARE_DATA auth_gssweb_module;

#define command(name, func, var, type, usage)           \
  AP_INIT_ ## type (name, (void*) func,                 \
        (void*)APR_OFFSETOF(gss_auth_config, var),      \
        OR_AUTHCFG | RSRC_CONF, usage)

static const command_rec gssweb_config_cmds[] = {
    command("GSSServiceName", ap_set_string_slot, service_name,
            TAKE1, "Service name used for Apache authentication."),

    { NULL }
};

static int
gssweb_authenticate_user(request_rec *r)
{
    gss_auth_config *conf = 
        (gss_auth_config *) ap_get_module_config(r->per_dir_config,
						&auth_gssweb_module);
    const char *auth_line = NULL;
    const char *type = NULL;
    char *auth_type = NULL;
    char *negotiate_ret_value = NULL;
    gss_conn_ctx conn_ctx = NULL;
    int ret;
    OM_uint32 major_status, minor_status, minor_status2;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    const char *posted_token = NULL;
    int ret;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
    OM_uint32 ret_flags = 0;
    unsigned int nonce;

    gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "Entering GSSWeb authentication");
   
    /* Check if this is for our auth type */
    type = ap_auth_type(r);
    if (type == NULL || strcasecmp(type, "GSSWeb") != 0) {
        gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
		"AuthType '%s' is not GSSWeb, bailing out",
		(type) ? type : "(NULL)");

        return DECLINED;
    }

    /* Set up a GSS context for this request, if there isn't one already */
    conn_ctx = gss_get_conn_ctx(r);
    if (conn_ctx == NULL) {
	gss_log(APLOG_MARK, APLOG_ERR, 0, r,
		"Failed to create internal context: probably not enough memory");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Set-up the output filter, if we haven't already */
    if (GSS_CTX_EMPTY == conn_ctx->state) {

      // TBD -- Set-up the output filter 
    }

    /* Read the token and nonce from the POST */
    //TBD -- gss_log the values

    /* If the nonce is set and doesn't match, start over */
    if ((0 != conn_ctx_nonce) && (conn_ctx->nonce != nonce) {
	if (GSS_C_NO_CONTEXT != conn_ctx->context) {
	  gss_delete_sec_context(&minor_status, &conn_ctx->context, GSS_C_NO_BUFFER);
	}
	conn_ctx->context = GSS_C_NO_CONTEXT;
	conn_ctx->state = GSS_CTX_EMPTY;
	conn_ctx->user = NULL;
	if (NULL != conn_ctx->output_token) {
	  // TBD -- release the output token
	}
	conn_ctx->output_token = NULL;
      }
      conn_ctx->nonce = nonce;
      
    /* If the output filter reported an internal server error, return it */
    if (GSS_CTX_ERROR == conn_ctx->state) {
      ret = HTTP_INTERNAL_SERVER_ERROR;
      gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	      "Output filter returned internal server error, reporting.");
      goto end;
    }

    /* Acquire server credentials */
    ret = get_gss_creds(r, conf, &server_creds);
    if (ret)
      goto end;

    /* Decode input token */
    input_token.length = apr_base64_decode(input_token.value, posted_token);

    /* Call gss_accept_sec_context */
    major_status = gss_accept_sec_context(&minor_status,
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

    if (GSS_ERROR(major_status)) {
      gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	      "%s", get_gss_error(r, major_status, minor_status,
				  "Failed to establish authentication"));
      gss_delete_sec_context(&minor_status, &ctx->context, GSS_C_NO_BUFFER);
      ctx->context = GSS_C_NO_CONTEXT;
      ctx->state = GSS_CTX_EMPTY;
      ret = HTTP_UNAUTHORIZED;
      goto end;
    }

    /* Store the token & nonce in the stored context */
    conn_ctx.output_token = &output_token;
    conn_ctx.nonce = nonce;

    /* If we aren't done yet, go around again */
    if (major_status & GSS_S_CONTINUE_NEEDED) {
      ctx->state = GSS_CTX_IN_PROGRESS;
      ret = HTTP_UNAUTHORIZED;
      goto end;
    }

    ctx->state = GSS_CTX_ESTABLISHED;
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

static void
gssweb_register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(gssweb_authenticate_user, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_gssweb_module = {
    STANDARD20_MODULE_STUFF,
    gss_config_dir_create,
    NULL,
    NULL,
    NULL,
    gssweb_config_cmds,
    gssweb_register_hooks
};
