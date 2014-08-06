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

/* 
 * NOTE: Portions of the code in this file were derived from example
 * code distributed under the Apache 2.0 license:
 *     http://www.apache.org/licenses/LICENSE-2.0
 * The example code was modified for inclusion in this module.
 * 
 * This module implements the Apache server side of the GSSWeb
 * authentiction type which allows Moonshot to be used for
 * authentication in web applications.  The module consists of two
 * components: the hook function (gssweb_authenticate_user) that does
 * most of the work, and an output filter (gssweb_authenticate_filter)
 * that is registered by the hook function to send the output token
 * back to the client in a json message that wraps the original
 * response content.
 *
 * This module uses a simple protocol between the client and server
 * to exchange GSS tokens and nonce information.  The protocol is 
 * described in the protocol.txt file included with module source.
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
  
#define DEFAULT_ENCTYPE		"application/x-www-form-urlencoded"
#define GSS_MAX_TOKEN_SIZE	4096	//TBD -- check this value

/* gssweb_read_post() -- Reads the post data associated with a
 * request.
 */
static int gssweb_read_post(request_rec *r, const char **rbuf)
{
  int rc;
  if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK) {
    return rc;
  }
  if (ap_should_client_block(r)) {
    char argsbuffer[GSS_MAX_TOKEN_SIZE+256];
    int rsize, len_read, rpos = 0;
    long length = r->remaining;
    *rbuf = ap_pcalloc(r->pool, length + 1);
    ap_hard_timeout("util_read", r);
    while ((len_read =
	    ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) { 
      ap_reset_timeout(r);
      if ((rpos + len_read) > length) {
	rsize = length - rpos;
      }
      else {
	rsize = len_read;
      }
      memcpy((char*)*rbuf + rpos, argsbuffer, rsize);
      rpos += rsize;
    }
    ap_kill_timeout(r);
  }
  return rc;
}

/* gssweb_get_post_data() -- Gets the token and nonce from the request
 * data.
 */
static int gssweb_get_post_data(request_rec *r, int *nonce, gss_buffer_desc *input_token)
{
  const char *data;
  const char *key, *val, *type;
  int rc = 0;

  if(r->method_number != M_POST) {
    return DECLINED;
  }

  type = ap_table_get(r->headers_in, "Content-Type");
  if(strcasecmp(type, DEFAULT_ENCTYPE) != 0) {
    return DECLINED;
  }

  if((rc = util_read(r, &data)) != OK) {
    return rc;
  }
  if(*tab) {
    ap_clear_table(*tab);
  }
  else {
    *tab = ap_make_table(r->pool, 8);
  }
  while(*data && (val = ap_getword(r->pool, &data, '&'))) { 
    key = ap_getword(r->pool, &val, '=');
    ap_unescape_url((char*)key);
    ap_unescape_url((char*)val);
    ap_table_merge(*tab, key, val);
  }
  return OK;
}

/* gssweb_authenticate_filter() -- Output filter for gssweb authentication.
 * Wraps original response in JSON -- adding JSON to the beginning of the 
 * response, escapes double quotes in the original response, and adds JSON
 * to the end of the response.  Handles responses that involve more than
 * one filter call by maintaining state until an EOS bucket is received.
 */
static apr_status_t gssweb_authenticate_filter (ap_filter_t *f,
                                        apr_bucket_brigade *pbbIn)
{
  request_rec *r = f->r;
  conn_rec *c = r->connection;
  apr_bucket *pbktIn;
  apr_bucket_brigade *pbbOut;

  pbbOut=apr_brigade_create(r->pool, c->bucket_alloc);
  for (pbktIn = APR_BRIGADE_FIRST(pbbIn);
       pbktIn != APR_BRIGADE_SENTINEL(pbbIn);
       pbktIn = APR_BUCKET_NEXT(pbktIn))
    {
      const char *data;
      apr_size_t len;
      char *buf;
      apr_size_t n;
      apr_bucket *pbktOut;

      if(APR_BUCKET_IS_EOS(pbktIn))
	{
	  apr_bucket *pbktEOS=apr_bucket_eos_create(c->bucket_alloc);
	  APR_BRIGADE_INSERT_TAIL(pbbOut,pbktEOS);
	  continue;
	}

      /* read */
      apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ);

      /* write */
      buf = apr_bucket_alloc(len, c->bucket_alloc);
      for(n=0 ; n < len ; ++n)
	buf[n] = apr_toupper(data[n]);

      pbktOut = apr_bucket_heap_create(buf, len, apr_bucket_free,
				       c->bucket_alloc);
      APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
    }

  /* Q: is there any advantage to passing a brigade for each bucket? 
   * A: obviously, it can cut down server resource consumption, if this
   * experimental module was fed a file of 4MB, it would be using 8MB for
   * the 'read' buckets and the 'write' buckets.
   *
   * Note it is more efficient to consume (destroy) each bucket as it's
   * processed above than to do a single cleanup down here.  In any case,
   * don't let our caller pass the same buckets to us, twice;
   */
  apr_brigade_cleanup(pbbIn);
  return ap_pass_brigade(f->next,pbbOut);
}

/* gssweb_authenticate_user() -- Hook to perform actual user
 * authentication.  Will be called once for each round trip in the GSS
 * authentication loop.  Reads the tokend from the request, calls
 * gss_accept_sec_context(), and stores the output token and context
 * in the user data area. Registers output filter to send the GSS
 * output token back to the client.
 */
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
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "Failed to create internal context: probably not enough memory");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  /* Read the token and nonce from the POST */
  if (0 != gssweb_get_post_data(r, &nonce, &input_token)) {
    ret = HTTP_UNAUTHORIZED;
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "Unable to read nonce or input token.");
    goto end;
  }
  gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "GSSWeb nonce value = %u.", nonce);
   
  /* If the nonce is set and doesn't match, start over */
  if ((0 != conn_ctx->nonce) && (conn_ctx->nonce != nonce)) {
    if (GSS_C_NO_CONTEXT != conn_ctx->context) {
      gss_delete_sec_context(&minor_status, &conn_ctx->context, GSS_C_NO_BUFFER);
    }
    conn_ctx->context = GSS_C_NO_CONTEXT;
    conn_ctx->state = GSS_CTX_EMPTY;
    conn_ctx->user = NULL;
    if (0 != conn_ctx->output_token.length) {
      gss_release_buffer(&minor_status, &conn_ctx->output_token);
    }
      conn_ctx->output_token = GSS_C_EMPTY_BUFFER;
  }
 
  /* If the output filter reported an internal server error, return it */
  if (GSS_CTX_ERROR == conn_ctx->state) {
    ret = HTTP_INTERNAL_SERVER_ERROR;
    gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	    "Output filter returned internal server error, reporting.");
    goto end;
  }

  /* If this is a new authentiction cycle, set-up the output filter. */
  if (GSS_CTX_EMPTY == conn_ctx->state)
 {
   ap_add_output_filter("gssweb_auth_filter",conn_ctx->ctx,r,r->connection);
   ap_register_output_filter("gssweb_auth_filter",gssweb_authenticate_filter,AP_FTYPE_RESOURCE);

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

  /* Store the nonce & ouput token in the stored context */
  conn_ctx->nonce = nonce;
  conn_ctx->output_token = output_token;
    
  /* If we aren't done yet, go around again */
  if (major_status & GSS_S_CONTINUE_NEEDED) {
    ctx->state = GSS_CTX_IN_PROGRESS;
    ret = HTTP_UNAUTHORIZED;
    goto end;
  }

  ctx->state = GSS_CTX_ESTABLISHED;
  // TBD -- set the user and authtype in the request structure
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
