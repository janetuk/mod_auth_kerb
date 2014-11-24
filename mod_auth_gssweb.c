/*
 * Copyright (c) 2012, 2013, 2014 JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * NOTE: Some code in this module was derived from code in
 * mod_auth_gssapi.c which is copyrighted by CESNET.  See that file
 * for full copyright details.
 *
 * NOTE: Portions of the code in this file were derived from example
 * code distributed under the Apache 2.0 license:
 *     http://www.apache.org/licenses/LICENSE-2.0
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

#include <stdio.h>
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

/* gssweb_read_req() -- reads the request data into a buffer 
 */
static int gssweb_read_req(request_rec *r, const char **rbuf, apr_off_t *size)
{
  int rc = OK;

  if((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_get_post_data: Failed to set up client block");
    return(rc);
  }
  
  if(ap_should_client_block(r)) {
    char          argsbuffer[HUGE_STRING_LEN];
    apr_off_t     rsize, len_read, rpos = 0;
    apr_off_t     length = r->remaining;

    *rbuf = (const char *) apr_pcalloc(r->pool, (apr_size_t) (length + 1));
    *size = length;
    while((len_read = ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
      if((rpos + len_read) > length) {
	rsize = length - rpos;
      }
      else {
	rsize = len_read;
      }

      memcpy((char *) *rbuf + rpos, argsbuffer, (size_t) rsize);
      rpos += rsize;
    }
  }
  return(rc);
}

/* gssweb_get_post_data() -- Gets the token and nonce from the request
 * data.
 */
static int gssweb_get_post_data(request_rec *r, int *nonce, gss_buffer_desc *input_token)
{
  const char *data;
  apr_off_t datalen;
  const char *key, *val, *type;
  int rc = 0;
  size_t len;

  *nonce = 0;
  input_token->length = 0;
  input_token->value = NULL;

    gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_get_post_data: Entering function");
 
  if(r->method_number != M_POST) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_get_post_data: Request data is not a POST, declining.");
    return DECLINED;
  }

  type = apr_table_get(r->headers_in, "Content-Type");
  if(strcasecmp(type, DEFAULT_ENCTYPE) != 0) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_get_post_data: Unexpected content type, declining.");
    return DECLINED;
  }

  if((rc = gssweb_read_req(r, &data, &datalen)) != OK) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_get_post_data: Data read error, rc = %d", rc);
    return rc;
  }
  
  while(*data && (val = ap_getword(r->pool, &data, '&'))) { 
    key = ap_getword(r->pool, &val, '=');
    ap_unescape_url((char*)key);
    ap_unescape_url((char*)val);
    if (0 == strcasecmp(key, "token")) {
      gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_get_post_data: Found encoded token: %s", val);
      len = apr_base64_decode_len(val);
      if (NULL == (input_token->value = apr_pcalloc(r->pool, len+1))) {
      }
      input_token->length = apr_base64_decode(input_token->value, val);
    }
    else if (0 == strcasecmp(key, "nonce")) {
      gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_get_post_data: Found nonce: %s", val);
      *nonce = atoi(val);
    }
    else {
      gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_get_post_data: unknown key (%s), ignored", key);
    }
  }
  if ((0 == *nonce) || (0 == input_token->length)) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_get_post_data: nonce (%d) or token len (%d) is 0, declining", *nonce, input_token->length);
    return DECLINED;
  }
  else {
    gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_get_post_data: returning nonce (%d) and token (%d bytes)", *nonce, input_token->length);
    return OK;
  }
}

/* gssweb_authenticate_filter() -- Output filter for gssweb authentication.
 * Wraps original response in JSON -- adding JSON to the beginning of the 
 * response, escapes double quotes in the original response, and adds JSON
 * to the end of the response.  Handles responses that involve more than
 * one filter call by maintaining state until an EOS bucket is received.
 */
static apr_status_t gssweb_authenticate_filter (ap_filter_t *f,
                                        apr_bucket_brigade *brig_in)
{
  request_rec *r = f->r;
  conn_rec *c = r->connection;
  apr_bucket_brigade *brig_out;
  apr_bucket *bkt_in = NULL;
  apr_bucket *bkt_out = NULL;
  apr_bucket *bkt_eos = NULL;
  const char *data = NULL;
  apr_size_t len = 0;
  apr_size_t enc_len = 0;
  char *buf = NULL;
  char *stoken = NULL;
  apr_size_t n = 0;
  gss_conn_ctx conn_ctx = NULL;
  const char *c_type = NULL;
  const char *c_len = NULL;
  apr_status_t ret = 0;

  gss_log(APLOG_MARK, APLOG_DEBUG, 0, f->r, "Entering GSSWeb filter");

  /* Get the context from the request.  If the context is NULL or 
   * there is no outstanding request (no nonce set), just forward 
   * all of the buckets as-is, because the client isn't gssweb 
   */
  if ((NULL == (conn_ctx = gss_retrieve_conn_ctx(r))) ||
      (0 == conn_ctx->nonce)) {
    for (bkt_in = APR_BRIGADE_FIRST(brig_in);
	 bkt_in != APR_BRIGADE_SENTINEL(brig_in);
	 bkt_in = APR_BUCKET_NEXT(bkt_in))
      {
	if (NULL == (brig_out = apr_brigade_create(r->pool, c->bucket_alloc))) {      
	  apr_brigade_cleanup(brig_in);
	  return HTTP_INTERNAL_SERVER_ERROR;
	}
	apr_bucket_copy(bkt_in, &bkt_out);
	APR_BRIGADE_INSERT_TAIL(brig_out, bkt_out);
	ap_pass_brigade(f->next, brig_out);
      }
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_filter: Failed to find valid context");
    apr_brigade_cleanup(brig_in);
    return OK;
  }

  c_type = apr_table_get(r->headers_in, "Content-Type");
  c_len = apr_table_get(r->headers_in, "Content-Length");
  /* clear content-length and MD5 checksum */
  apr_table_unset(r->headers_out, "Content-Length");
  apr_table_unset(r->headers_out, "Content-MD5");
  gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_authenticate_filter: Received Content-Type: %s, Content-Length: %d", c_type, c_len);

  /* If this is the first call for a response, send opening JSON block */
  if (GSS_FILT_NEW == conn_ctx->filter_stat) {
    gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_authenticate_filter: First filter call for response");
    if (NULL == (brig_out = apr_brigade_create(r->pool, c->bucket_alloc))) {
      conn_ctx->filter_stat = GSS_FILT_ERROR;
      gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_filter: Unable to allocate output brigade (opening)");
      apr_brigade_cleanup(brig_in);
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Encode the output token */
    len = apr_base64_encode_len(conn_ctx->output_token.length);
    if (NULL == (stoken = apr_bucket_alloc(len+1, c->bucket_alloc))) {
      gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_filter: Unable to allocate space for encoded output token");
      apr_brigade_cleanup(brig_in);
      apr_brigade_cleanup(brig_out);
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    apr_base64_encode_binary(stoken, conn_ctx->output_token.value, conn_ctx->output_token.length);

    if (NULL == (data = apr_bucket_alloc(len+1024, c->bucket_alloc))) {
      gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_filter: Unable to allocate space for opening JSON block");
      apr_brigade_cleanup(brig_in);
      apr_brigade_cleanup(brig_out);
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Send opening JSON block */
    snprintf((char *)data, len+1024, 
	     "{\"gssweb\": {\n\"token\": \"%s\",\n\"nonce\": \"%d\"},\n\"application\": {\n\"data\": \"", 
	     stoken, conn_ctx->nonce);
    gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_authenticate_filter: Sending (%d bytes): %s", strlen(data), data);
    
    bkt_out = apr_bucket_heap_create(data, strlen(data), apr_bucket_free,
				     c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(brig_out, bkt_out);
    if (0 != (ret = ap_pass_brigade(f->next, brig_out))) {
      apr_brigade_cleanup(brig_in);
      apr_brigade_cleanup(brig_out);
      return ret;
    }

    conn_ctx->filter_stat = GSS_FILT_INPROGRESS;
  }

  /* Loop through the app data buckets, escaping and sending each one */
  for (bkt_in = APR_BRIGADE_FIRST(brig_in);
       bkt_in != APR_BRIGADE_SENTINEL(brig_in);
       bkt_in = APR_BUCKET_NEXT(bkt_in))
    {
      if (NULL == (brig_out = apr_brigade_create(r->pool, c->bucket_alloc))) {
	    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_filter: Unable to allocate brigade (loop)");
	    conn_ctx->filter_stat = GSS_FILT_ERROR;
	    apr_brigade_cleanup(brig_in);
	    return HTTP_INTERNAL_SERVER_ERROR;
      }

      /* if this is an EOS, send the JSON closing block */
      if(APR_BUCKET_IS_EOS(bkt_in))
	{
	  /* create and add the JSON closing block */
	  
	  if (NULL == (data = apr_bucket_alloc(1024, c->bucket_alloc))) {
	      gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_filter: Unable to allocate space for closing JSON block");
	      apr_brigade_cleanup(brig_in);
	      apr_brigade_cleanup(brig_out);
	      return HTTP_INTERNAL_SERVER_ERROR;
	  }

	  snprintf((char *)data, 1024, "\",\n\"content-type\": \"%s\",\n\"content-length\": \"%s\"\n}\n}", c_type, c_len);
	  gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_authenticate_filter: Sending (%d bytes) %s", strlen(data), data);

	  bkt_out = apr_bucket_heap_create(data, strlen(data), apr_bucket_free,
					   c->bucket_alloc);
	  APR_BRIGADE_INSERT_TAIL(brig_out, bkt_out);

	  /* Indicate that the next filter call is a new response */
	  conn_ctx->filter_stat = GSS_FILT_NEW;
	  
	  /* set EOS in the outbound brigade */
	  bkt_eos = apr_bucket_eos_create(c->bucket_alloc);
	  APR_BRIGADE_INSERT_TAIL (brig_out, bkt_eos);
	  
	  /* set application type to 'application/json' */
	  apr_table_set(r->headers_out, "Content-Type", "application/json");

	  /* clear content-length and MD5 checksum */
	  apr_table_unset(r->headers_out, "Content-Length");
	  apr_table_unset(r->headers_out, "Content-MD5");

	  /* pass the brigade */
	  gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_authenticate_filter: Sending: EOS");
	  if (0 != (ret = ap_pass_brigade(f->next, brig_out))) {
	    conn_ctx->filter_stat = GSS_FILT_ERROR;
	    apr_brigade_cleanup(brig_in);
	    apr_brigade_cleanup(brig_out);
	    return ret;
	  }
	  break;
	}

      /* Read application data from each input bucket */
      apr_bucket_read(bkt_in, &data, &len, APR_BLOCK_READ);

      /* Base64 encode the data (if any) */
      if (0 != len) {
	enc_len = apr_base64_encode_len(len);
	if (NULL == (buf = apr_bucket_alloc(enc_len, c->bucket_alloc))) {
	  gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_filter: Unable to allocate space for encoded application data");
	  apr_brigade_cleanup(brig_in);
	  apr_brigade_cleanup(brig_out);
	  return HTTP_INTERNAL_SERVER_ERROR;
	}
	enc_len = apr_base64_encode_binary(buf, data, len);

	/* Put the data in a bucket and add it to the the output brigade */
	bkt_out = apr_bucket_heap_create(buf, enc_len-1, apr_bucket_free, c->bucket_alloc);
	buf[enc_len] = '\0';
	gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_authenticate_filter: Sending (%d bytes)", enc_len);
	APR_BRIGADE_INSERT_TAIL(brig_out, bkt_out);
	
	/* Send the output brigade */
	if (OK != (ret = ap_pass_brigade(f->next, brig_out))) {
	  apr_brigade_cleanup(brig_in);
	  apr_brigade_cleanup(brig_out);
	  return ret;
	}
      }
    }

  /* Make sure we don't see the same data again */
  apr_brigade_cleanup(brig_in);
  return OK;
}

/* gssweb_add_filter() -- Hook to add our output filter to the request
 * (r). Called for all error responses through the
 * gssweb_insert_error_filter hook.
 */
static void
gssweb_add_filter(request_rec *r) 
{
  gss_conn_ctx conn_ctx = NULL;

  /* Get the context for this request, if any */
  conn_ctx = gss_retrieve_conn_ctx(r);

  /* Add the output filter */
  ap_add_output_filter("gssweb_auth_filter", (void *)conn_ctx, r, r->connection);
  return;
}

/* gssweb_authenticate_user() -- Hook to perform actual user
 * authentication.  Will be called once for each round trip in the GSS
 * authentication loop.  Reads the tokend from the request, calls
 * gss_accept_sec_context(), and stores the output token and context
 * in the user data areas.  Adds output filter to send the GSS
 * output token back to the client.
 */
static int
gssweb_authenticate_user(request_rec *r) 
{
  const char *auth_line = NULL;
  char *auth_type = NULL;
  char *negotiate_ret_value = NULL;
  gss_conn_ctx conn_ctx = NULL;
  int ret;
  OM_uint32 major_status, minor_status, minor_status2;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  gss_name_t client_name = GSS_C_NO_NAME;
  gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
  OM_uint32 ret_flags = 0;
  unsigned int nonce;
  int release_output_token = 1;
  gss_auth_config *conf = NULL;

  gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "Entering GSSWeb authentication");

  /* Get the module configuration */
  conf = (gss_auth_config *) ap_get_module_config(r->per_dir_config,
						  &auth_gssweb_module);

  /* Check if this is for our auth type */
  auth_type = (char *)ap_auth_type(r);
  if (auth_type == NULL || strcasecmp(auth_type, "GSSWeb") != 0) {
        gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
		"gssweb_authenticate_user: AuthType '%s' is not GSSWeb, bailing out",
		(auth_type) ? auth_type : "(NULL)");
        ret = DECLINED;
	goto end;
  }

  /* Retrieve the existing context (if any), or create one */
  if ((NULL == (conn_ctx = gss_retrieve_conn_ctx(r))) &&
      (NULL == (conn_ctx = gss_create_conn_ctx(r, conf)))) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_user: Unable to find or create context");
  }

  /* Read the token and nonce from the POST */
  if (0 != gssweb_get_post_data(r, &nonce, &input_token)) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_user: Unable to read nonce or input token from GSSWeb input");
    gss_delete_sec_context(&minor_status, &conn_ctx->context, GSS_C_NO_BUFFER);
    conn_ctx->context = GSS_C_NO_CONTEXT;
    conn_ctx->state = GSS_CTX_FAILED;
    if (0 != conn_ctx->output_token.length)
      gss_release_buffer(&minor_status, &(conn_ctx->output_token));
    conn_ctx->output_token.length = 0;
    ret = HTTP_UNAUTHORIZED;
    goto end;
  }
  gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_authenticate_user: GSSWeb nonce value = %u.", nonce);

  /* If the nonce does not match, release old context and create new */
  if ((0 != conn_ctx->nonce) && (conn_ctx->nonce != nonce)) {
    gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
	    "gssweb_authenticate_user: Nonce in context (%d) does not match nonce in input (%d), new request", conn_ctx->nonce, nonce);
    gss_cleanup_conn_ctx(conn_ctx);
    if (NULL == (conn_ctx = gss_create_conn_ctx (r, conf))) {
      gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_user: Failed to create GSS context");
      ret = HTTP_INTERNAL_SERVER_ERROR;
      goto end;
    }
  }

  /* If the output filter reported an internal server error, return it */
  if (GSS_FILT_ERROR == conn_ctx->filter_stat) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	    "gssweb_authenticate_user: Output filter returned error, reporting.");
    ret = HTTP_INTERNAL_SERVER_ERROR;
    goto end;
  }

  /* Add the output filter to this request (for non-error returns) */
  ap_add_output_filter("gssweb_auth_filter", (void *)conn_ctx, r, r->connection);

  /* Call gss_accept_sec_context */
  major_status = gss_accept_sec_context(&minor_status,
					&conn_ctx->context,
					conn_ctx->server_creds,
					&input_token,
					GSS_C_NO_CHANNEL_BINDINGS,
					NULL,
					NULL,
					&output_token,
					&ret_flags,
					NULL,
					&delegated_cred);
  gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
	  "gssweb_authenticate_user: Client %s us their credential",
	  (ret_flags & GSS_C_DELEG_FLAG) ? "delegated" : "didn't delegate");

  if (GSS_ERROR(major_status)) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	    "%s", get_gss_error(r, major_status, minor_status,
				"gssweb_authenticate_user: Failed to establish authentication"));
    conn_ctx->state = GSS_CTX_FAILED;
  }

  /* If there was no token returned, clear token from context and exit */
  if (0 == output_token.length) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gssweb_authenticate_user: No output token");
    gss_delete_sec_context(&minor_status, &conn_ctx->context, GSS_C_NO_BUFFER);
    conn_ctx->context = GSS_C_NO_CONTEXT;
    conn_ctx->state = GSS_CTX_FAILED;
    if (0 != conn_ctx->output_token.length)
      gss_release_buffer(&minor_status, &(conn_ctx->output_token));
    conn_ctx->output_token.length = 0;
    ret = HTTP_UNAUTHORIZED;
    goto end;
  }

  /* Store the nonce & ouput token in the stored context */
  conn_ctx->nonce = nonce;
  conn_ctx->output_token = output_token;
  release_output_token = 0;

  /* If we aren't done yet, go around again */
  gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_authenticate_user: Accept sec context complete, continue needed");
  if (major_status & GSS_S_CONTINUE_NEEDED) {
    conn_ctx->state = GSS_CTX_IN_PROGRESS;
    ret = HTTP_UNAUTHORIZED;
    goto end;
  }

  gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gssweb_authenticate_user: Authentication succeeded!!");
  conn_ctx->state = GSS_CTX_ESTABLISHED;
  r->user = apr_pstrdup(r->pool, conn_ctx->user);
  r->ap_auth_type = "GSSWeb";
  ret = OK;

 end:
  if (delegated_cred)
    gss_release_cred(&minor_status, &delegated_cred);
  
  if ((release_output_token) && (output_token.length))
    gss_release_buffer(&minor_status, &output_token);
    
  if (client_name != GSS_C_NO_NAME)
    gss_release_name(&minor_status, &client_name);

  return ret;
}

static void
gssweb_register_hooks(apr_pool_t *p)
{
  /* register the gssweb output filter */
  ap_register_output_filter("gssweb_auth_filter", gssweb_authenticate_filter, NULL, AP_FTYPE_RESOURCE);

  /* register hooks */
  ap_hook_check_user_id(gssweb_authenticate_user, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_insert_error_filter(gssweb_add_filter, NULL, NULL, APR_HOOK_MIDDLE);
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
