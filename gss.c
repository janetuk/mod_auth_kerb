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

static const char *
get_gss_error(request_rec *r, OM_uint32 err_maj, OM_uint32 err_min, char *prefix)
{
   OM_uint32 maj_stat, min_stat; 
   OM_uint32 msg_ctx = 0;
   gss_buffer_desc status_string;
   char *err_msg;
   int first_pass;

   gss_log(APLOG_MARK, APLOG_DEBUG, 0, r,
	   "GSS-API major_status:%8.8x, minor_status:%8.8x",
	   err_maj, err_min);

   err_msg = apr_pstrdup(r->pool, prefix);
   do {
      maj_stat = gss_display_status (&min_stat,
	                             err_maj,
				     GSS_C_GSS_CODE,
				     GSS_C_NO_OID,
				     &msg_ctx,
				     &status_string);
      if (!GSS_ERROR(maj_stat)) {
         err_msg = apr_pstrcat(r->pool, err_msg,
			       ": ", (char*) status_string.value, NULL);
	 gss_release_buffer(&min_stat, &status_string);
	 first_pass = 0;
      }
   } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);

   msg_ctx = 0;
   err_msg = apr_pstrcat(r->pool, err_msg, " (", NULL);
   first_pass = 1;
   do {
      maj_stat = gss_display_status (&min_stat,
	                             err_min,
				     GSS_C_MECH_CODE,
				     GSS_C_NULL_OID,
				     &msg_ctx,
				     &status_string);
      if (!GSS_ERROR(maj_stat)) {
	 err_msg = apr_pstrcat(r->pool, err_msg,
			       (first_pass) ? "" : ", ",
	                       (char *) status_string.value,
			       NULL);
	 gss_release_buffer(&min_stat, &status_string);
	 first_pass = 0;
      }
   } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);
   err_msg = apr_pstrcat(r->pool, err_msg, ")", NULL);

   return err_msg;
}

static int
get_gss_creds(request_rec *r,
              gss_auth_config *conf,
	      gss_cred_id_t *server_creds)
{
   gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
   OM_uint32 major_status, minor_status, minor_status2;
   gss_name_t server_name = GSS_C_NO_NAME;
   char buf[1024];
   int have_server_princ;

   if (conf->service_name && strcmp(conf->service_name, "Any") == 0) {
       *server_creds = GSS_C_NO_CREDENTIAL;
       return 0;
   }

   have_server_princ = conf->service_name && strchr(conf->service_name, '/') != NULL;
   if (have_server_princ)
       strncpy(buf, conf->service_name, sizeof(buf));
   else
       snprintf(buf, sizeof(buf), "%s@%s",
	       (conf->service_name) ? conf->service_name : SERVICE_NAME,
	       ap_get_server_name(r));

   token.value = buf;
   token.length = strlen(buf) + 1;

   major_status = gss_import_name(&minor_status, &token,
	 			  (have_server_princ) ? (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME : (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
				  &server_name);
   memset(&token, 0, sizeof(token));
   if (GSS_ERROR(major_status)) {
      gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	      "%s", get_gss_error(r, major_status, minor_status,
	      "gss_import_name() failed"));
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   major_status = gss_display_name(&minor_status, server_name, &token, NULL);
   if (GSS_ERROR(major_status)) {
      /* Perhaps we could just ignore this error but it's safer to give up now,
         I think */
      gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	      "%s", get_gss_error(r, major_status, minor_status,
		                  "gss_display_name() failed"));
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "Acquiring creds for %s", token.value);
   gss_release_buffer(&minor_status, &token);
   
   major_status = gss_acquire_cred(&minor_status, server_name, GSS_C_INDEFINITE,
			           GSS_C_NO_OID_SET, GSS_C_ACCEPT,
				   server_creds, NULL, NULL);
   gss_release_name(&minor_status2, &server_name);
   if (GSS_ERROR(major_status)) {
      gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	      "%s", get_gss_error(r, major_status, minor_status,
		 		  "Failed to load GSS-API credentials"));
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   return 0;
}

static int
cmp_gss_type(gss_buffer_t token, gss_OID oid)
{
   unsigned char *p;
   size_t len;

   if (token->length == 0)
      return GSS_S_DEFECTIVE_TOKEN;

   p = token->value;
   if (*p++ != 0x60)
      return GSS_S_DEFECTIVE_TOKEN;
   len = *p++;
   if (len & 0x80) {
      if ((len & 0x7f) > 4)
	 return GSS_S_DEFECTIVE_TOKEN;
      p += len & 0x7f;
   }
   if (*p++ != 0x06)
      return GSS_S_DEFECTIVE_TOKEN;

   if (((OM_uint32) *p++) != oid->length)
      return GSS_S_DEFECTIVE_TOKEN;

   return memcmp(p, oid->elements, oid->length);
}

int
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

  ret = get_gss_creds(r, conf, &server_creds);
  if (ret)
     goto end;

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
     gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	     "%s", get_gss_error(r, major_status, minor_status,
		                 "Failed to establish authentication"));
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
  gss_release_name(&minor_status, &client_name); 
  if (GSS_ERROR(major_status)) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r,
	    "%s", get_gss_error(r, major_status, minor_status,
		                "gss_display_name() failed"));
    ret = HTTP_INTERNAL_SERVER_ERROR;
    goto end;
  }

  ctx->state = GSS_CTX_ESTABLISHED;
  ctx->user = apr_pstrdup(r->pool, output_token.value);
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
