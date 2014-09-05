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

void
gss_log(const char *file, 
        int line,
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
        int module_index,
#endif
        int level,
        int status,
        const request_rec *r,
        const char *fmt, ...)
{
    char errstr[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(errstr, sizeof(errstr), fmt, ap);
    va_end(ap);
   
    ap_log_rerror(file,
                  line, 
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
                  module_index,
#endif
                  level | APLOG_NOERRNO, 
                  status, 
                  r, 
                  "%s", 
                  errstr);
}

apr_status_t
gss_cleanup_conn_ctx(void *data)
{
    gss_conn_ctx ctx = (gss_conn_ctx) data;
    OM_uint32 minor_status;

    if (ctx && ctx->context != GSS_C_NO_CONTEXT)
	gss_delete_sec_context(&minor_status, &ctx->context, GSS_C_NO_BUFFER);
  
    if (ctx && ctx->server_creds != GSS_C_NO_CREDENTIAL)
      gss_release_cred(&minor_status, &ctx->server_creds);

    return APR_SUCCESS;
}

gss_conn_ctx
gss_create_conn_ctx(request_rec *r, gss_auth_config *conf)
{
  char key[1024];
  gss_conn_ctx ctx = NULL;
 
  snprintf(key, sizeof(key), "mod_auth_gssweb:conn_ctx");
  
  if (NULL == (ctx = (gss_conn_ctx) apr_palloc(r->connection->pool, sizeof(*ctx)))) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gss_create_conn_ctx: Can't allocate GSS context");
    return NULL;
  }
  ctx->context = GSS_C_NO_CONTEXT;
  ctx->state = GSS_CTX_EMPTY;
  ctx->filter_stat = GSS_FILT_NEW;
  ctx->user = NULL;

  /* Acquire and store server credentials */
  if (0 == get_gss_creds(r, conf, &(ctx->server_creds))) {
    gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gss_create_conn_ctx: Server credentials acquired");
  } else {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gss_create_conn_ctx: Error: Server credentials NOT acquired");
    return NULL;
  }

  apr_pool_userdata_set(ctx, key, gss_cleanup_conn_ctx, r->connection->pool);

  return ctx;
}

gss_conn_ctx
gss_retrieve_conn_ctx(request_rec *r)
{
  char key[1024];
  gss_conn_ctx ctx = NULL;
 
  snprintf(key, sizeof(key), "mod_auth_gssweb:conn_ctx");
  apr_pool_userdata_get((void **)&ctx, key, r->connection->pool);

  if (NULL == ctx)
    gss_log(APLOG_MARK, APLOG_DEBUG, 0, r, "gss_retrieve_conn_ctx: No GSS context found");

  return ctx;
}

void *
gss_config_dir_create(apr_pool_t *p, char *d)
{
    gss_auth_config *conf;

    conf = (gss_auth_config *) apr_pcalloc(p, sizeof(*conf));
    return conf;
}


const char *
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

int
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

int
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

