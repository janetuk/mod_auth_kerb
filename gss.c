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

  if (NULL == (ctx = (gss_conn_ctx) apr_pcalloc(r->connection->pool, sizeof(*ctx)))) {
    gss_log(APLOG_MARK, APLOG_ERR, 0, r, "gss_create_conn_ctx: Can't allocate GSS context");
    return NULL;
  }
  ctx->context = GSS_C_NO_CONTEXT;
  ctx->state = GSS_CTX_EMPTY;
  ctx->filter_stat = GSS_FILT_NEW;
  ctx->user = NULL;
  ctx->name_attributes = NULL;
  apr_pool_create(&ctx->pool, r->connection->pool);
  /* register the context in the memory pool, so it can be freed
   * when the connection/request is terminated */
  apr_pool_cleanup_register(ctx->pool, (void *)ctx,
                              gss_cleanup_conn_ctx, apr_pool_cleanup_null);

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
    conf->pool = p;

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

/*
 * Name attributes to environment variables code
 * This code is strongly based on the code from https://github.com/modauthgssapi/mod_auth_gssapi
 */

static char *mag_status(request_rec *req, int type, uint32_t err)
{
    uint32_t maj_ret, min_ret;
    gss_buffer_desc text;
    uint32_t msg_ctx;
    char *msg_ret;
    int len;

    msg_ret = NULL;
    msg_ctx = 0;
    do {
        maj_ret = gss_display_status(&min_ret, err, type,
                                     GSS_C_NO_OID, &msg_ctx, &text);
        if (maj_ret != GSS_S_COMPLETE) {
            return msg_ret;
        }

        len = text.length;
        if (msg_ret) {
            msg_ret = apr_psprintf(req->pool, "%s, %*s",
                                   msg_ret, len, (char *)text.value);
        } else {
            msg_ret = apr_psprintf(req->pool, "%*s", len, (char *)text.value);
        }
        gss_release_buffer(&min_ret, &text);
    } while (msg_ctx != 0);

    return msg_ret;
}

char *mag_error(request_rec *req, const char *msg, uint32_t maj, uint32_t min)
{
    char *msg_maj;
    char *msg_min;

    msg_maj = mag_status(req, GSS_C_GSS_CODE, maj);
    msg_min = mag_status(req, GSS_C_MECH_CODE, min);
    return apr_psprintf(req->pool, "%s: [%s (%s)]", msg, msg_maj, msg_min);
}


static char mag_get_name_attr(request_rec *req,
                              gss_name_t name, name_attr *attr)
{
    uint32_t maj, min;

    maj = gss_get_name_attribute(&min, name, &attr->name,
                                 &attr->authenticated,
                                 &attr->complete,
                                 &attr->value,
                                 &attr->display_value,
                                 &attr->more);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                      "gss_get_name_attribute() failed on %.*s%s",
                      (int)attr->name.length, (char *)attr->name.value,
                      mag_error(req, "", maj, min));
        return 0;
    }

    return 1;
}

#define GSS_NAME_ATTR_USERDATA "GSS Name Attributes Userdata"

static apr_status_t mag_gss_name_attrs_cleanup(void *data)
{
    gss_conn_ctx_t *gss_ctx = (struct gss_conn_ctx_t *)data;
    free(gss_ctx->name_attributes);
    gss_ctx->name_attributes = NULL;
    return 0;
}

static void mc_add_name_attribute(gss_conn_ctx_t *gss_ctx,
                                  const char *name, const char *value)
{
    size_t size;

    if (gss_ctx->na_count % 16 == 0) {
        size = sizeof(mag_attr) * (gss_ctx->na_count + 16);
        gss_ctx->name_attributes = realloc(gss_ctx->name_attributes, size);
        if (!gss_ctx->name_attributes) apr_pool_abort_get(gss_ctx->pool)(ENOMEM);
        apr_pool_userdata_setn(gss_ctx, GSS_NAME_ATTR_USERDATA,
                               mag_gss_name_attrs_cleanup, gss_ctx->pool);
    }

    gss_ctx->name_attributes[gss_ctx->na_count].name = apr_pstrdup(gss_ctx->pool, name);
    gss_ctx->name_attributes[gss_ctx->na_count].value = apr_pstrdup(gss_ctx->pool, value);
    gss_ctx->na_count++;
}

static void mag_set_env_name_attr(request_rec *req, gss_conn_ctx_t *gss_ctx,
                                  name_attr *attr)
{
    char *value = "";
    int len = 0;

    /* Prefer a display_value, otherwise fallback to value */
    if (attr->display_value.length != 0) {
        len = attr->display_value.length;
        value = (char *)attr->display_value.value;
    } else if (attr->value.length != 0) {
        len = apr_base64_encode_len(attr->value.length);
        value = apr_pcalloc(req->pool, len);
        len = apr_base64_encode(value,
                                (char *)attr->value.value,
                                attr->value.length);
    }

    if (attr->number == 1) {
        mc_add_name_attribute(gss_ctx,
                              attr->env_name,
                              apr_psprintf(req->pool, "%.*s", len, value));
    }
    if (attr->more != 0 || attr->number > 1) {
        mc_add_name_attribute(gss_ctx,
                              apr_psprintf(req->pool, "%s_%d",
                                           attr->env_name, attr->number),
                              apr_psprintf(req->pool, "%.*s", len, value));
    }
    if (attr->more == 0 && attr->number > 1) {
        mc_add_name_attribute(gss_ctx,
                              apr_psprintf(req->pool, "%s_N", attr->env_name),
                              apr_psprintf(req->pool, "%d", attr->number - 1));
    }
}

static char* mag_escape_display_value(request_rec *req, gss_buffer_desc disp_value)
{
    /* This function returns a copy (in the pool) of the given gss_buffer_t where every
     * occurrence of " has been replaced by \". This string is NULL terminated */
    int i = 0, j = 0, n_quotes = 0;
    char *escaped_value = NULL;
    char *value = (char*) disp_value.value;

    // count number of quotes in the input string
    for (i = 0, j = 0; i < disp_value.length; i++)
        if (value[i] == '"')
            n_quotes++;

    // if there are no quotes, just return a copy of the string
    if (n_quotes == 0)
        return apr_pstrndup(req->pool, value, disp_value.length);

    // gss_buffer_t are not \0 terminated, but our result will be
    escaped_value = apr_palloc(req->pool, disp_value.length + n_quotes + 1);
    for (i = 0,j = 0; i < disp_value.length; i++, j++) {
        if (value[i] == '"') {
            escaped_value[j] = '\\';
            j++;
        }
        escaped_value[j] = value[i];
    }
    // make the string NULL terminated
    escaped_value[j] = '\0';
    return escaped_value;
}

static void mag_add_json_name_attr(request_rec *req, char first,
                                   name_attr *attr, char **json)
{
    const char *value = "";
    int len = 0;
    char *b64value = NULL;
    int b64len = 0;
    const char *vstart = "";
    const char *vend = "";
    const char *vformat;

    if (attr->value.length != 0) {
        b64len = apr_base64_encode_len(attr->value.length);
        b64value = apr_pcalloc(req->pool, b64len);
        b64len = apr_base64_encode(b64value,
                                   (char *)attr->value.value,
                                   attr->value.length);
    }
    if (attr->display_value.length != 0) {
        value = mag_escape_display_value(req, attr->display_value);
        len = strlen(value);
    }
    if (attr->number == 1) {
        *json = apr_psprintf(req->pool,
                            "%s%s\"%.*s\":{\"authenticated\":%s,"
                                          "\"complete\":%s,"
                                          "\"values\":[",
                            *json, (first ? "" : ","),
                            (int)attr->name.length, (char *)attr->name.value,
                            attr->authenticated ? "true" : "false",
                            attr->complete ? "true" : "false");
    } else {
        vstart = ",";
    }

    if (b64value) {
        if (len) {
            vformat = "%s%s{\"raw\":\"%s\",\"display\":\"%.*s\"}%s";
        } else {
            vformat = "%s%s{\"raw\":\"%s\",\"display\":%.*s}%s";
        }
    } else {
        if (len) {
            vformat = "%s%s{\"raw\":%s,\"display\":\"%.*s\"}%s";
        } else {
            vformat = "%s%s{\"raw\":%s,\"display\":%.*s}%s";
        }
    }

    if (attr->more == 0) {
        vend = "]}";
    }

    *json = apr_psprintf(req->pool, vformat, *json,
                        vstart,
                        b64value ? b64value : "null",
                        len ? len : 4, len ? value : "null",
                        vend);
}

gss_buffer_desc empty_buffer = GSS_C_EMPTY_BUFFER;

void mag_get_name_attributes(request_rec *req, gss_auth_config *cfg,
                             gss_name_t name, gss_conn_ctx_t *gss_ctx)
{
    uint32_t maj, min;
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    name_attr attr;
    char *json = NULL;
    char *error;
    int count = 0;
    int i, j;

    maj = gss_inquire_name(&min, name, NULL, NULL, &attrs);
    if (GSS_ERROR(maj)) {
        error = mag_error(req, "gss_inquire_name() failed", maj, min);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s", error);
        apr_table_set(req->subprocess_env, "GSS_NAME_ATTR_ERROR", error);
        return;
    }

    if (!attrs || attrs->count == 0) {
        mc_add_name_attribute(gss_ctx, "GSS_NAME_ATTR_ERROR", "0 attributes found");
    }

    if (cfg->name_attributes->output_json) {

        if (attrs) count = attrs->count;

        json = apr_psprintf(req->pool,
                            "{\"name\":\"%s\",\"attributes\":{",
                            gss_ctx->user);
    } else {
        count = cfg->name_attributes->map_count;
    }

    for (i = 0; i < count; i++) {
        memset(&attr, 0, sizeof(name_attr));

        if (cfg->name_attributes->output_json) {
            attr.name = attrs->elements[i];
            for (j = 0; j < cfg->name_attributes->map_count; j++) {
                if (strncmp(cfg->name_attributes->map[j].attr_name,
                            attrs->elements[i].value,
                            attrs->elements[i].length) == 0) {
                    attr.env_name = cfg->name_attributes->map[j].env_name;
                    break;
                }
            }
        } else {
            attr.name.length = strlen(cfg->name_attributes->map[i].attr_name);
            attr.name.value = cfg->name_attributes->map[i].attr_name;
            attr.env_name = cfg->name_attributes->map[i].env_name;
        }

        attr.number = 0;
        attr.more = -1;
        do {
            attr.number++;
            attr.value = empty_buffer;
            attr.display_value = empty_buffer;
            if (!mag_get_name_attr(req, name, &attr)) break;

            if (cfg->name_attributes->output_json) {
                mag_add_json_name_attr(req, i == 0, &attr, &json);
            }
            if (attr.env_name) {
                mag_set_env_name_attr(req, gss_ctx, &attr);
            }

            gss_release_buffer(&min, &attr.value);
            gss_release_buffer(&min, &attr.display_value);
        } while (attr.more != 0);
    }

    if (cfg->name_attributes->output_json) {
        json = apr_psprintf(req->pool, "%s}}", json);
        mc_add_name_attribute(gss_ctx, "GSS_NAME_ATTRS_JSON", json);
    }
}

static void mag_set_name_attributes(request_rec *req, gss_conn_ctx_t *gss_ctx)
{
    int i = 0;
    for (i = 0; i < gss_ctx->na_count; i++) {
        apr_table_set(req->subprocess_env,
                      gss_ctx->name_attributes[i].name,
                      gss_ctx->name_attributes[i].value);
    }
}

void mag_set_req_data(request_rec *req,
                      gss_auth_config *cfg,
                      gss_conn_ctx_t *gss_ctx)
{
    if (gss_ctx->name_attributes) {
        mag_set_name_attributes(req, gss_ctx);
    }
}

static apr_status_t mag_name_attrs_cleanup(void *data)
{
    gss_auth_config *cfg = (gss_auth_config *)data;
    free(cfg->name_attributes);
    cfg->name_attributes = NULL;
    return 0;
}

const char *mag_name_attrs(cmd_parms *parms, void *mconfig,
                                  const char *w)
{
    gss_auth_config *cfg = (gss_auth_config *)mconfig;
    void *tmp_na;
    size_t size = 0;
    char *p;
    int c;

    if (!cfg->name_attributes) {
        size = sizeof(mag_name_attributes)
                + (sizeof(mag_na_map) * 16);
    } else if (cfg->name_attributes->map_count % 16 == 0) {
        size = sizeof(mag_name_attributes)
                + (sizeof(mag_na_map)
                    * (cfg->name_attributes->map_count + 16));
    }
    if (size) {
        tmp_na = realloc(cfg->name_attributes, size);
        if (!tmp_na) apr_pool_abort_get(cfg->pool)(ENOMEM);

        if (cfg->name_attributes) {
            size_t empty = (sizeof(mag_na_map) * 16);
            memset(tmp_na + size - empty, 0, empty);
        } else {
            memset(tmp_na, 0, size);
        }
        cfg->name_attributes = (mag_name_attributes *)tmp_na;
        apr_pool_userdata_setn(cfg, GSS_NAME_ATTR_USERDATA,
                               mag_name_attrs_cleanup, cfg->pool);
    }


    p = strchr(w, ' ');
    if (p == NULL) {
        if (strcmp(w, "json") == 0) {
            cfg->name_attributes->output_json = 1;
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                         "Invalid Name Attributes value [%s].", w);
        }
        return NULL;
    }

    c = cfg->name_attributes->map_count;
    cfg->name_attributes->map[c].env_name = apr_pstrndup(cfg->pool, w, p-w);
    p++;
    cfg->name_attributes->map[c].attr_name = apr_pstrdup(cfg->pool, p);
    cfg->name_attributes->map_count += 1;

    return NULL;
}
