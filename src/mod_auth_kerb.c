#ident "$Id$"

#ifndef APXS1
#include "ap_compat.h"
#include "apr_strings.h"
#endif
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#ifdef KRB5
#include <krb5.h>
#include <gssapi.h>
#endif /* KRB5 */

#ifdef KRB4
#include <krb.h>
#endif /* KRB4 */

#ifdef APXS1
module auth_kerb_module;
#else
module AP_MODULE_DECLARE_DATA auth_kerb_module;
#endif

/*************************************************************************** 
 Macros To Ease Compatibility
 ***************************************************************************/
#ifdef APXS1
#define MK_POOL pool
#define MK_TABLE_GET ap_table_get
#define MK_TABLE_SET ap_table_set
#define MK_TABLE_TYPE table
#define MK_PSTRDUP ap_pstrdup
#define MK_USER r->connection->user
#define MK_AUTH_TYPE r->connection->ap_auth_type
#define MK_ARRAY_HEADER array_header
#else
#define MK_POOL apr_pool_t
#define MK_TABLE_GET apr_table_get
#define MK_TABLE_SET apr_table_set
#define MK_TABLE_TYPE apr_table_t
#define MK_PSTRDUP apr_pstrdup
#define MK_USER r->user
#define MK_AUTH_TYPE r->ap_auth_type
#define MK_ARRAY_HEADER apr_array_header_t
#endif /* APXS1 */


/*************************************************************************** 
 Auth Configuration Structure
 ***************************************************************************/
typedef struct {
	char *krb_auth_realms;
	int krb_fail_status;
	char *krb_force_instance;
	int krb_save_credentials;
	char *service_name;
	char *krb_lifetime;
#ifdef KRB5
	char *krb_5_keytab;
	int krb_forwardable;
	int krb_method_gssapi;
	int krb_method_k5pass;
#endif
#ifdef KRB4
	char *krb_4_srvtab;
	int krb_method_k4pass;
#endif
} kerb_auth_config;

static const char*
krb5_save_realms(cmd_parms *cmd, kerb_auth_config *sec, char *arg);

#ifdef APXS1
#define command(name, func, var, type, usage) 		\
  { name, func, 					\
    (void*)XtOffsetOf(kerb_auth_config, var), 		\
    OR_AUTHCFG, type, usage }
#else
#define command(name, func, var, type, usage)		\
  AP_INIT_ ## type (name, func, 			\
	(void*)APR_XtOffsetOf(kerb_auth_config, var),	\
	OR_AUTHCFG, usage)
#endif

static const command_rec kerb_auth_cmds[] = {
   command("KrbAuthRealm", krb5_save_realms, krb_auth_realms,
     RAW_ARGS, "Realms to attempt authentication against (can be multiple)."),

   command("KrbAuthRealms", krb5_save_realms, krb_auth_realms,
     RAW_ARGS, "Alias for KrbAuthRealm."),

#if 0
   command("KrbFailStatus", kerb_set_fail_slot, krb_fail_status,
     TAKE1, "If auth fails, return status set here."),
#endif

   command("KrbForceInstance", ap_set_string_slot, krb_force_instance,
     TAKE1, "Force authentication against an instance specified here."),

   command("KrbSaveCredentials", ap_set_flag_slot, krb_save_credentials,
     FLAG, "Save and store credentials/tickets retrieved during auth."),

   command("KrbSaveTickets", ap_set_flag_slot, krb_save_credentials,
     FLAG, "Alias for KrbSaveCredentials."),

   command("KrbServiceName", ap_set_string_slot, service_name,
     TAKE1, "Kerberos service name to be used by apache."),

#if 0
   command("KrbLifetime", ap_set_string_slot, krb_lifetime,
     TAKE1, "Kerberos ticket lifetime."),
#endif

#ifdef KRB5
   command("Krb5Keytab", ap_set_file_slot, krb_5_keytab,
     TAKE1, "Location of Kerberos V5 keytab file."),

   command("KrbForwardable", ap_set_flag_slot, krb_forwardable,
     FLAG, "Credentials retrieved will be flagged as forwardable."),

   command("KrbMethodGSSAPI", ap_set_flag_slot, krb_method_gssapi,
     FLAG, "Enable GSSAPI authentication."),

   command("KrbMethodK5Pass", ap_set_flag_slot, krb_method_k5pass,
     FLAG, "Enable Kerberos V5 password authentication."),
#endif 

#ifdef KRB4
   command("Krb4Srvtab", ap_set_file_slot, krb_4_srvtab,
     TAKE1, "Location of Kerberos V4 srvtab file."),

   command("KrbMethodK4Pass", ap_set_flag_slot, krb_method_k4pass,
     FLAG, "Enable Kerberos V4 password authentication."),
#endif

   { NULL }
};

#ifdef KRB5
typedef struct {
   gss_ctx_id_t context;
   gss_cred_id_t server_creds;
} gss_connection_t;

static gss_connection_t *gss_connection = NULL;
#endif


/*************************************************************************** 
 Auth Configuration Initialization
 ***************************************************************************/
static void *kerb_dir_create_config(MK_POOL *p, char *d)
{
	kerb_auth_config *rec;

	rec = (kerb_auth_config *) ap_pcalloc(p, sizeof(kerb_auth_config));
	((kerb_auth_config *)rec)->krb_fail_status = HTTP_UNAUTHORIZED;
#ifdef KRB5
	((kerb_auth_config *)rec)->krb_method_k5pass = 1;
	((kerb_auth_config *)rec)->krb_method_gssapi = 1;
#endif
#ifdef KRB4
	((kerb_auth_config *)rec)->krb_method_k4pass = 1;
#endif
	return rec;
}

static const char*
krb5_save_realms(cmd_parms *cmd, kerb_auth_config *sec, char *arg)
{
   sec->krb_auth_realms= ap_pstrdup(cmd->pool, arg);
   return NULL;
}

void log_rerror(const char *file, int line, int level, int status,
                const request_rec *r, const char *fmt, ...)
{
   char errstr[1024];
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(errstr, sizeof(errstr), fmt, ap);
   va_end(ap);

#ifdef APXS1
   ap_log_rerror(file, line, level, r, "%s", errstr);
#else
   ap_log_rerror(file, line, level, status, r, "%s", errstr);
#endif
}

#if 0
static const char *kerb_set_fail_slot(cmd_parms *cmd, void *struct_ptr,
					const char *arg)
{
	int offset = (int) (long) cmd->info;
	if (!strncasecmp(arg, "unauthorized", 12))
		*(int *) ((char *)struct_ptr + offset) = HTTP_UNAUTHORIZED;
	else if (!strncasecmp(arg, "forbidden", 9))
		*(int *) ((char *)struct_ptr + offset) = HTTP_FORBIDDEN;
	else if (!strncasecmp(arg, "declined", 8))
		*(int *) ((char *)struct_ptr + offset) = DECLINED;
	else
		return "KrbAuthFailStatus must be Forbidden, Unauthorized, or Declined.";
	return NULL;
}
#endif

#ifdef KRB4
/*************************************************************************** 
 Username/Password Validation for Krb4
 ***************************************************************************/
int kerb4_password_validate(request_rec *r, const char *user, const char *pass)
{
	kerb_auth_config *conf =
		(kerb_auth_config *)ap_get_module_config(r->per_dir_config,
					&auth_kerb_module);
	int ret;
	int lifetime = DEFAULT_TKT_LIFE;
	char *c, *tfname;
	char *username = NULL;
	char *instance = NULL;
	char *realm = NULL;

	username = (char *)ap_pstrdup(r->pool, user);
	if (!username) {
		return 0;
	}

	instance = strchr(username, '.');
	if (instance) {
		*instance++ = '\0';
	}
	else {
		instance = "";
	}

	realm = strchr(username, '@');
	if (realm) {
		*realm++ = '\0';
	}
	else {
		realm = "";
	}

	if (conf->krb_lifetime) {
		lifetime = atoi(conf->krb_lifetime);
	}

	if (conf->krb_force_instance) {
		instance = conf->krb_force_instance;
	}

	if (conf->krb_save_credentials) {
		tfname = (char *)malloc(sizeof(char) * MAX_STRING_LEN);
		sprintf(tfname, "/tmp/k5cc_ap_%s", MK_USER);

		if (!strcmp(instance, "")) {
			tfname = strcat(tfname, ".");
			tfname = strcat(tfname, instance);
		}

		if (!strcmp(realm, "")) {
			tfname = strcat(tfname, ".");
			tfname = strcat(tfname, realm);
		}

		for (c = tfname + strlen("/tmp") + 1; *c; c++) {
			if (*c == '/')
				*c = '.';
		}

		krb_set_tkt_string(tfname);
	}

	if (!strcmp(realm, "")) {
		realm = (char *)malloc(sizeof(char) * (REALM_SZ + 1));
		ret = krb_get_lrealm(realm, 1);
		if (ret != KSUCCESS)
			return 0;
	}

	ret = krb_get_pw_in_tkt((char *)user, instance, realm, "krbtgt", realm,
					lifetime, (char *)pass);
	switch (ret) {
		case INTK_OK:
		case INTK_W_NOTALL:
			return 1;
			break;

		default:
			return 0;
			break;
	}
}
#endif /* KRB4 */

#ifdef KRB5
/*************************************************************************** 
 Username/Password Validation for Krb5
 ***************************************************************************/
#ifndef HEIMDAL
krb5_error_code
krb5_verify_user(krb5_context context, krb5_principal principal,
      		 krb5_ccache ccache, const char *password, krb5_boolean secure,
		 const char *service)
{
   int ret;
   krb5_context kcontext;
   krb5_principal server, client;
   krb5_timestamp now;
   krb5_creds my_creds;
   krb5_flags options = 0;
   krb5_principal me = NULL;
   krb5_data tgtname = {
      0,
      KRB5_TGS_NAME_SIZE,
      KRB5_TGS_NAME
   };

   memset((char *)&my_creds, 0, sizeof(my_creds));
   my_creds.client = principal;

   if (krb5_build_principal_ext(kcontext, &server,
	    			krb5_princ_realm(kcontext, me)->length,
				krb5_princ_realm(kcontext, me)->data,
				tgtname.length, tgtname.data,
				krb5_princ_realm(kcontext, me)->length,
				krb5_princ_realm(kcontext, me)->data,
				0)) {
	return ret;
   }

   my_creds.server = server;
   if (krb5_timeofday(kcontext, &now))
   	return -1;

   my_creds.times.starttime = 0;
   /* XXX
   my_creds.times.endtime = now + lifetime;
   my_creds.times.renew_till = now + renewal;
   */

   ret = krb5_get_in_tkt_with_password(kcontext, options, 0, NULL, 0,
	 			       password, ccache, &my_creds, 0);
   if (ret) {
   	return ret;
   }

   return 0;
}
#endif


static int
krb5_cache_cleanup(void *data)
{
   krb5_context context;
   krb5_ccache  cache;
   krb5_error_code problem;
   char *cache_name = (char *) data;

   problem = krb5_init_context(&context);
   if (problem) {
      /* ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "krb5_init_context() failed"); */
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   problem = krb5_cc_resolve(context, cache_name, &cache);
   if (problem) {
      /* log_error(APLOG_MARK, APLOG_ERR, 0, NULL, 
                "krb5_cc_resolve() failed (%s: %s)",
	        cache_name, krb5_get_err_text(context, problem)); */
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   krb5_cc_destroy(context, cache);
   krb5_free_context(context);
   return OK;
}

static int
create_krb5_ccache(krb5_context kcontext,
      		   request_rec *r,
		   kerb_auth_config *conf,
		   krb5_principal princ,
		   krb5_ccache *ccache)
{
   char *ccname;
   krb5_error_code problem;
   int ret;
   krb5_ccache tmp_ccache = NULL;

#ifdef HEIMDAL
   problem = krb5_cc_gen_new(kcontext, &krb5_fcc_ops, &tmp_ccache);
#else
   problem = krb5_fcc_generate_new(kcontext, &tmp_ccache);
#endif
   if (problem) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		 "Cannot create file for new krb5 ccache: %s",
		 krb5_get_err_text(kcontext, problem));
      ret = HTTP_INTERNAL_SERVER_ERROR;
      goto end;
   }

   ccname = ap_pstrdup(r->pool, krb5_cc_get_name(kcontext, tmp_ccache));

   problem = krb5_cc_initialize(kcontext, tmp_ccache, princ);
   if (problem) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		 "Cannot create krb5 ccache %s: krb5_cc_initialize() failed: %s",
		 ccname, krb5_get_err_text(kcontext, problem));
      ret = HTTP_INTERNAL_SERVER_ERROR;
      goto end;
   }

   ap_table_setn(r->subprocess_env, "KRB5CCNAME", ccname);
   ap_register_cleanup(r->pool, ccname,
		       krb5_cache_cleanup, ap_null_cleanup);

   *ccache = tmp_ccache;
   tmp_ccache = NULL;

   ret = OK;

end:
   if (tmp_ccache)
      krb5_cc_destroy(kcontext, tmp_ccache);

   return ret;
}

static int
store_krb5_creds(krb5_context kcontext,
      		 request_rec *r,
		 kerb_auth_config *conf,
		 krb5_ccache delegated_cred)
{
   char errstr[1024];
   krb5_error_code problem;
   krb5_principal princ;
   krb5_ccache ccache;
   int ret;

   problem = krb5_cc_get_principal(kcontext, delegated_cred, &princ);
   if (problem) {
      snprintf(errstr, sizeof(errstr), "krb5_cc_get_principal() failed: %s",
	       krb5_get_err_text(kcontext, problem));
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   ret = create_krb5_ccache(kcontext, r, conf, princ, &ccache);
   if (ret) {
      krb5_free_principal(kcontext, princ);
      return ret;
   }

   problem = krb5_cc_copy_cache(kcontext, delegated_cred, ccache);
   krb5_free_principal(kcontext, princ);
   if (problem) {
      snprintf(errstr, sizeof(errstr), "krb5_cc_copy_cache() failed: %s",
	       krb5_get_err_text(kcontext, problem));
      krb5_cc_destroy(kcontext, ccache);
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   krb5_cc_close(kcontext, ccache);
   return OK;
}


int authenticate_user_krb5pwd(request_rec *r,
	                      kerb_auth_config *conf,
			      const char *auth_line)
{
   const char      *sent_pw = NULL; 
   const char      *sent_name = NULL;
   const char      *realms = NULL;
   const char	   *service_name = NULL;
   krb5_context    kcontext = NULL;
   krb5_error_code code;
   krb5_principal  client = NULL;
   krb5_ccache     ccache = NULL;
   int             ret;
   char *name = NULL;

   code = krb5_init_context(&kcontext);
   if (code) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
    		 "Cannot initialize Kerberos5 context (%d)", code);
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   sent_pw = ap_pbase64decode(r->pool, auth_line);
   sent_name = ap_getword (r->pool, &sent_pw, ':');
   /* do not allow user to override realm setting of server */
   if (strchr(sent_name, '@')) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
  		 "specifying realm in user name is prohibited");
      ret = HTTP_UNAUTHORIZED;
      goto end;
   } 

#ifdef HEIMDAL
   code = krb5_cc_gen_new(kcontext, &krb5_mcc_ops, &ccache);
#else
   code = krb5_mcc_generate_new(kcontext, &ccache);
#endif
   if (code) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
	         "Cannot generate new ccache: %s",
		 krb5_get_err_text(kcontext, code));
      ret = HTTP_INTERNAL_SERVER_ERROR;
      goto end;
   }

   if (conf->krb_5_keytab)
      /* setenv("KRB5_KTNAME", conf->krb_5_keytab, 1); */
      kcontext->default_keytab = conf->krb_5_keytab;

   if (conf->service_name) {
      char *p;
      service_name = ap_pstrdup(r->pool, conf->service_name);
      if ((p=strchr(service_name, '/')))
	 *p = '\0';
   } else
      service_name = "khttp";

   realms = conf->krb_auth_realms;
   do {
      if (realms && (code = krb5_set_default_realm(kcontext,
	          		           ap_getword_white(r->pool, &realms))))
	 continue;

      if (client) {
	 krb5_free_principal(kcontext, client);
	 client = NULL;
      }
      code = krb5_parse_name(kcontext, sent_name, &client);
      if (code)
	 continue;

      code = krb5_verify_user(kcontext, client, ccache, sent_pw, 1, 
	    		      service_name);
      if (code == 0)
	 break;

      /* ap_getword_white() used above shifts the parameter, so it's not
         needed to touch the realms variable */
   } while (realms && *realms);

   memset((char *)sent_pw, 0, strlen(sent_pw));

   if (code) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "Verifying krb5 password failed: %s",
		 krb5_get_err_text(kcontext, code));
      ret = HTTP_UNAUTHORIZED;
      goto end;
   }

   code = krb5_unparse_name(kcontext, client, &name);
   if (code) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "krb5_unparse_name() failed: %s",
	         krb5_get_err_text(kcontext, code));
      ret = HTTP_UNAUTHORIZED;
      goto end;
   }
   MK_USER = ap_pstrdup (r->pool, name);
   MK_AUTH_TYPE = "Basic";
   free(name);

   if (conf->krb_save_credentials)
      store_krb5_creds(kcontext, r, conf, ccache);

   ret = OK;

end:
   if (client)
      krb5_free_principal(kcontext, client);
   if (ccache)
      krb5_cc_destroy(kcontext, ccache);
   krb5_free_context(kcontext);

   return ret;
}

/*********************************************************************
 * GSSAPI Authentication
 ********************************************************************/

static const char *
get_gss_error(MK_POOL *p, OM_uint32 error_status, char *prefix)
{
   OM_uint32 maj_stat, min_stat;
   OM_uint32 msg_ctx = 0;
   gss_buffer_desc status_string;
   char buf[1024];
   size_t len;

   snprintf(buf, sizeof(buf), "%s", prefix);
   len = strlen(buf);
   do {
      maj_stat = gss_display_status (&min_stat,
	                             error_status,
				     GSS_C_MECH_CODE,
				     GSS_C_NO_OID,
				     &msg_ctx,
				     &status_string);
      if (sizeof(buf) > len + status_string.length + 1) {
         sprintf(buf+len, ": %s", (char*) status_string.value);
         len += status_string.length;
      }
      gss_release_buffer(&min_stat, &status_string);
   } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);

   return (ap_pstrdup(p, buf));
}

static int
cleanup_gss_connection(void *data)
{
   OM_uint32 minor_status;
   gss_connection_t *gss_conn = (gss_connection_t *)data;

   if (data == NULL)
      return OK;
   if (gss_conn->context != GSS_C_NO_CONTEXT)
      gss_delete_sec_context(&minor_status, &gss_conn->context,
	                     GSS_C_NO_BUFFER);
   if (gss_conn->server_creds != GSS_C_NO_CREDENTIAL)
      gss_release_cred(&minor_status, &gss_conn->server_creds);

   return OK;
}

static int
store_gss_creds(request_rec *r, kerb_auth_config *conf, char *princ_name,
                gss_cred_id_t delegated_cred)
{
   OM_uint32 maj_stat, min_stat;
   krb5_principal princ = NULL;
   krb5_ccache ccache = NULL;
   krb5_error_code problem;
   krb5_context context;
   int ret = HTTP_INTERNAL_SERVER_ERROR;

   problem = krb5_init_context(&context);
   if (problem) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Cannot initialize krb5 context");
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   problem = krb5_parse_name(context, princ_name, &princ);
   if (problem) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
	 "Cannot parse delegated username (%s)", krb5_get_err_text(context, problem));
      goto end;
   }

   problem = create_krb5_ccache(context, r, conf, princ, &ccache);
   if (problem) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	 "Cannot create krb5 ccache (%s)", krb5_get_err_text(context, problem));
      goto end;
   }

   maj_stat = gss_krb5_copy_ccache(&min_stat, delegated_cred, ccache);
   if (GSS_ERROR(maj_stat)) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	 "Cannot store delegated credential (%s)", 
	 get_gss_error(r->pool, min_stat, "gss_krb5_copy_ccache"));
      goto end;
   }

   krb5_cc_close(context, ccache);
   ccache = NULL;
   ret = 0;

end:
   if (princ)
      krb5_free_principal(context, princ);
   if (ccache)
      krb5_cc_destroy(context, ccache);
   krb5_free_context(context);
   return ret;
}

static int
get_gss_creds(request_rec *r,
              kerb_auth_config *conf,
	      gss_cred_id_t *server_creds)
{
   gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
   OM_uint32 major_status, minor_status, minor_status2;
   gss_name_t server_name = GSS_C_NO_NAME;

   if (conf->service_name) {
      input_token.value = conf->service_name;
      input_token.length = strlen(conf->service_name) + 1;
   }
   else {
      input_token.value = "khttp";
      input_token.length = 6;
   }
   major_status = gss_import_name(&minor_status, &input_token,
			          (conf->service_name) ? 
			  	       GSS_C_NT_USER_NAME : GSS_C_NT_HOSTBASED_SERVICE,
				  &server_name);
   if (GSS_ERROR(major_status)) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "%s", get_gss_error(r->pool, minor_status,
		 "gss_import_name() failed"));
      return HTTP_INTERNAL_SERVER_ERROR;
   }
   
   major_status = gss_acquire_cred(&minor_status, server_name, GSS_C_INDEFINITE,
			           GSS_C_NO_OID_SET, GSS_C_ACCEPT,
				   server_creds, NULL, NULL);
   gss_release_name(&minor_status2, &server_name);
   if (GSS_ERROR(major_status)) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "%s", get_gss_error(r->pool, minor_status,
		 		     "gss_acquire_cred() failed"));
      return HTTP_INTERNAL_SERVER_ERROR;
   }
   
   return 0;
}

static int
authenticate_user_gss(request_rec *r,
      	 	      kerb_auth_config *conf,
		      const char *auth_line)
{
  OM_uint32 major_status, minor_status, minor_status2;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  const char *auth_param = NULL;
  int ret;
  gss_name_t client_name = GSS_C_NO_NAME;
  gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;

  if (gss_connection == NULL) {
     gss_connection = ap_pcalloc(r->connection->pool, sizeof(*gss_connection));
     if (gss_connection == NULL) {
	log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	           "ap_pcalloc() failed (not enough memory)");
	ret = HTTP_INTERNAL_SERVER_ERROR;
	goto end;
     }
     memset(gss_connection, 0, sizeof(*gss_connection));
     ap_register_cleanup(r->connection->pool, gss_connection, cleanup_gss_connection, ap_null_cleanup);
  }

  if (conf->krb_5_keytab)
     setenv("KRB5_KTNAME", conf->krb_5_keytab, 1);

  if (gss_connection->server_creds == GSS_C_NO_CREDENTIAL) {
     ret = get_gss_creds(r, conf, &gss_connection->server_creds);
     if (ret)
	goto end;
  }

  /* ap_getword() shifts parameter */
  auth_param = ap_getword_white(r->pool, &auth_line);
  if (auth_param == NULL) {
     log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	        "No Authorization parameter in request from client");
     ret = HTTP_UNAUTHORIZED;
     goto end;
  }

  input_token.length = ap_base64decode_len(auth_param) + 1;
  input_token.value = ap_pcalloc(r->connection->pool, input_token.length);
  if (input_token.value == NULL) {
     log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	   	"ap_pcalloc() failed (not enough memory)");
     ret = HTTP_INTERNAL_SERVER_ERROR;
     goto end;
  }
  input_token.length = ap_base64decode(input_token.value, auth_param);

  major_status = gss_accept_sec_context(&minor_status,
	                                &gss_connection->context,
					gss_connection->server_creds,
					&input_token,
					GSS_C_NO_CHANNEL_BINDINGS,
					&client_name,
					NULL,
					&output_token,
					NULL,
					NULL,
					&delegated_cred);
  if (output_token.length) {
     char *token = NULL;
     size_t len;
     
     len = ap_base64encode_len(output_token.length) + 1;
     token = ap_pcalloc(r->connection->pool, len + 1);
     if (token == NULL) {
	log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	           "ap_pcalloc() failed (not enough memory)");
        ret = HTTP_INTERNAL_SERVER_ERROR;
	gss_release_buffer(&minor_status2, &output_token);
	goto end;
     }
     ap_base64encode(token, output_token.value, output_token.length);
     token[len] = '\0';
     ap_table_set(r->err_headers_out, "WWW-Authenticate",
	          ap_pstrcat(r->pool, "GSS-Negotiate ", token, NULL));
     gss_release_buffer(&minor_status2, &output_token);
  }

  if (GSS_ERROR(major_status)) {
     log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	        "%s", get_gss_error(r->pool, minor_status,
		                    "gss_accept_sec_context() failed"));
     ret = HTTP_UNAUTHORIZED;
     goto end;
  }

  if (major_status & GSS_S_CONTINUE_NEEDED) {
     /* Some GSSAPI mechanism (eg GSI from Globus) may require multiple 
      * iterations to establish authentication */
     ret = HTTP_UNAUTHORIZED;
     goto end;
  }

  major_status = gss_display_name(&minor_status, client_name, &output_token, NULL);
  gss_release_name(&minor_status, &client_name); 
  if (GSS_ERROR(major_status)) {
    log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	       "%s", get_gss_error(r->pool, minor_status, 
		                   "gss_export_name() failed"));
    ret = HTTP_INTERNAL_SERVER_ERROR;
    goto end;
  }

  MK_AUTH_TYPE = "Negotiate";
  MK_USER = ap_pstrdup(r->pool, output_token.value);

  if (conf->krb_save_credentials && delegated_cred != GSS_C_NO_CREDENTIAL)
     store_gss_creds(r, conf, (char *)output_token.value, delegated_cred);

  gss_release_buffer(&minor_status, &output_token);


#if 0
  /* If the user comes from a realm specified by configuration don't include
      its realm name in the username so that the authorization routine could
      work for both Password-based and Ticket-based authentication. It's
      administrators responsibility to include only such realm that have
      unified principal instances, i.e. if the same principal name occures in
      multiple realms, it must be always assigned to a single user.
  */    
  p = strchr(r->connection->user, '@');
  if (p != NULL) {
     const char *realms = conf->gss_krb5_realms;

     while (realms && *realms) {
	if (strcmp(p+1, ap_getword_white(r->pool, &realms)) == 0) {
	   *p = '\0';
	   break;
	}
     }
  }
#endif

  ret = OK;

end:
  if (delegated_cred)
     gss_release_cred(&minor_status, &delegated_cred);

  if (output_token.length) 
     gss_release_buffer(&minor_status, &output_token);

  if (client_name != GSS_C_NO_NAME)
     gss_release_name(&minor_status, &client_name);

  return ret;
}
#endif /* KRB5 */


static void
note_kerb_auth_failure(request_rec *r, const kerb_auth_config *conf)
{
   const char *auth_name = NULL;

   /* get the user realm specified in .htaccess */
   auth_name = ap_auth_name(r);

   /* XXX check AuthType */

   /* XXX should the WWW-Authenticate header be cleared first? */
#ifdef KRB5
   if (conf->krb_method_gssapi)
      ap_table_add(r->err_headers_out, "WWW-Authenticate", "GSS-Negotiate ");
   if (conf->krb_method_k5pass)
      ap_table_add(r->err_headers_out, "WWW-Authenticate",
                   ap_pstrcat(r->pool, "Basic realm=\"", auth_name, "\"", NULL));
#endif

#ifdef KRB4
   if (conf->krb_method_k4pass)
      ap_table_add(r->err_headers_out, "WWW-Authenticate",
	    	   ap_pstrcat(r->pool, "Basic realm=\"", auth_name, "\"", NULL));
#endif
}

int kerb_authenticate_user(request_rec *r)
{
   kerb_auth_config *conf = 
      (kerb_auth_config *) ap_get_module_config(r->per_dir_config,
						&auth_kerb_module);
   const char *auth_type = NULL;
   const char *auth_line = NULL;
   const char *type = NULL;
   int use_krb5 = 0, use_krb4 = 0;
   int ret;

   /* get the type specified in .htaccess */
   type = ap_auth_type(r);

   if (type && strcasecmp(type, "Kerberos") == 0)
      use_krb5 = use_krb4 = 1;
   else if(type && strcasecmp(type, "KerberosV5") == 0)
      use_krb4 = 0;
   else if (type && strcasecmp(type, "KerberosV4") == 0)
      use_krb5 = 0;
   else
      return DECLINED;

   /* get what the user sent us in the HTTP header */
   auth_line = MK_TABLE_GET(r->headers_in, "Authorization");
   if (!auth_line) {
      note_kerb_auth_failure(r, conf);
      return HTTP_UNAUTHORIZED;
   }
   auth_type = ap_getword_white(r->pool, &auth_line);

   ret = HTTP_UNAUTHORIZED;

#ifdef KRB5
   if (use_krb5 && conf->krb_method_gssapi &&
       strcasecmp(auth_type, "GSS-Negotiate") == 0) {
      ret = authenticate_user_gss(r, conf, auth_line);
   } else if (use_krb5 && conf->krb_method_k5pass &&
	      strcasecmp(auth_type, "Basic") == 0) {
       ret = authenticate_user_krb5pwd(r, conf, auth_line);
   }
#endif

#ifdef KRB4
   if (ret == HTTP_UNAUTHORIZED && use_krb4 && conf->krb_method_k4pass &&
       strcasecmp(auth_type, "Basic") == 0)
      ret = authenticate_user_krb4pwd(r, conf, auth_line);
#endif

   if (ret == HTTP_UNAUTHORIZED)
      note_kerb_auth_failure(r, conf);

   return ret;
}


/*************************************************************************** 
 Module Setup/Configuration
 ***************************************************************************/
#ifdef APXS1
module MODULE_VAR_EXPORT auth_kerb_module = {
	STANDARD_MODULE_STUFF,
	NULL,				/*      module initializer            */
	kerb_dir_create_config,		/*      per-directory config creator  */
	NULL,				/*      per-directory config merger   */
	NULL,				/*      per-server    config creator  */
	NULL,				/*      per-server    config merger   */
	kerb_auth_cmds,			/*      command table                 */
	NULL,				/* [ 9] content handlers              */
	NULL,				/* [ 2] URI-to-filename translation   */
	kerb_authenticate_user,		/* [ 5] check/validate user_id        */
	NULL,				/* [ 6] check user_id is valid *here* */
	NULL,				/* [ 4] check access by host address  */
	NULL,				/* [ 7] MIME type checker/setter      */
	NULL,				/* [ 8] fixups                        */
	NULL,				/* [10] logger                        */
	NULL,				/* [ 3] header parser                 */
	NULL,				/*      process initialization        */
	NULL,				/*      process exit/cleanup          */
	NULL				/* [ 1] post read_request handling    */
};
#else
void kerb_register_hooks(apr_pool_t *p)
{
   ap_hook_check_user_id(kerb_authenticate_user, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_kerb_module =
{
   STANDARD20_MODULE_STUFF,
   kerb_dir_create_config,	/* create per-dir    conf structures  */
   NULL,			/* merge  per-dir    conf structures  */
   NULL,			/* create per-server conf structures  */
   NULL,			/* merge  per-server conf structures  */
   kerb_auth_cmds,		/* table of configuration directives  */
   kerb_register_hooks		/* register hooks                     */
};
#endif
