/*************************************************************************** 
 Included Headers And Module Declaration
 ***************************************************************************/
#ident "$Id$"

#ifdef APXS1
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

module kerb_auth_module;
#else
#ifdef APXS2
#include "apr_strings.h"
#include "apr_lib.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

module AP_MODULE_DECLARE_DATA kerb_auth_module;
#endif /* APXS2 */
#endif /* APXS1 */

#ifdef KRB5
#include <krb5.h>
#endif /* KRB5 */

#ifdef GSSAPI
#include <gssapi.h>
#endif /* GSSAPI */

#ifdef KRB4
#include <krb.h>
#endif /* KRB4 */




/*************************************************************************** 
 Macros To Ease Compatibility
 ***************************************************************************/
#ifdef APXS1
#define MK_POOL pool
#define MK_TABLE_GET ap_table_get
#define MK_TABLE_SET ap_table_set
#define MK_TABLE_TYPE table
#define MK_PSTRDUP ap_pstrdup
#define MK_PROXY STD_PROXY
#define MK_USER r->connection->user
#define MK_AUTH_TYPE r->connection->ap_auth_type
#define MK_ARRAY_HEADER array_header
#else
#ifdef APXS2
#define MK_POOL apr_pool_t
#define MK_TABLE_GET apr_table_get
#define MK_TABLE_SET apr_table_set
#define MK_TABLE_TYPE apr_table_t
#define MK_PSTRDUP apr_pstrdup
#define MK_PROXY PROXYREQ_PROXY
#define MK_USER r->user
#define MK_AUTH_TYPE r->ap_auth_type
#define MK_ARRAY_HEADER apr_array_header_t
#endif /* APXS2 */
#endif /* APXS1 */




/*************************************************************************** 
 Auth Configuration Structure
 ***************************************************************************/
typedef struct {
#ifdef KRB4
	char *krb_4_srvtab;
#endif /* KRB4 */
#ifdef KRB5
	char *krb_5_keytab;
#endif /* KRB5 */
	int krb_auth_enable;
	char *krb_auth_realms;
	int krb_authoritative;
	int krb_fail_status;
	char *krb_force_instance;
#ifdef KRB5
	int krb_forwardable;
#endif /* KRB5 */
	char *krb_lifetime;
#ifdef GSSAPI
	int krb_method_gssapi;
#endif /* GSSAPI */
#ifdef KRB4
	int krb_method_k4pass;
#endif /* KRB4 */
#ifdef KRB5
	int krb_method_k5pass;
	char *krb_renewable;
#endif /* KRB5 */
	int krb_save_credentials;
	char *krb_tmp_dir;
	char *service_name;
} kerb_auth_config;




/*************************************************************************** 
 GSSAPI Support Initialization
 ***************************************************************************/
#ifdef GSSAPI
typedef struct {
   gss_ctx_id_t context;
   gss_cred_id_t server_creds;
} gss_connection_t;

static gss_connection_t *gss_connection = NULL;

static void
cleanup_gss_connection(void *data)
{
   OM_uint32 minor_status;
   gss_connection_t *gss_conn = (gss_connection_t *)data;

   if (data == NULL)
      return;
   if (gss_conn->context != GSS_C_NO_CONTEXT)
      gss_delete_sec_context(&minor_status, &gss_conn->context,
	                     GSS_C_NO_BUFFER);
   if (gss_conn->server_creds != GSS_C_NO_CREDENTIAL)
      gss_release_cred(&minor_status, &gss_conn->server_creds);
}
#endif /* GSSAPI */




/*************************************************************************** 
 Auth Configuration Initialization
 ***************************************************************************/
static void *kerb_dir_config(MK_POOL *p, char *d)
{
	static void *rec;
	rec = (void *) ap_pcalloc(p, sizeof(kerb_auth_config));
	((kerb_auth_config *)rec)->krb_fail_status = HTTP_UNAUTHORIZED;
	((kerb_auth_config *)rec)->krb_authoritative = 0;
#ifdef GSSAPI
	((kerb_auth_config *)rec)->krb_method_gssapi = 0;
#endif /* GSSAPI */
#ifdef KRB4
	((kerb_auth_config *)rec)->krb_method_k4pass = 1;
#endif /* KRB4 */
#ifdef KRB5
	((kerb_auth_config *)rec)->krb_method_k5pass = 1;
#ifdef KRB4
	((kerb_auth_config *)rec)->krb_method_k4pass = 0;
#endif /* KRB4 */
#endif /* KRB5 */
	((kerb_auth_config *)rec)->krb_auth_realms = "";
	return rec;
}




/*************************************************************************** 
 Auth Configuration Parsers
 ***************************************************************************/
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




/*************************************************************************** 
 Auth Configuration Commands
 ***************************************************************************/
#ifdef APXS1
command_rec kerb_auth_cmds[] = {
	{
		"AuthKerberos",
		ap_set_flag_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_auth_enable),
		OR_AUTHCFG,
		FLAG,
		"Permit Kerberos auth without AuthType requirement."
	},

#ifdef KRB4
	{
		"Krb4Srvtab",
		ap_set_file_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_4_srvtab),
		RSRC_CONF & ACCESS_CONF,
		TAKE1,
		"Location of Kerberos V4 srvtab file."
	},
#endif /* KRB4 */

#ifdef KRB5
	{
		"Krb5Keytab",
		ap_set_file_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_5_keytab),
		RSRC_CONF & ACCESS_CONF,
		TAKE1,
		"Location of Kerberos V5 keytab file."
	},
#endif /* KRB5 */

	{
		"KrbAuthoritative",
		ap_set_flag_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_authoritative),
		OR_AUTHCFG,
		FLAG,
		"Refuse to pass request down to lower modules."
	},

	{
		"KrbAuthRealm",
		ap_set_string_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_auth_realms),
		OR_AUTHCFG,
		ITERATE,
		"Realms to attempt authentication against (can be multiple)."
	},

	{
		"KrbFailStatus",
		kerb_set_fail_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_fail_status),
		OR_AUTHCFG,
		TAKE1,
		"If auth fails, return status set here."
	},

	{
		"KrbForceInstance",
		ap_set_string_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_force_instance),
		OR_AUTHCFG,
		TAKE1,
		"Force authentication against an instance specified here."
	},

#ifdef KRB5
	{
		"KrbForwardable",
		ap_set_flag_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_forwardable),
		OR_AUTHCFG,
		FLAG,
		"Credentials retrieved will be flagged as forwardable."
	},
#endif /* KRB5 */

	{
		"KrbLifetime",
		ap_set_string_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_lifetime),
		OR_AUTHCFG,
		TAKE1,
		"Lifetime of tickets retrieved."
	},

#ifdef GSSAPI
	{
		"KrbMethodGSSAPI",
		ap_set_flag_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_method_gssapi),
		OR_AUTHCFG,
		FLAG,
		"Enable GSSAPI authentication."
	},
#endif /* GSSAPI */

#ifdef KRB4
	{
		"KrbMethodK4Pass",
		ap_set_flag_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_method_k4pass),
		OR_AUTHCFG,
		FLAG,
		"Enable Kerberos V4 password authentication."
	},
#endif /* KRB4 */

#ifdef KRB5
	{
		"KrbMethodK5Pass",
		ap_set_flag_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_method_k5pass),
		OR_AUTHCFG,
		FLAG,
		"Enable Kerberos V5 password authentication."
	},

	{
		"KrbRenewable",
		ap_set_string_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_renewable),
		OR_AUTHCFG,
		TAKE1,
		"Credentials retrieved will be renewable for this length."
	},
#endif /* KRB5 */

	{
		"KrbSaveCredentials",
		ap_set_flag_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_save_credentials),
		OR_AUTHCFG,
		FLAG,
		"Save and store credentials/tickets retrieved during auth."
	},

	{
		"KrbSaveTickets",
		ap_set_flag_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_save_credentials),
		OR_AUTHCFG,
		FLAG,
		"Alias for KrbSaveCredentials."
	},

	{
		"KrbTmpdir",
		ap_set_string_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_tmp_dir),
		RSRC_CONF & ACCESS_CONF,
		TAKE1,
		"Path to store ticket files and such in."
	},

	{ NULL }
};
#else
#ifdef APXS2
static const command_rec kerb_auth_cmds[] = {
	AP_INIT_FLAG(
		"AuthKerberos",
		kerb_set_type_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_auth_enable),
		OR_AUTHCFG,
		"Permit Kerberos auth without AuthType requirement."
	),

#ifdef KRB4
	AP_INIT_TAKE1(
		"Krb4Srvtab",
		ap_set_file_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_4_srvtab),
		RSRC_CONF & ACCESS_CONF,
		"Location of Kerberos V4 srvtab file."
	),
#endif /* KRB4 */

#ifdef KRB5
	AP_INIT_TAKE1(
		"Krb5Keytab",
		ap_set_file_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_5_keytab),
		RSRC_CONF & ACCESS_CONF,
		"Location of Kerberos V5 keytab file."
	),
#endif /* KRB5 */

	AP_INIT_FLAG(
		"KrbAuthoritative",
		ap_set_flag_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_authoritative),
		OR_AUTHCFG,
		"Refuse to pass request down to lower modules."
	),

	AP_INIT_ITERATE(
		"KrbAuthRealm",
		ap_set_string_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_auth_realms),
		OR_AUTHCFG,
		"Realm to attempt authentication against (can be multiple)."
	),

	AP_INIT_TAKE1(
		"KrbFailStatus",
		kerb_set_fail_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_fail_status),
		OR_AUTHCFG,
		"If auth fails, return status set here."
	),

	AP_INIT_TAKE1(
		"KrbForceInstance",
		ap_set_string_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_force_instance),
		OR_AUTHCFG,
		"Force authentication against an instance specified here."
	),

#ifdef KRB5
	AP_INIT_FLAG(
		"KrbForwardable",
		ap_set_flag_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_forwardable),
		OR_AUTHCFG,
		"Credentials retrieved will be flagged as forwardable."
	),
#endif /* KRB5 */

	AP_INIT_TAKE1(
		"KrbLifetime",
		ap_set_string_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_lifetime),
		OR_AUTHCFG,
		"Lifetime of tickets retrieved."
	),

#ifdef GSSAPI
	AP_INIT_FLAG(
		"KrbMethodGSSAPI",
		ap_set_flag_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_method_gssapi),
		OR_AUTHCFG,
		"Enable GSSAPI authentication."
	),
#endif /* GSSAPI */

#ifdef KRB4
	AP_INIT_FLAG(
		"KrbMethodK4Pass",
		ap_set_flag_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_method_k4pass),
		OR_AUTHCFG,
		"Enable Kerberos V4 password authentication."
	),
#endif /* KRB4 */

#ifdef KRB5
	AP_INIT_FLAG(
		"KrbMethodK5Pass",
		ap_set_flag_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_method_k5pass),
		OR_AUTHCFG,
		"Enable Kerberos V5 password authentication."
	),

	AP_INIT_TAKE1(
		"KrbRenewable",
		ap_set_string_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_renewable),
		OR_AUTHCFG,
		"Credentials retrieved will be renewable for this length."
	),
#endif /* KRB5 */

	AP_INIT_FLAG(
		"KrbSaveCredentials",
		ap_set_flag_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_save_credentials),
		OR_AUTHCFG,
		"Save and store credentials/tickets retrieved during auth."
	),

	AP_INIT_FLAG(
		"KrbSaveTickets",
		ap_set_flag_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_save_credentials),
		OR_AUTHCFG,
		"Alias for KrbSaveCredentials."
	),

	AP_INIT_TAKE1(
		"KrbTmpdir",
		ap_set_string_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_tmp_dir),
		RSRC_CONF & ACCESS_CONF,
		"Path to store ticket files and such in."
	),

	{ NULL }
};
#endif /* APXS2 */
#endif /* APXS1 */


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


/*************************************************************************** 
 Username/Password Validation
 ***************************************************************************/
#ifdef KRB5
static void
krb5_cache_cleanup(void *data)
{
   krb5_context context;
   krb5_ccache  cache;
   krb5_error_code problem;
   char *cache_name = (char *) data;

   problem = krb5_init_context(&context);
   if (problem) {
      ap_log_error(APLOG_MARK, APLOG_ERR, NULL, "krb5_init_context() failed");
      return;
   }

   problem = krb5_cc_resolve(context, cache_name, &cache);
   if (problem) {
      ap_log_error(APLOG_MARK, APLOG_ERR, NULL, 
                   "krb5_cc_resolve() failed (%s: %s)",
	           cache_name, krb5_get_err_text(context, problem)); 
      return;
   }

   krb5_cc_destroy(context, cache);
   krb5_free_context(context);
}

static int
store_krb5_creds(krb5_context kcontext,
      		 request_rec *r,
		 kerb_auth_config *conf,
		 krb5_ccache delegated_cred)
{
	char *c, ccname[MAX_STRING_LEN];
	krb5_error_code problem;
	char errstr[1024];
	int ret;
	krb5_ccache ccache = NULL;
	krb5_principal me = NULL;

	sprintf(ccname, "FILE:%s/k5cc_ap_%s",
  	        conf->krb_tmp_dir ? conf->krb_tmp_dir : "/tmp",
	        MK_USER);

	for (c = ccname + strlen(conf->krb_tmp_dir ? conf->krb_tmp_dir :
	     "/tmp") + 1; *c; c++) {
		if (*c == '/')
			*c = '.';
	  }

	problem = krb5_cc_set_default_name(kcontext, ccname);
	if (problem) {
		snprintf(errstr, sizeof(errstr),
			   "krb5_cc_set_default_name() failed: %s",
			   krb5_get_err_text(kcontext, problem));
		ap_log_reason (errstr, r->uri, r);
		ret = SERVER_ERROR;
		goto end;
	  }
#if 0
	  /* XXX Dan: Why is this done? Cleanup? But the file would not be 
	   * accessible from another processes (CGI) */
	  unlink(ccname+strlen("FILE:"));
#endif

	  problem = krb5_cc_resolve(kcontext, ccname, &ccache);
	  if (problem) {
		snprintf(errstr, sizeof(errstr),
			 "krb5_cc_resolve() failed: %s",
			 krb5_get_err_text(kcontext, problem));
		ap_log_reason (errstr, r->uri, r);
		ret = SERVER_ERROR;
		goto end;
	  }

	  problem = krb5_cc_get_principal(kcontext, delegated_cred, &me);
	  if (problem) {
		  snprintf(errstr, sizeof(errstr),
			   "krb5_cc_get_principal() failed: %s",
			   krb5_get_err_text(kcontext, problem));
		  ap_log_reason (errstr, r->uri, r);
		  ret = SERVER_ERROR;
		  goto end;
	  }

	  problem = krb5_cc_initialize(kcontext, ccache, me);
	  if (problem) {
	  	snprintf(errstr, sizeof(errstr),
		         "krb5_cc_initialize() failed: %s",
			 krb5_get_err_text(kcontext, problem));
		ap_log_reason (errstr, r->uri, r);
		ret = SERVER_ERROR;
		goto end;
	  }

	  problem = krb5_cc_copy_cache(kcontext, delegated_cred, ccache);
	  if (problem) {
	     snprintf(errstr, sizeof(errstr),
		      "krb5_cc_copy_cache failed: %s",
		      krb5_get_err_text(kcontext, problem));
	     ap_log_reason (errstr, r->uri, r);
	     ret = SERVER_ERROR;
	     goto end;
	  }
	  ap_table_setn(r->subprocess_env, "KRB5CCNAME", ccname);
	  ap_register_cleanup(r->pool, ccname,
			      krb5_cache_cleanup, ap_null_cleanup);

	  krb5_cc_close(kcontext, ccache);

	  ret = OK;

end:

	  return ret; /* XXX */
}

int kerb5_password_validate(request_rec *r, const char *user, const char *pass)
{

	kerb_auth_config *conf =
		(kerb_auth_config *)ap_get_module_config(r->per_dir_config,
					&kerb_auth_module);
	int ret;
	krb5_context kcontext;
	krb5_principal client;
	krb5_ccache ccache = NULL;
	krb5_deltat lifetime = 300;	/* 5 minutes */
	krb5_deltat renewal = 0;
	krb5_flags options = 0;
	char errstr[1024];
	krb5_error_code code;
	const char *realms;

	if (krb5_init_context(&kcontext)) {
	   	snprintf(errstr, sizeof(errstr),
		         "Cannot initialize Kerberos5 context");
		ap_log_reason (errstr, r->uri, r);
		ret = SERVER_ERROR;
		return 0;
	}

	if (conf->krb_forwardable) {
	   options |= KDC_OPT_FORWARDABLE;
	}

	if (conf->krb_renewable) {
	   options |= KDC_OPT_RENEWABLE;
	   renewal = 86400;        /* 24 hours */
	}

	if (conf->krb_lifetime) {
	   lifetime = atoi(conf->krb_lifetime);
	}

#ifdef HEIMDAL
	code = krb5_cc_gen_new(kcontext, &krb5_mcc_ops, &ccache);
#else
	code = krb5_mcc_generate_new(kcontext, &ccache);
#endif
	if (code) {
	   snprintf(errstr, sizeof(errstr), "Cannot generate new ccache: %.100s",
		    krb5_get_err_text(kcontext, code));
	   ap_log_reason (errstr, r->uri, r);
	   ret = SERVER_ERROR;
	   goto end;
	}

	realms = conf->krb_auth_realms;
	do {
	   code = 0;
	   if (realms) {
	      code = krb5_set_default_realm(kcontext, 
		    			    ap_getword_white(r->pool, &realms));
	      if (code)
		 continue;
	   }

	   code = krb5_parse_name(kcontext, r->connection->user, &client);
	   if (code)
	      continue;

	   code = krb5_verify_user(kcontext, client, ccache, pass,
		 		   1, "khttp");
	   krb5_free_principal(kcontext, client);
	   if (code == 0)
	      break;

	   /* ap_getword_white() used above shifts the parameter, so it's not
	      needed to touch the realms variable */
	} while (realms && *realms);

	memset((char *)pass, 0, strlen(pass));

	if (code) {
	   snprintf(errstr, sizeof(errstr), "Verifying krb5 password failed: %s",
		    krb5_get_err_text(kcontext, code));
	   ap_log_reason (errstr, r->uri, r);
	   ret = HTTP_UNAUTHORIZED;
	   goto end;
	}

	if (conf->krb_save_credentials) {
		ret = store_krb5_creds(kcontext, r, conf, ccache);
		if (ret)
			goto end;
	}

	ret = 1; /* XXX should be OK ? */

end:
	if (ccache)
	   krb5_cc_destroy(kcontext, ccache);
	krb5_free_context(kcontext);

	return (ret != 1) ? 0 : 1; /* XXX */
}
#endif /* KRB5 */

#ifdef KRB4
int kerb4_password_validate(request_rec *r, const char *user, const char *pass)
{
	kerb_auth_config *conf =
		(kerb_auth_config *)ap_get_module_config(r->per_dir_config,
					&kerb_auth_module);
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
		sprintf(tfname, "%s/k5cc_ap_%s",
			conf->krb_tmp_dir ? conf->krb_tmp_dir : "/tmp",
			MK_USER);

		if (!strcmp(instance, "")) {
			tfname = strcat(tfname, ".");
			tfname = strcat(tfname, instance);
		}

		if (!strcmp(realm, "")) {
			tfname = strcat(tfname, ".");
			tfname = strcat(tfname, realm);
		}

		for (c = tfname + strlen(conf->krb_tmp_dir ? conf->krb_tmp_dir :
				"/tmp") + 1; *c; c++) {
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




/*************************************************************************** 
 GSSAPI Validation
 ***************************************************************************/
#ifdef GSSAPI
static const char *
get_gss_error(pool *p, OM_uint32 error_status, char *prefix)
{
   OM_uint32 maj_stat, min_stat;
   OM_uint32 msg_ctx = 0;
   gss_buffer_desc status_string;
   char buf[1024];
   size_t len;

   snprintf(buf, sizeof(buf), "%s: ", prefix);
   len = strlen(buf);
   do {
      maj_stat = gss_display_status (&min_stat,
	                             error_status,
				     GSS_C_MECH_CODE,
				     GSS_C_NO_OID,
				     &msg_ctx,
				     &status_string);
      if (sizeof(buf) > len + status_string.length + 1) {
         sprintf(buf+len, "%s:", (char*) status_string.value);
         len += status_string.length;
      }
      gss_release_buffer(&min_stat, &status_string);
   } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);

   return (ap_pstrdup(p, buf));
}

static int
get_gss_creds(request_rec *r,
              kerb_auth_config *conf,
	      gss_cred_id_t *server_creds)
{
   int ret = 0;
   gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
   OM_uint32 major_status, minor_status;
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
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r,
	            "%s", get_gss_error(r->pool, minor_status,
		    "gss_import_name() failed"));
      ret = SERVER_ERROR;
      goto fail;
   }
   
#ifdef KRB5
   if (conf->krb_5_keytab)
      setenv("KRB5_KTNAME", conf->krb_5_keytab, 1);
#endif

   major_status = gss_acquire_cred(&minor_status, server_name, GSS_C_INDEFINITE,
			           GSS_C_NO_OID_SET, GSS_C_ACCEPT,
				   server_creds, NULL, NULL);
#ifdef KRB5
   if (conf->krb_5_keytab)
      unsetenv("KRB5_KTNAME");
#endif
   if (GSS_ERROR(major_status)) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r,
	           "%s", get_gss_error(r->pool, minor_status,
		 		       "gss_acquire_cred() failed"));
      ret = SERVER_ERROR;
      goto fail;
   }
   
   return 0;

fail:
   /* XXX cleanup */

   return ret;
}

static int
negotiate_authenticate_user(request_rec *r,
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
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
	              "ap_pcalloc() failed (not enough memory)");
	ret = SERVER_ERROR;
	goto end;
     }
     memset(gss_connection, 0, sizeof(*gss_connection));
     ap_register_cleanup(r->connection->pool, gss_connection, cleanup_gss_connection, ap_null_cleanup);
  }

  if (gss_connection->server_creds == GSS_C_NO_CREDENTIAL) {
     ret = get_gss_creds(r, conf, &gss_connection->server_creds);
     if (ret)
	goto end;
  }

  /* ap_getword() shifts parameter */
  auth_param = ap_getword_white(r->pool, &auth_line);
  if (auth_param == NULL) {
     ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
	           "No Authorization parameter in request from client");
     ret = HTTP_UNAUTHORIZED;
     goto end;
  }

  input_token.length = ap_base64decode_len(auth_param);
  input_token.value = ap_pcalloc(r->connection->pool, input_token.length);
  if (input_token.value == NULL) {
     ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
	   	   "ap_pcalloc() failed (not enough memory)");
     ret = SERVER_ERROR;
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
     
     len = ap_base64encode_len(output_token.length);
     token = ap_pcalloc(r->connection->pool, len + 1);
     if (token == NULL) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
	             "ap_pcalloc() failed (not enough memory)");
        ret = SERVER_ERROR;
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
     ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
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

  major_status = gss_export_name(&minor_status, client_name, &output_token);
  gss_release_name(&minor_status, &client_name); 
  if (GSS_ERROR(major_status)) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
	          "%s", get_gss_error(r->pool, minor_status, 
		                      "gss_export_name() failed"));
    ret = SERVER_ERROR;
    goto end;
  }

  r->connection->ap_auth_type = "Negotiate";
  r->connection->user = ap_pstrdup(r->pool, output_token.value);
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

  gss_release_buffer(&minor_status, &output_token);

#if 0
  /* This should be only done if afs token are requested or gss_save creds is 
   * specified */
  /* gss_export_cred() from the GGF GSS Extensions could be used */
  if (delegated_cred != GSS_C_NO_CREDENTIAL &&
      (conf->gss_save_creds || (conf->gss_krb5_cells && k_hasafs()))) {	
     krb5_init_context(&krb_ctx);
     do_afs_log(krb_ctx, r, delegated_cred->ccache, conf->gss_krb5_cells);
     ret = store_krb5_creds(krb_ctx, r, conf, delegated_cred->ccache);
     krb5_free_context(krb_ctx);
     if (ret)
	goto end;
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
#endif /* GSSAPI */




/*************************************************************************** 
 User Authentication
 ***************************************************************************/
int kerb_authenticate_user(request_rec *r)
{
	const char *name;		/* AuthName specified */
	const char *type;		/* AuthType specified */
	const char *sent_pw;		/* Password sent by browser */
	int res;			/* Response holder */
	int retcode;			/* Return code holder */
	const char *t;			/* Decoded auth_line */
	const char *authtype;		/* AuthType to send back to browser */
	const char *auth_line = MK_TABLE_GET(r->headers_in,
					(r->proxyreq == MK_PROXY)
						? "Proxy-Authorization"
						: "Authorization");
	kerb_auth_config *conf =
		(kerb_auth_config *)ap_get_module_config(r->per_dir_config,
					&kerb_auth_module);

	type = ap_auth_type(r);

	if (!conf->krb_auth_enable &&
	    (type == NULL || (strncasecmp(type, "Kerberos", 8) != 0))) {
		if (conf->krb_authoritative) {
			return HTTP_UNAUTHORIZED;
		}
		else {
			return DECLINED;
		}
	}

	name = ap_auth_name(r);
	if (!name) {
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (!auth_line) {
		MK_TABLE_SET(r->err_headers_out, "WWW-Authenticate",
			(char *)ap_pstrcat(r->pool,
			"Basic realm=\"", name, "\"", NULL));
		return HTTP_UNAUTHORIZED;
	}

	type = ap_getword_white(r->pool, &auth_line);
	t = ap_pbase64decode(r->pool, auth_line);
	MK_USER = ap_getword_nulls(r->pool, &t, ':');
	MK_AUTH_TYPE = "Kerberos";
	sent_pw = ap_getword_white(r->pool, &t);

	retcode = DECLINED;

#ifdef GSSAPI
	if (conf->krb_method_gssapi && retcode != OK) {
		MK_AUTH_TYPE = "Negotiate";
		if (negotiate_authenticate_user(r, conf, auth_line))
			retcode = OK;
		else
			retcode = conf->krb_fail_status;
	}
#endif /* GSSAPI */

#ifdef KRB5
	if (conf->krb_method_k5pass && retcode != OK) {
		MK_AUTH_TYPE = "KerberosV5";
		if (kerb5_password_validate(r, MK_USER, sent_pw)) {
			retcode = OK;
		}
		else {
			retcode = conf->krb_fail_status;
			/* XXX should SERVER_ERROR be overriden too? */
		}
	}
#endif /* KRB5 */

#ifdef KRB4
	if (conf->krb_method_k4pass && retcode != OK) {
		MK_AUTH_TYPE = "KerberosV4";
		if (kerb4_password_validate(r, MK_USER, sent_pw)) {
			retcode = OK;
		}
		else {
			retcode = conf->krb_fail_status;
		}
	}
#endif /* KRB4 */

	if (conf->krb_authoritative && retcode == DECLINED) {
		return HTTP_UNAUTHORIZED;
	}
	else {
		return retcode;
	}
}




/*************************************************************************** 
 Access Verification
 ***************************************************************************/
int kerb_check_user_access(request_rec *r)
{
	register int x;
	const char *t, *w;
	const MK_ARRAY_HEADER *reqs_arr = ap_requires(r);
	require_line *reqs;
	kerb_auth_config *conf =
		(kerb_auth_config *)ap_get_module_config(r->per_dir_config,
						&kerb_auth_module);

	if (reqs_arr == NULL) {
		return OK;
	}
	reqs = (require_line *)reqs_arr->elts;

	for (x = 0; x < reqs_arr->nelts; x++) {
		t = reqs[x].requirement;
		w = ap_getword_white(r->pool, &t);
		if (strcmp(w, "realm") == 0) {
			while (t[0] != '\0') {
				w = ap_getword_conf(r->pool, &t);
				if (strcmp(MK_USER, w) == 0) {
					return OK;
				}
			}
		}
	}

	return DECLINED;
}




/*************************************************************************** 
 Module Setup/Configuration
 ***************************************************************************/
#ifdef APXS1
module MODULE_VAR_EXPORT kerb_auth_module = {
	STANDARD_MODULE_STUFF,
	NULL,				/*      module initializer            */
	kerb_dir_config,		/*      per-directory config creator  */
	NULL,				/*      per-directory config merger   */
	NULL,				/*      per-server    config creator  */
	NULL,				/*      per-server    config merger   */
	kerb_auth_cmds,			/*      command table                 */
	NULL,				/* [ 9] content handlers              */
	NULL,				/* [ 2] URI-to-filename translation   */
	kerb_authenticate_user,		/* [ 5] check/validate user_id        */
	kerb_check_user_access,		/* [ 6] check user_id is valid *here* */
	NULL,				/* [ 4] check access by host address  */
	NULL,				/* [ 7] MIME type checker/setter      */
	NULL,				/* [ 8] fixups                        */
	NULL,				/* [10] logger                        */
	NULL,				/* [ 3] header parser                 */
	NULL,				/*      process initialization        */
	NULL,				/*      process exit/cleanup          */
	NULL				/* [ 1] post read_request handling    */
#ifdef EAPI
	,				/*            EAPI Additions          */
	NULL,				/* EAPI add module                    */
	NULL,				/* EAPI remove module                 */
	NULL,				/* EAPI rewrite command               */
	NULL				/* EAPI new connection                */
#endif /* EAPI */
};
#else
#ifdef APXS2
void kerb_register_hooks(apr_pool_t *p)
{
	ap_hook_check_user_id(kerb_authenticate_user, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_access_checker(kerb_check_user_access, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA kerb_auth_module =
{
	STANDARD20_MODULE_STUFF,
	kerb_dir_config,		/* create per-dir    conf structures  */
	NULL,				/* merge  per-dir    conf structures  */
	NULL,				/* create per-server conf structures  */
	NULL,				/* merge  per-server conf structures  */
	kerb_auth_cmds,			/* table of configuration directives  */
	kerb_register_hooks		/* register hooks                     */
};
#endif /* APXS2 */
#endif /* APXS1 */
