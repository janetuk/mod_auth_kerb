/*************************************************************************** 
 Included Headers And Module Declaration
 ***************************************************************************/
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
#define MK_RERROR_LEVEL ""
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
#define MK_RERROR_LEVEL "0, "
#define MK_USER r->user
#define MK_AUTH_TYPE r->ap_auth_type
#define MK_ARRAY_HEADER apr_array_header_t
#endif /* APXS2 */
#endif /* APXS1 */




/*************************************************************************** 
 Auth Configuration Structure
 ***************************************************************************/
typedef struct {
	char *krb_auth_type;
#ifdef KRB4
	char *krb_4_srvtab;
#endif /* KRB4 */
#ifdef KRB5
	char *krb_5_keytab;
#endif /* KRB5 */
	int krb_authoritative;
	char *krb_default_realm;
	int krb_fail_status;
	char *krb_force_instance;
#ifdef KRB5
	int krb_forwardable;
#endif /* KRB5 */
	char *krb_lifetime;
#ifdef KRB5
	char *krb_renewable;
#endif /* KRB5 */
	int krb_save_credentials;
	char *krb_tmp_dir;
} kerb_auth_config;




/*************************************************************************** 
 Auth Configuration Initialization
 ***************************************************************************/
static void *kerb_dir_config(AP_POOL *p, char *d)
{
	static void *rec;
	rec = (void *) ap_pcalloc(p, sizeof(kerb_auth_config));
	((kerb_auth_config *)rec)->krb_fail_status = HTTP_UNAUTHORIZED;
	((kerb_auth_config *)rec)->krb_authoritative = 0;
	((kerb_auth_config *)rec)->krb_auth_type = MK_PSTRDUP(p, "None");
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

/* these are either char *struct_ptr, char *arg or void *struct_ptr, const char *arg */
static const char *kerb_set_type_slot(cmd_parms *cmd, void *struct_ptr,
					const char *arg)
{
	int offset = (int) (long) cmd->info;
	if
#ifdef KRB5
	   (!strncasecmp(arg, "v5", 2))
		*(char **) ((char *)struct_ptr + offset) = MK_PSTRDUP(cmd->pool, "KerberosV5");
	else if
#endif /* KRB5 */
#ifdef KRB4
	   (!strncasecmp(arg, "v4", 2))
		*(char **) ((char *)struct_ptr + offset) = MK_PSTRDUP(cmd->pool, "KerberosV4");
#endif /* KRB4 */
	else if
	   (!strncasecmp(arg, "dualv5v4", 8))
		*(char **) ((char *)struct_ptr + offset) = MK_PSTRDUP(cmd->pool, "KerberosDualV5V4");
	else if
	   (!strncasecmp(arg, "dualv4v5", 8))
		*(char **) ((char *)struct_ptr + offset) = MK_PSTRDUP(cmd->pool, "KerberosDualV4V5");
#if defined(KRB4) && defined(KRB5)
#endif /* KRB4 && KRB5 */
	else
		return "AuthKerberos must be V5, V4, DualV4V5, or DualV5V4.";
	return NULL;
}




/*************************************************************************** 
 Auth Configuration Commands
 ***************************************************************************/
#ifdef APXS1
command_rec kerb_auth_cmds[] = {
	{
		"AuthKerberos",
		kerb_set_type_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_auth_type),
		OR_AUTHCFG,
		TAKE1,
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
		"KrbDefaultRealm",
		ap_set_string_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_default_realm),
		OR_AUTHCFG,
		TAKE1,
		"Default realm to authenticate users against."
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

#ifdef KRB5
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
		OR_AUTHCFG,
		TAKE1,
		"Path to store ticket files and such in."
	},

	{ NULL }
};
#else
#ifdef APXS2
static const command_rec kerb_auth_cmds[] = {
	AP_INIT_TAKE1(
		"AuthKerberos",
		kerb_set_type_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_auth_type),
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

	AP_INIT_TAKE1(
		"KrbDefaultRealm",
		ap_set_string_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_default_realm),
		OR_AUTHCFG,
		"Default realm to authenticate users against."
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

#ifdef KRB5
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
		OR_AUTHCFG,
		"Path to store ticket files and such in."
	),

	{ NULL }
};
#endif /* APXS2 */
#endif /* APXS1 */




/*************************************************************************** 
 Username/Password Validation
 ***************************************************************************/
#ifdef KRB5
int kerb5_password_validate(const char *user, const char *pass) {
	int ret;
	krb5_context kcontext;
	krb5_principal server, me;
	krb5_creds my_creds;
	krb5_timestamp now;
	krb5_deltat lifetime = 0;
	krb5_data tgtname = {
		0,
		KRB5_TGS_NAME_SIZE,
		KRB5_TGS_NAME
	};

	if (krb5_init_context(&kcontext))
		return 0;

	memset((char *)&my_creds, 0, sizeof(my_creds));
	if(krb5_parse_name(kcontext, user, &me))
		return 0;
	my_creds.client = me;

	if (krb5_build_principal_ext(kcontext, &server,
				krb5_princ_realm(kcontext, me)->length,
				krb5_princ_realm(kcontext, me)->data,
				tgtname.length, tgtname.data,
				krb5_princ_realm(kcontext, me)->length,
				krb5_princ_realm(kcontext, me)->data,
				0)) {
		return 0;
	}
	my_creds.server = server;
	if (krb5_timeofday(kcontext, &now))
		return 0;
	my_creds.times.starttime = 0;
	my_creds.times.endtime = now + lifetime;
	my_creds.times.renew_till = 0;

	ret = krb5_get_in_tkt_with_password(kcontext, 0, 0, NULL, 0,
				pass, NULL, &my_creds, 0);
	if (ret) {
		return 0;
	}

	krb5_free_cred_contents(kcontext, &my_creds);

	return 1;
}
#endif /* KRB5 */

#ifdef KRB4
int kerb4_password_validate(const char *user, const char *pass) {
	int ret;
	char realm[REALM_SZ];

	ret = krb_get_lrealm(realm, 1);
	if (ret != KSUCCESS)
		return !KRB4_OK;

	ret = krb_get_pw_in_tkt((char *)user, "", realm, "krbtgt", realm,
					DEFAULT_TKT_LIFE, (char *)pass);
	switch (ret) {
		case INTK_OK:
		case INTK_W_NOTALL:
			return KRB4_OK;
			break;

		default:
			return !KRB4_OK;
			break;
	}
}
#endif /* KRB4 */




/*************************************************************************** 
 User Authentication
 ***************************************************************************/
int kerb_authenticate_user(request_rec *r) {
	const char *name;		/* AuthName specified */
	const char *type;		/* AuthType specified */
	int KerberosV5 = 0;		/* Kerberos V5 check enabled */
	int KerberosV4 = 0;		/* Kerberos V4 check enabled */
	int KerberosV4first = 0;	/* Kerberos V4 check first */
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

	if (type != NULL) {
#ifdef KRB5
		if ((strncasecmp(type, "KerberosV5", 10) == 0) ||
		    (strncasecmp(conf->krb_auth_type, "KerberosV5", 10) == 0)) {
			KerberosV5 = 1;
		}
#endif /* KRB5 */

#ifdef KRB4
		if ((strncasecmp(type, "KerberosV4", 10) == 0) ||
		    (strncasecmp(conf->krb_auth_type, "KerberosV4", 10) == 0)) {
			KerberosV4 = 1;
		}
#endif /* KRB4 */

#if defined(KRB5) && defined(KRB4)
		if ((strncasecmp(type, "KerberosDualV5V4", 15) == 0) ||
		    (strncasecmp(conf->krb_auth_type, "KerberosDualV5V4", 15) == 0)) {
			KerberosV5 = 1;
			KerberosV4 = 1;
		}

		if ((strncasecmp(type, "KerberosDualV4V5", 15) == 0) ||
		    (strncasecmp(conf->krb_auth_type, "KerberosDualV4V5", 15) == 0)) {
			KerberosV5 = 1;
			KerberosV4 = 1;
			KerberosV4first = 1;
		}
#endif /* KRB5 && KRB4 */
	}

	if (!KerberosV4 && !KerberosV5) {
		if (conf->krb_authoritative) {
			return HTTP_UNAUTHORIZED;
		}
		else {
			return DECLINED;
		}
	}

	name = ap_auth_name(r);
	if (!name) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
				MK_RERROR_LEVEL "need AuthName: %s", r->uri);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (!auth_line) {
		MK_TABLE_SET(r->err_headers_out, "WWW-Authenticate",
			ap_pstrcat(r->pool, "Basic realm=\"", name, "\"", NULL));
		return HTTP_UNAUTHORIZED;
	}

	type = ap_getword_white(r->pool, &auth_line);
	t = ap_pbase64decode(r->pool, auth_line);
	MK_USER = ap_getword_nulls(r->pool, &t, ':');
	MK_AUTH_TYPE = "Kerberos";
	sent_pw = ap_getword_white(r->pool, &t);

	retcode = DECLINED;

#ifdef KRB5
	if (KerberosV5 && !KerberosV4first && retcode != OK) {
		MK_AUTH_TYPE = "KerberosV5";
		if (kerb5_password_validate(MK_USER, sent_pw)) {
			retcode = OK;
		}
		else {
			retcode = conf->krb_fail_status;
		}
	}
#endif /* KRB5 */

#ifdef KRB4
	if (KerberosV4 && retcode != OK) {
		MK_AUTH_TYPE = "KerberosV4";
		if (kerb4_password_validate(MK_USER, sent_pw)) {
			retcode = OK;
		}
		else {
			retcode = conf->krb_fail_status;
		}
	}
#endif /* KRB4 */

#if defined(KRB5) && defined(KRB4)
	if (KerberosV5 && KerberosV4first && retcode != OK) {
		MK_AUTH_TYPE = "KerberosV5"
		if (kerb5_password_validate(MK_USER, sent_pw)) {
			retcode = OK;
		}
		else {
			retcode = conf->krb_fail_status;
		}
	}
#endif /* KRB5 && KRB4 */

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
int check_user_access(request_rec *r) {
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
