/*
 * Daniel Kouril <kouril@users.sourceforge.net>
 *
 * Source and Documentation can be found at:
 * http://modauthkerb.sourceforge.net/
 *
 * Based on work by
 *   James E. Robinson, III <james@ncstate.net>
 *   Daniel Henninger <daniel@ncsu.edu>
 *   Ludek Sulak <xsulak@fi.muni.cz>
 */

/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#ident "$Id$"

#include "config.h"

#define MODAUTHKERB_VERSION "5.0-rc4"

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
#ifdef HEIMDAL
#  include <gssapi.h>
#else
#  include <gssapi/gssapi.h>
#  include <gssapi/gssapi_generic.h>
#  define GSS_C_NT_USER_NAME gss_nt_user_name
#  define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  define krb5_get_err_text(context,code) error_message(code)
#endif
#include "spnegokrb5.h"
#endif /* KRB5 */

#ifdef KRB4
/*Prevent warning about closesocket redefinition (Apache's ap_config.h and 
 * MIT Kerberos' port-sockets.h both define it as close) */
#ifdef closesocket
#  undef closesocket
#endif
#include <krb.h>
#include <netdb.h> /* gethostbyname() */
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
#define MK_USER r->connection->user
#define MK_AUTH_TYPE r->connection->ap_auth_type
#else
#define MK_POOL apr_pool_t
#define MK_TABLE_GET apr_table_get
#define MK_USER r->user
#define MK_AUTH_TYPE r->ap_auth_type
#endif /* APXS1 */


/*************************************************************************** 
 Auth Configuration Structure
 ***************************************************************************/
typedef struct {
	char *krb_auth_realms;
	int krb_save_credentials;
	int krb_verify_kdc;
	char *krb_service_name;
	int krb_authoritative;
#ifdef KRB5
	char *krb_5_keytab;
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
   command("KrbAuthRealms", krb5_save_realms, krb_auth_realms,
     RAW_ARGS, "Realms to attempt authentication against (can be multiple)."),

   command("KrbAuthRealm", krb5_save_realms, krb_auth_realms,
     RAW_ARGS, "Alias for KrbAuthRealms."),

   command("KrbSaveCredentials", ap_set_flag_slot, krb_save_credentials,
     FLAG, "Save and store credentials/tickets retrieved during auth."),

   command("KrbVerifyKDC", ap_set_flag_slot, krb_verify_kdc,
     FLAG, "Verify tickets against keytab to prevent KDC spoofing attacks."),

   command("KrbServiceName", ap_set_string_slot, krb_service_name,
     TAKE1, "Service name to be used by Apache for authentication."),

   command("KrbAuthoritative", ap_set_flag_slot, krb_authoritative,
     FLAG, "Set to 'off' to allow access control to be passed along to lower modules if the UserID is not known to this module."),

#ifdef KRB5
   command("Krb5Keytab", ap_set_file_slot, krb_5_keytab,
     TAKE1, "Location of Kerberos V5 keytab file."),

   command("KrbMethodNegotiate", ap_set_flag_slot, krb_method_gssapi,
     FLAG, "Enable Negotiate authentication method."),

   command("KrbMethodK5Passwd", ap_set_flag_slot, krb_method_k5pass,
     FLAG, "Enable Kerberos V5 password authentication."),
#endif 

#ifdef KRB4
   command("Krb4Srvtab", ap_set_file_slot, krb_4_srvtab,
     TAKE1, "Location of Kerberos V4 srvtab file."),

   command("KrbMethodK4Passwd", ap_set_flag_slot, krb_method_k4pass,
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

static const char *EMPTY_STRING = "\0";
#endif


/*************************************************************************** 
 Auth Configuration Initialization
 ***************************************************************************/
static void *kerb_dir_create_config(MK_POOL *p, char *d)
{
	kerb_auth_config *rec;

	rec = (kerb_auth_config *) ap_pcalloc(p, sizeof(kerb_auth_config));
        ((kerb_auth_config *)rec)->krb_verify_kdc = 1;
	((kerb_auth_config *)rec)->krb_service_name = "HTTP";
	((kerb_auth_config *)rec)->krb_authoritative = 1;
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
   char errnostr[1024];
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(errstr, sizeof(errstr), fmt, ap);
   va_end(ap);

   errnostr[0] = '\0';
   if (errno)
      snprintf(errnostr, sizeof(errnostr), "%s: (%s)", errstr, strerror(errno));
   else
      snprintf(errnostr, sizeof(errnostr), "%s", errstr);
   
#ifdef APXS1
   ap_log_rerror(file, line, level | APLOG_NOERRNO, r, "%s", errnostr);
#else
   ap_log_rerror(file, line, level | APLOG_NOERRNO, status, r, "%s", errnostr);
#endif
}

#ifdef KRB4
/*************************************************************************** 
 Username/Password Validation for Krb4
 ***************************************************************************/
static int
verify_krb4_user(request_rec *r, char *name, char *instance, char *realm,
      		 char *password, char *linstance, char *srvtab, int krb_verify_kdc)
{
   int ret;
   char *phost;
   unsigned long addr;
   struct hostent *hp;
   const char *hostname;
   KTEXT_ST ticket;
   AUTH_DAT authdata;
   char lrealm[REALM_SZ];

   ret = krb_get_pw_in_tkt(name, instance, realm, "krbtgt", realm, 
	 		   DEFAULT_TKT_LIFE, password);
   if (ret) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "Cannot get krb4 ticket: krb_get_pw_in_tkt() failed: %s",
		 krb_get_err_text(ret));
      return ret;
   }

   if (!krb_verify_kdc)
      return ret;

   hostname = ap_get_server_name(r);

   hp = gethostbyname(hostname);
   if (hp == NULL) {
      dest_tkt();
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "Cannot verify krb4 ticket: gethostbyname() failed: %s",
		 hstrerror(h_errno));
      return h_errno;
   }
   memcpy(&addr, hp->h_addr, sizeof(addr));

   phost = krb_get_phost((char *)hostname);

   krb_get_lrealm(lrealm, 1);

   ret = krb_mk_req(&ticket, linstance, phost, lrealm, 0);
   if (ret) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "Cannot verify krb4 ticket: krb_mk_req() failed: %s",
		 krb_get_err_text(ret));
      dest_tkt();
      return ret;
   }

   ret = krb_rd_req(&ticket, linstance, phost, addr, &authdata, srvtab);
   if (ret) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "Cannot verify krb4 ticket: krb_rd_req() failed: %s",
		 krb_get_err_text(ret));
      dest_tkt();
   }

   return ret;
}

static int
krb4_cache_cleanup(void *data)
{
   char *tkt_file = (char *) data;
   
   krb_set_tkt_string(tkt_file);
   dest_tkt();
   return OK;
}

static int 
authenticate_user_krb4pwd(request_rec *r,
      			  kerb_auth_config *conf,
			  const char *auth_line)
{
   int ret;
   const char *sent_pw;
   const char *sent_name;
   char *sent_instance;
   char tkt_file[32];
   char *tkt_file_p = NULL;
   int fd;
   const char *realms;
   const char *realm;
   char *user;
   char lrealm[REALM_SZ];
   int all_principals_unkown;

   sent_pw = ap_pbase64decode(r->pool, auth_line);
   sent_name = ap_getword (r->pool, &sent_pw, ':');

   /* do not allow user to override realm setting of server */
   if (strchr(sent_name, '@')) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "specifying realm in user name is prohibited");
      return HTTP_UNAUTHORIZED;
   }

   sent_instance = strchr(sent_name, '.');
   if (sent_instance)
      *sent_instance++ = '\0'; 

   snprintf(tkt_file, sizeof(tkt_file), "/tmp/apache_tkt_XXXXXX");
   fd = mkstemp(tkt_file);
   if (fd < 0) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "Cannot create krb4 ccache: mkstemp() failed: %s",
		 strerror(errno));
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   tkt_file_p = ap_pstrdup(r->pool, tkt_file);
   ap_register_cleanup(r->pool, tkt_file_p,
	               krb4_cache_cleanup, ap_null_cleanup);

   krb_set_tkt_string(tkt_file);

   all_principals_unkown = 1;
   realms = conf->krb_auth_realms;
   do {
      memset(lrealm, 0, sizeof(lrealm));
      realm = NULL;
      if (realms)
	 realm = ap_getword_white(r->pool, &realms);

      if (realm == NULL) {
	 ret = krb_get_lrealm(lrealm, 1);
	 if (ret)
	    break;
	 realm = lrealm;
      }

      ret = verify_krb4_user(r, (char *)sent_name, 
	                     (sent_instance) ? sent_instance : "",
	    		     (char *)realm, (char *)sent_pw,
			     conf->krb_service_name,
			     conf->krb_4_srvtab, conf->krb_verify_kdc);
      if (!conf->krb_authoritative && ret) {
	 /* if we're not authoritative, we allow authentication to pass on
	  * to another modules if (and only if) the user is not known to us */
	 if (all_principals_unkown && ret != KDC_PR_UNKNOWN)
	    all_principals_unkown = 0;
      }

      if (ret == 0)
	 break;
   } while (realms && *realms);

   if (ret) {
      /* XXX log only in the verify_krb4_user() call */
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Verifying krb4 password failed");
      ret = (!conf->krb_authoritative && all_principals_unkown == 1 && ret == KDC_PR_UNKNOWN) ?
	         DECLINED : HTTP_UNAUTHORIZED;
      goto end;
   }

   user = ap_pstrdup(r->pool, sent_name);
   if (sent_instance)
      user = ap_pstrcat(r->pool, user, ".", sent_instance, NULL);
   user = ap_pstrcat(r->pool, user, "@", realm, NULL);

   MK_USER = user;
   MK_AUTH_TYPE = "Basic";
   ap_table_setn(r->subprocess_env, "KRBTKFILE", tkt_file_p);

   if (!conf->krb_save_credentials)
      krb4_cache_cleanup(tkt_file);

end:
   if (ret)
      krb4_cache_cleanup(tkt_file);
   close(fd);
   tf_close();

   return ret;
}
#endif /* KRB4 */

#ifdef KRB5
/*************************************************************************** 
 Username/Password Validation for Krb5
 ***************************************************************************/
/* Inspired by krb5_verify_user from Heimdal */
static krb5_error_code
verify_krb5_user(request_rec *r, krb5_context context, krb5_principal principal,
      		 krb5_ccache ccache, const char *password, const char *service,
		 krb5_keytab keytab, int krb_verify_kdc)
{
   krb5_creds creds;
   krb5_principal server = NULL;
   krb5_error_code ret;
   krb5_verify_init_creds_opt opt;

   memset(&creds, 0, sizeof(creds));

   ret = krb5_get_init_creds_password(context, &creds, principal, 
	 			      (char *)password, krb5_prompter_posix,
				      NULL, 0, NULL, NULL);
   if (ret)
      return ret;

   ret = krb5_sname_to_principal(context, ap_get_server_name(r), service, 
	 			 KRB5_NT_SRV_HST, &server);
   if (ret)
      goto end;

   krb5_verify_init_creds_opt_init(&opt);
   krb5_verify_init_creds_opt_set_ap_req_nofail(&opt, krb_verify_kdc);

   ret = krb5_verify_init_creds(context, &creds, server, keytab, NULL, &opt);
   if (ret)
      goto end;

   if (ccache) {
      ret = krb5_cc_initialize(context, ccache, principal);
      if (ret == 0)
	 ret = krb5_cc_store_cred(context, ccache, &creds);
   }

end:
   krb5_free_cred_contents(context, &creds);
   if (server)
      krb5_free_principal(context, server);
   return ret;
}

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
   int fd;
   krb5_error_code problem;
   int ret;
   krb5_ccache tmp_ccache = NULL;

   ccname = ap_psprintf(r->pool, "FILE:%s/krb5cc_apache_XXXXXX", P_tmpdir);
   fd = mkstemp(ccname + strlen("FILE:"));
   if (fd < 0) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                 "mkstemp() failed: %s", strerror(errno));
      ret = HTTP_INTERNAL_SERVER_ERROR;
      goto end;
   }
   close(fd);

   problem = krb5_cc_resolve(kcontext, ccname, &tmp_ccache);
   if (problem) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                 "krb5_cc_resolve() failed: %s",
                 krb5_get_err_text(kcontext, problem));
      ret = HTTP_INTERNAL_SERVER_ERROR;
      unlink(ccname);
      goto end;
   }

   problem = krb5_cc_initialize(kcontext, tmp_ccache, princ);
   if (problem) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		 "Cannot initialize krb5 ccache %s: krb5_cc_initialize() failed: %s",
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

#ifdef HEIMDAL
   problem = krb5_cc_copy_cache(kcontext, delegated_cred, ccache);
#else
   problem = krb5_cc_copy_creds(kcontext, delegated_cred, ccache);
#endif
   krb5_free_principal(kcontext, princ);
   if (problem) {
      snprintf(errstr, sizeof(errstr), "Failed to store credentials: %s",
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
   krb5_context    kcontext = NULL;
   krb5_error_code code;
   krb5_principal  client = NULL;
   krb5_ccache     ccache = NULL;
   krb5_keytab     keytab = NULL;
   int             ret;
   char            *name = NULL;
   int             all_principals_unkown;
   char            *ccname = NULL;
   int             fd;

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

   /* XXX Heimdal allows to use the MEMORY: type with empty argument ? */
   ccname = ap_psprintf(r->pool, "MEMORY:%s/krb5cc_apache_XXXXXX", P_tmpdir);
   fd = mkstemp(ccname + strlen("MEMORY:"));
   if (fd < 0) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                 "mkstemp() failed: %s", strerror(errno));
      ret = HTTP_INTERNAL_SERVER_ERROR;
      goto end;
   }
   close(fd);

   code = krb5_cc_resolve(kcontext, ccname, &ccache);
   if (code) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                 "krb5_cc_resolve() failed: %s",
                 krb5_get_err_text(kcontext, code));
      ret = HTTP_INTERNAL_SERVER_ERROR;
      unlink(ccname);
      goto end;
   }

   if (conf->krb_5_keytab)
      krb5_kt_resolve(kcontext, conf->krb_5_keytab, &keytab);

   all_principals_unkown = 1;
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

      code = verify_krb5_user(r, kcontext, client, ccache, sent_pw, 
	    		      conf->krb_service_name, 
	    		      keytab, conf->krb_verify_kdc);
      if (!conf->krb_authoritative && code) {
	 /* if we're not authoritative, we allow authentication to pass on
	  * to another modules if (and only if) the user is not known to us */
	 if (all_principals_unkown && code != KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN)
	    all_principals_unkown = 0;
      }

      if (code == 0)
	 break;

      /* ap_getword_white() used above shifts the parameter, so it's not
         needed to touch the realms variable */
   } while (realms && *realms);

   memset((char *)sent_pw, 0, strlen(sent_pw));

   if (code) {
      /* XXX log only in the verify_krb5_user() call */
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "Verifying krb5 password failed: %s",
		 krb5_get_err_text(kcontext, code));
      if (!conf->krb_authoritative && all_principals_unkown == 1 && code == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN)
	 ret = DECLINED;
      else
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
   if (keytab)
      krb5_kt_close(kcontext, keytab);
   krb5_free_context(kcontext);

   return ret;
}

/*********************************************************************
 * GSSAPI Authentication
 ********************************************************************/

static const char *
get_gss_error(MK_POOL *p, OM_uint32 err_maj, OM_uint32 err_min, char *prefix)
{
   OM_uint32 maj_stat, min_stat; 
   OM_uint32 msg_ctx = 0;
   gss_buffer_desc status_string;
   char *err_msg;
   size_t len;

   err_msg = ap_pstrdup(p, prefix);
   do {
      maj_stat = gss_display_status (&min_stat,
	                             err_maj,
				     GSS_C_GSS_CODE,
				     GSS_C_NO_OID,
				     &msg_ctx,
				     &status_string);
      err_msg = ap_pstrcat(p, err_msg, ": ", (char*) status_string.value, NULL);
      gss_release_buffer(&min_stat, &status_string);
      
      if (GSS_ERROR(maj_stat) || msg_ctx == 0)
	 break;

      maj_stat = gss_display_status (&min_stat,
	                             err_min,
				     GSS_C_MECH_CODE,
				     GSS_C_NULL_OID,
				     &msg_ctx,
				     &status_string);
      err_msg = ap_pstrcat(p, err_msg,
	                   " (", (char*) status_string.value, ")", NULL);
      gss_release_buffer(&min_stat, &status_string);
   } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);

   return err_msg;
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

   gss_connection = NULL;

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
	 get_gss_error(r->pool, maj_stat, min_stat, "gss_krb5_copy_ccache"));
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
   char buf[1024];

   snprintf(buf, sizeof(buf), "%s/%s", conf->krb_service_name, ap_get_server_name(r));

   input_token.value = buf;
   input_token.length = strlen(buf) + 1;

   major_status = gss_import_name(&minor_status, &input_token,
	 			  GSS_C_NT_USER_NAME,
				  &server_name);
   if (GSS_ERROR(major_status)) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "%s", get_gss_error(r->pool, major_status, minor_status,
		 "gss_import_name() failed"));
      return HTTP_INTERNAL_SERVER_ERROR;
   }
   
   major_status = gss_acquire_cred(&minor_status, server_name, GSS_C_INDEFINITE,
			           GSS_C_NO_OID_SET, GSS_C_ACCEPT,
				   server_creds, NULL, NULL);
   gss_release_name(&minor_status2, &server_name);
   if (GSS_ERROR(major_status)) {
      log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	         "%s", get_gss_error(r->pool, major_status, minor_status,
		 		     "gss_acquire_cred() failed"));
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

static int
authenticate_user_gss(request_rec *r, kerb_auth_config *conf,
		      const char *auth_line, char **negotiate_ret_value)
{
  OM_uint32 major_status, minor_status, minor_status2;
  gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
  const char *auth_param = NULL;
  int ret;
  gss_name_t client_name = GSS_C_NO_NAME;
  gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
  OM_uint32 (*accept_sec_token)();
  gss_OID_desc spnego_oid;

  *negotiate_ret_value = (char *)EMPTY_STRING;

  spnego_oid.length = 6;
  spnego_oid.elements = (void *)"\x2b\x06\x01\x05\x05\x02";

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

  if (conf->krb_5_keytab) {
     char *ktname;
     /* we don't use the ap_* calls here, since the string passed to putenv()
      * will become part of the enviroment and shouldn't be free()ed by apache
      */
     ktname = malloc(strlen("KRB5_KTNAME=") + strlen(conf->krb_5_keytab) + 1);
     if (ktname == NULL) {
	log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "malloc() failed: not enough memory");
	ret = HTTP_INTERNAL_SERVER_ERROR;
	goto end;
     }
     sprintf(ktname, "KRB5_KTNAME=%s", conf->krb_5_keytab);
     putenv(ktname);
  }

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

  accept_sec_token = (cmp_gss_type(&input_token, &spnego_oid) == 0) ?
     			gss_accept_sec_context_spnego : gss_accept_sec_context;

  major_status = accept_sec_token(&minor_status,
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
     *negotiate_ret_value = token;
     gss_release_buffer(&minor_status2, &output_token);
  }

  if (GSS_ERROR(major_status)) {
     log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	        "%s", get_gss_error(r->pool, major_status, minor_status,
		                    "gss_accept_sec_context() failed"));
     /* Don't offer the Negotiate method again if call to GSS layer failed */
     *negotiate_ret_value = NULL;
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
	       "%s", get_gss_error(r->pool, major_status, minor_status,
		                   "gss_export_name() failed"));
    ret = HTTP_INTERNAL_SERVER_ERROR;
    goto end;
  }

  MK_AUTH_TYPE = "Negotiate";
  MK_USER = ap_pstrdup(r->pool, output_token.value);

  if (conf->krb_save_credentials && delegated_cred != GSS_C_NO_CREDENTIAL)
     store_gss_creds(r, conf, (char *)output_token.value, delegated_cred);

  gss_release_buffer(&minor_status, &output_token);

  ret = OK;

end:
  if (delegated_cred)
     gss_release_cred(&minor_status, &delegated_cred);

  if (output_token.length) 
     gss_release_buffer(&minor_status, &output_token);

  if (client_name != GSS_C_NO_NAME)
     gss_release_name(&minor_status, &client_name);

  cleanup_gss_connection(gss_connection);

  return ret;
}
#endif /* KRB5 */

static int
already_succeeded(request_rec *r)
{
   if (ap_is_initial_req(r) || MK_AUTH_TYPE == NULL)
      return 0;
   if (strcmp(MK_AUTH_TYPE, "Negotiate") ||
       (strcmp(MK_AUTH_TYPE, "Basic") && strchr(MK_USER, '@')))
      return 1;
   return 0;
}

static void
note_kerb_auth_failure(request_rec *r, const kerb_auth_config *conf,
      		       int use_krb4, int use_krb5, char *negotiate_ret_value)
{
   const char *auth_name = NULL;
   int set_basic = 0;
   char *negoauth_param;

   /* get the user realm specified in .htaccess */
   auth_name = ap_auth_name(r);

   /* XXX should the WWW-Authenticate header be cleared first? */
#ifdef KRB5
   if (use_krb5 && conf->krb_method_gssapi && negotiate_ret_value != NULL) {
      negoauth_param = (*negotiate_ret_value == '\0') ? "Negotiate" :
	          ap_pstrcat(r->pool, "Negotiate ", negotiate_ret_value, NULL);
      ap_table_add(r->err_headers_out, "WWW-Authenticate", negoauth_param);
   }
   if (use_krb5 && conf->krb_method_k5pass) {
      ap_table_add(r->err_headers_out, "WWW-Authenticate",
                   ap_pstrcat(r->pool, "Basic realm=\"", auth_name, "\"", NULL));
      set_basic = 1;
   }
#endif

#ifdef KRB4
   if (use_krb4 && conf->krb_method_k4pass && !set_basic)
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
   static int last_return = HTTP_UNAUTHORIZED;
   char *negotiate_ret_value;

   /* get the type specified in .htaccess */
   type = ap_auth_type(r);

   if (type && strcasecmp(type, "Kerberos") == 0)
      use_krb5 = use_krb4 = 1;
   else if(type && strcasecmp(type, "KerberosV5") == 0)
      use_krb4 = 0;
   else if(type && strcasecmp(type, "KerberosV4") == 0)
      use_krb5 = 0;
   else
      return DECLINED;

   /* get what the user sent us in the HTTP header */
   auth_line = MK_TABLE_GET(r->headers_in, "Authorization");
   if (!auth_line) {
      note_kerb_auth_failure(r, conf, use_krb4, use_krb5, "\0");
      return HTTP_UNAUTHORIZED;
   }
   auth_type = ap_getword_white(r->pool, &auth_line);

   if (already_succeeded(r))
      return last_return;

   ret = HTTP_UNAUTHORIZED;

#ifdef KRB5
   if (use_krb5 && conf->krb_method_gssapi &&
       strcasecmp(auth_type, "Negotiate") == 0) {
      ret = authenticate_user_gss(r, conf, auth_line, &negotiate_ret_value);
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
      note_kerb_auth_failure(r, conf, use_krb4, use_krb5, negotiate_ret_value);

   last_return = ret;
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
static int
kerb_init_handler(apr_pool_t *p, apr_pool_t *plog,
      		  apr_pool_t *ptemp, server_rec *s)
{
   ap_add_version_component(p, "mod_auth_kerb/" MODAUTHKERB_VERSION);
   return OK;
}

void kerb_register_hooks(apr_pool_t *p)
{
   ap_hook_post_config(kerb_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
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
