int kerb_authenticate_user(request_rec *r) {
	const char *name;		/* AuthName specified */
	const char *type;		/* AuthType specified */
	int KerberosV5 = 0;		/* Kerberos V5 check enabled */
	int KerberosV4 = 0;		/* Kerberos V4 check enabled */
	int KerberosV4first = 0;	/* Kerberos V4 check first */
	const char *sent_pw;		/* Password sent by browser */
	const char *t;			/* Return value holder */
	int res;			/* Response holder */
	int retcode;			/* Return code holder */

	kerb_auth_config *conf =
		(kerb_auth_config *)ap_get_module_config(r->per_dir_config,
					&kerb_auth_module);

	const char *auth_line = apr_table_get(r->headers_in,
					(PROXYREQ_PROXY == r->proxyreq)
						? "Proxy-Authorization"
						: "Authorization");

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
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			0, r, "need AuthName: %s", r->uri);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (!auth_line) {
		apr_table_set(r->err_headers_out, "WWW-Authenticate",
			(char *)apr_pstrcat(r->pool, "Basic realm=\"", name, "\"", NULL));
		return HTTP_UNAUTHORIZED;
	}

	type = ap_getword_white(r->pool, &auth_line);
	t = ap_pbase64decode(r->pool, auth_line);
	r->user = ap_getword_nulls(r->pool, &t, ':');
	r->ap_auth_type = "Kerberos";
	sent_pw = ap_getword_white(r->pool, &t);

	retcode = DECLINED;

#ifdef KRB5
	if (KerberosV5 && !KerberosV4first && retcode != OK) {
		r->ap_auth_type = "KerberosV5";
		if (kerb5_password_validate(r->user, sent_pw)) {
			retcode = OK;
		}
		else {
			retcode = conf->krb_fail_status;
		}
	}
#endif /* KRB5 */

#ifdef KRB4
	if (KerberosV4 && retcode != OK) {
		r->ap_auth_type = "KerberosV4";
		if (kerb4_password_validate(r->user, sent_pw)) {
			retcode = OK;
		}
		else {
			retcode = conf->krb_fail_status;
		}
	}
#endif /* KRB4 */

#if defined(KRB5) && defined(KRB4)
	if (KerberosV5 && KerberosV4first && retcode != OK) {
		r->ap_auth_type = "KerberosV5";
		if (kerb5_password_validate(r->user, sent_pw)) {
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
