int kerb_authenticate_user(request_rec *r) {
	const char *type;		/* AuthType specified */
	int KerberosV5 = 0;		/* Kerberos V5 check enabled */
	int KerberosV4 = 0;		/* Kerberos V4 check enabled */
	const char *sent_pw;		/* Password sent by browser */
	int res;			/* Response holder */
	const char *authtype;		/* AuthType to send back to browser */
	const char *auth_line = ap_table_get(r->headers_in,
					(r->proxyreq == STD_PROXY)
						? "Proxy-Authorization"
						: "Authorization");

	type = ap_auth_type(r);

	if (type != NULL) {
#ifdef KRB5
		if (strncasecmp(type, "KerberosV5", 10) == 0) {
			KerberosV5 = 1;
		}
#endif /* KRB5 */

#ifdef KRB4
		if (strncasecmp(type, "KerberosV4", 10) == 0) {
			KerberosV4 = 1;
		}
#endif /* KRB4 */
	}

	if (!KerberosV4 && !KerberosV5) {
		return DECLINED;
	}

	if (!ap_auth_name(r)) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
				"need AuthName: %s", r->uri);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (!auth_line) {
		ap_table_set(r->err_headers_out, "WWW-Authenticate", "Kerberos");
		return HTTP_UNAUTHORIZED;
	}

	type = ap_getword_white(r->pool, &auth_line);
	r->connection->user = ap_getword_nulls(r->pool, &auth_line, ':');
	r->connection->ap_auth_type = "Kerberos";
	sent_pw = ap_getword_white(r->pool, &auth_line);

#ifdef KRB5
	if (KerberosV5) {
		if (kerb5_password_validate(r->connection->user, sent_pw)) {
			return OK;
		}
		else {
			return HTTP_UNAUTHORIZED;
		}
	}
#endif /* KRB5 */
#ifdef KRB4
	if (KerberosV4) {
		if (kerb4_password_validate(r->connection->user, sent_pw)) {
			return OK;
		}
		else {
			return HTTP_UNAUTHORIZED;
		}
	}
#endif /* KRB4 */

	return DECLINED;
}
