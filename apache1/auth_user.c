int kerb_authenticate_user(request_rec *r) {
	const char *type;		/* AuthType specified */
	int KerberosV5 = 0;		/* Kerberos V5 check enabled */
	int KerberosV4 = 0;		/* Kerberos V4 check enabled */
	const char *sent_pw;		/* Password sent by browser */
	int res;			/* Response holder */
	const char *auth_line = apr_table_get(r->headers_in,
					(PROXYREQ_PROXY == r->proxyreq)
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

	const char *t;

	if (!(t = ap_auth_type(r)) || strcasecmp(t, "Basic"))
		return DECLINED;

	if (!ap_auth_name(r)) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,
			0, r, "need AuthName: %s", r->uri);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (!auth_line) {
		ap_note_basic_auth_failure(r);
		return HTTP_UNAUTHORIZED;
	}

	if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
		/* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      "client used wrong authentication scheme: %s", r->uri);
        ap_note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    while (*auth_line == ' ' || *auth_line == '\t') {
        auth_line++;
    }

    t = ap_pbase64decode(r->pool, auth_line);
    /* Note that this allocation has to be made from r->connection->pool
     * because it has the lifetime of the connection.  The other allocations
     * are temporary and can be tossed away any time.
     */
    r->user = ap_getword_nulls (r->pool, &t, ':');
    r->ap_auth_type = "Basic";

    *pw = t;

    return OK;
}

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
