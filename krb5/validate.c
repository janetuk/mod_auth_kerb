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
		return !KRB5_OK;

	memset((char *)&my_creds, 0, sizeof(my_creds));
	if(krb5_parse_name(kcontext, user, &me))
		return !KRB5_OK;
	my_creds.client = me;

	if (krb5_build_principal_ext(kcontext, &server,
				krb5_princ_realm(kcontext, me)->length,
				krb5_princ_realm(kcontext, me)->data,
				tgtname.length, tgtname.data,
				krb5_princ_realm(kcontext, me)->length,
				krb5_princ_realm(kcontext, me)->data,
				0)) {
		return !KRB5_OK;
	}
	my_creds.server = server;
	if (krb5_timeofday(kcontext, &now))
		return !KRB5_OK;
	my_creds.times.starttime = 0;
	my_creds.times.endtime = now + lifetime;
	my_creds.times.renew_till = 0;

	ret = krb5_get_in_tkt_with_password(kcontext, 0, 0, NULL, 0,
				pass, NULL, &my_creds, 0);
	if (ret) {
		return !KRB5_OK;
	}

	krb5_free_cred_contents(kcontext, &my_creds);

	return KRB5_OK;
}
