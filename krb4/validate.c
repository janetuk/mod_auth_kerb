int kerb4_password_validate(const char *user, const char *pass) {
	int ret;
	char realm[REALM_SZ];

	ret = krb_get_lrealm(realm, 1);
	if (ret != KSUCCESS)
		return !KRB4_OK;

	ret = krb_get_pw_in_tkt(user, "", realm, "krbtgt", realm,
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
