static void *kerb_dir_config(apr_pool_t *p, char *d)
{
	static void *rec;
	rec = (void *) ap_pcalloc(p, sizeof(kerb_auth_config));
	((kerb_auth_config *)rec)->krb_fail_status = HTTP_UNAUTHORIZED;
	((kerb_auth_config *)rec)->krb_authoritative = 0;
	((kerb_auth_config *)rec)->krb_auth_type = apr_pstrdup(p, "None");
	return rec;
}
