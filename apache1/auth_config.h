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
