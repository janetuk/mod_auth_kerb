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
		return apr_pstrcat(cmd->pool, "KrbAuthFailStatus must be Forbidden, Unauthorized, or Declined.", NULL);
	return NULL;
}

static const char *kerb_set_type_slot(cmd_parms *cmd, void *struct_ptr,
						const char *arg)
{
	int offset = (int) (long) cmd->info;
	if
#ifdef KRB5
	   (!strncasecmp(arg, "v5", 2))
		*(char **) ((char *)struct_ptr + offset) = apr_pstrdup(cmd->pool, "KerberosV5");
	else if
#endif /* KRB5 */
#ifdef KRB4
	   (!strncasecmp(arg, "v4", 2))
		*(char **) ((char *)struct_ptr + offset) = apr_pstrdup(cmd->pool, "KerberosV4");
#endif /* KRB4 */
#if defined(KRB5) && defined(KRB4)
	else if
	   (!strncasecmp(arg, "dualv5v4", 8))
		*(char **) ((char *)struct_ptr + offset) = apr_pstrdup(cmd->pool, "KerberosDualV5V4");
	else if
	   (!strncasecmp(arg, "dualv4v5", 8))
		*(char **) ((char *)struct_ptr + offset) = apr_pstrdup(cmd->pool, "KerberosDualV4V5");
#endif /* KRB5 && KRB4 */
	else
		return "AuthKerberos must be V5, V4, DualV4V5, or DualV5V4.";
	return NULL;
}

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
