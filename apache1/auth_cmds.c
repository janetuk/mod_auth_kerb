static const char *kerb_set_fail_slot(cmd_parms *cmd, char *struct_ptr,
					char *arg)
{
	int offset = (int) (long) cmd->info;
	if (!strncasecmp(arg, "unauthorized", 12))
		*(int *) (struct_ptr + offset) = HTTP_UNAUTHORIZED;
	else if (!strncasecmp(arg, "forbidden", 9))
		*(int *) (struct_ptr + offset) = HTTP_FORBIDDEN;
	else if (!strncasecmp(arg, "declined", 8))
		*(int *) (struct_ptr + offset) = DECLINED;
	else
		return "KrbFailStatus must be Forbidden, Unauthorized, or Declined.";
	return NULL;
}

static const char *kerb_set_type_slot(cmd_parms *cmd, char *struct_ptr,
					char *arg)
{
	int offset = (int) (long) cmd->info;
	if
#ifdef KRB5
	   (!strncasecmp(arg, "v5", 2))
		*(char **) (struct_ptr + offset) = ap_pstrdup(cmd->pool, "KerberosV5");
	else if
#endif /* KRB5 */
#ifdef KRB4
	   (!strncasecmp(arg, "v4", 2))
		*(char **) (struct_ptr + offset) = ap_pstrdup(cmd->pool, "KerberosV4");
#endif /* KRB4 */
	else if
	   (!strncasecmp(arg, "dualv5v4", 2))
		*(char **) (struct_ptr + offset) = ap_pstrdup(cmd->pool, "KerberosDualV5V4");
	else if
	   (!strncasecmp(arg, "dualv4v5", 2))
		*(char **) (struct_ptr + offset) = ap_pstrdup(cmd->pool, "KerberosDualV4V5");
#if defined(KRB4) && defined(KRB5)
#endif /* KRB4 && KRB5 */
	else
		return "AuthKerberos must be V5 or V4.";
	return NULL;
}

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
