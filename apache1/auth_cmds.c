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
		*(char **) (struct_ptr + offset) = "KerberosV5";
	else if
#endif /* KRB5 */
#ifdef KRB4
	   (!strncasecmp(arg, "v4", 2))
		*(char **) (struct_ptr + offset) = "KerberosV4";
#endif /* KRB4 */
	else if
	   (!strncasecmp(arg, "dualv5v4", 2))
		*(char **) (struct_ptr + offset) = "KerberosDualV5V4";
	else if
	   (!strncasecmp(arg, "dualv4v5", 2))
		*(char **) (struct_ptr + offset) = "KerberosDualV4V5";
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

	{
		"KrbFailStatus",
		kerb_set_fail_slot,
		(void*)XtOffsetOf(kerb_auth_config, krb_fail_status),
		OR_AUTHCFG,
		TAKE1,
		"If auth fails, return status set here."
	},

	{ NULL }
};
