static const char *kerb_set_fail_slot(cmd_parms *cmd, void *struct_ptr,
						const char *arg)
{
	int offset = (int) (long) cmd->info;
	if (!strncasecmp(arg, "unauthorized", 12))
		*(int *) ((char *)struct_ptr + offset) = HTTP_UNAUTHORIZED;
	else if (!strncasecmp(arg, "forbidden", 9))
		*(int *) ((char *)struct_ptr + offset) = HTTP_FORBIDDEN;
	else if (!strncasecmp(arg, "declined", 9))
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
		*(char **) ((char *)struct_ptr + offset) = "KerberosV5";
	else if
#endif /* KRB5 */
#ifdef KRB4
	   (!strncasecmp(arg, "v4", 2))
		*(char **) ((char *)struct_ptr + offset) = "KerberosV4";
#endif /* KRB4 */
#if defined(KRB5) && defined(KRB4)
	else if
	   (!strncasecmp(arg, "dualv5v4", 8))
		*(char **) ((char *)struct_ptr + offset) = "KerberosDualV5V4";
	else if
	   (!strncasecmp(arg, "dualv4v5", 8))
		*(char **) ((char *)struct_ptr + offset) = "KerberosDualV4V5";
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

	AP_INIT_TAKE1(
		"KrbFailStatus",
		kerb_set_fail_slot,
		(void*)APR_XtOffsetOf(kerb_auth_config, krb_fail_status),
		OR_AUTHCFG,
		"If auth fails, return status set here."
	),

	{ NULL }
};
