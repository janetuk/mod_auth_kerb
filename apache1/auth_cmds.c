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
