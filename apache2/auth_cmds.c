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
