module AP_MODULE_DECLARE_DATA kerb_auth_module =
{
	STANDARD20_MODULE_STUFF,
	kerb_dir_config,		/* create per-dir    conf structures  */
	NULL,				/* merge  per-dir    conf structures  */
	NULL,				/* create per-server conf structures  */
	NULL,				/* merge  per-server conf structures  */
	kerb_auth_cmds,			/* table of configuration directives  */
	kerb_register_hooks		/* register hooks                     */
};
