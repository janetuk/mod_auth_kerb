module AP_MODULE_DECLARE_DATA kerb_auth_module =
{
	STANDARD20_MODULE_STUFF,
	kerb_dir_config,		/* dir config creater */
	NULL,				/* dir merger */
	NULL,				/* server config */
	NULL,				/* merge server config */
	kerb_auth_cmds,			/* command apr_table_t */
	kerb_register_hooks		/* register hooks */
};
