module kerb_auth_module = {
	STANDARD_MODULE_STUFF,
	NULL,				/* initializer */
	kerb_dir_config,		/* dir config creater */
	NULL,				/* dir merger */
	NULL,				/* server config */
	NULL,				/* merge server config */
	kerb_auth_cmds,			/* command table */
	NULL,				/* handlers */
	NULL,				/* filename translation */
	kerb_authenticate_user,		/* check_user_id */
	NULL,				/* check auth */
	NULL,				/* check access */
	NULL,				/* type_checker */
	NULL,				/* fixups */
	NULL				/* logger */
};
