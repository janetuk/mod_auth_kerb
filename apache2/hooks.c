void kerb_register_hooks(apr_pool_t *p)
{
	ap_hook_check_user_id(kerb_authenticate_user, NULL, NULL, APR_HOOK_MIDDLE);
}
