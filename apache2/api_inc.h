#include "apr_strings.h"
#include "apr_lib.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

module AP_MODULE_DECLARE_DATA kerb_auth_module;
