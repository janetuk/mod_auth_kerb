/*
 * Copyright (c) 2003 - 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "client_locl.h"
#include <gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "gss_common.h"
#include "base64.h"

/*
 * A simplistic client implementing draft-brezak-spnego-http-04.txt
 */

static int
do_connect (const char *hostname, const char *port)
{
    struct addrinfo *ai, *a;
    struct addrinfo hints;
    int error;
    int s = -1;

    memset (&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    error = getaddrinfo (hostname, port, &hints, &ai);
    if (error)
	errx (1, "getaddrinfo(%s): %s", hostname, gai_strerror(error));

    for (a = ai; a != NULL; a = a->ai_next) {
	s = socket (a->ai_family, a->ai_socktype, a->ai_protocol);
	if (s < 0)
	    continue;
	if (connect (s, a->ai_addr, a->ai_addrlen) < 0) {
	    warn ("connect(%s)", hostname);
 	    close (s);
 	    continue;
	}
	break;
    }
    freeaddrinfo (ai);
    if (a == NULL)
	errx (1, "failed to contact %s", hostname);

    return s;
}

static void
fdprintf(int s, const char *fmt, ...)
{
    size_t len;
    ssize_t ret;
    va_list ap;
    char *str, *buf;
    
    va_start(ap, fmt);
    vasprintf(&str, fmt, ap);
    va_end(ap);

    if (str == NULL)
	errx(1, "vasprintf");

    buf = str;
    len = strlen(buf);
    while (len) {
	ret = write(s, buf, len);
	if (ret == 0)
	    err(1, "connection closed");
	else if (ret < 0)
	    err(1, "error");
	len -= ret;
	buf += ret;
    }
    free(str);
}

//static int version_flag;
static int verbose_flag;
static int mutual_flag = 1;
static int delegate_flag;
static char *mech = NULL;
static char *port_str = "http";
static char *gss_service = "HTTP";
static char *user = NULL;
static char *pwd = NULL;

static struct option const long_opts[] = {
    { "help", no_argument, 0, 'h' },
    { "mech", required_argument, 0, 'm' },
    { "password", required_argument, 0, 'p' },
    { "gss-service", required_argument, 0, 's' },
    { "user", required_argument, 0, 'u' },
    { NULL, 0, NULL, 0 }
};

static const char *short_opts = "hm:p:s:u:";

static void
usage(int ret)
{
    fprintf(stderr, "Usage: http_client [OPTION] URL\n"
                    "-m mech, --mech=mech               gssapi mech to use\n"
                    "-p pass, --password=pass           password to acquire credentials\n"
                    "-s service, --gss-service=service  gssapi service to use\n"
                    "-u user, --user=user               client's username\n");
    exit(ret);
}

/*
 *
 */

struct http_req {
    char *response;
    char **headers;
    int num_headers;
    void *body;
    size_t body_size;
};


static void
http_req_zero(struct http_req *req)
{
    req->response = NULL;
    req->headers = NULL;
    req->num_headers = 0;
    req->body = NULL;
    req->body_size = 0;
}

static void
http_req_free(struct http_req *req)
{
    int i;

    free(req->response);
    for (i = 0; i < req->num_headers; i++)
	free(req->headers[i]);
    free(req->headers);
    free(req->body);
    http_req_zero(req);
}

static const char *
http_find_header(struct http_req *req, const char *header)
{
    int i, len = strlen(header);

    for (i = 0; i < req->num_headers; i++) {
	if (strncasecmp(header, req->headers[i], len) == 0) {
	    return req->headers[i] + len + 1;
	}
    }
    return NULL;
}


static int
http_query(int s, const char *host, const char *page, 
	   char **headers, int num_headers, struct http_req *req)
{
    enum { RESPONSE, HEADER, BODY } state;
    ssize_t ret;
//    char in_buf[4096], *in_ptr = in_buf;
    char in_buf[8000], *in_ptr = in_buf;
    size_t in_len = 0;
    int i;
    size_t content_length = 0;

    http_req_zero(req);

    fdprintf(s, "GET %s HTTP/1.0\r\n", page);
    for (i = 0; i < num_headers; i++)
	fdprintf(s, "%s\r\n", headers[i]);
    fdprintf(s, "Keep-Alive: 115\r\n");
    fdprintf(s, "Connection: keep-alive\r\n");
    fdprintf(s, "Host: %s\r\n\r\n", host);

    state = RESPONSE;

    while (1) {
	ret = read (s, in_ptr, sizeof(in_buf) - in_len - 1);
	if (ret == 0)
	    break;
	else if (ret < 0)
	    err (1, "read: %lu", (unsigned long)ret);
	
	in_buf[ret + in_len] = '\0';

	if (state == HEADER || state == RESPONSE) {
	    char *p;

	    in_len += ret;
	    in_ptr += ret;

	    while (1) {
		p = strstr(in_buf, "\r\n");

		if (p == NULL) {
		    break;
		} else if (p == in_buf) {
		    memmove(in_buf, in_buf + 2, sizeof(in_buf) - 2);
		    state = BODY;
		    in_len -= 2;
		    in_ptr -= 2;
		    break;
		} else if (state == RESPONSE) {
		    req->response = strndup(in_buf, p - in_buf);
		    state = HEADER;
		} else {
		    req->headers = realloc(req->headers,
					   (req->num_headers + 1) * sizeof(req->headers[0]));
		    req->headers[req->num_headers] = strndup(in_buf, p - in_buf);
		    if (req->headers[req->num_headers] == NULL)
			errx(1, "strdup");
		    if (strncmp(req->headers[req->num_headers], "Content-Length:", 15) == 0)
			content_length = atoi(req->headers[req->num_headers] + 16);
		    req->num_headers++;
		}
		memmove(in_buf, p + 2, sizeof(in_buf) - (p - in_buf) - 2);
		in_len -= (p - in_buf) + 2;
		in_ptr -= (p - in_buf) + 2;
	    }
	}

	if (state == BODY) {

	    req->body = realloc(req->body, req->body_size + in_len + 1);

	    memcpy((char *)req->body + req->body_size, in_buf, in_len);
	    req->body_size += in_len;
	    ((char *)req->body)[req->body_size] = '\0';

	    if (content_length && req->body_size == content_length)
		break;

	    in_ptr = in_buf;
	    in_len = 0;
	}
//	else
//	    abort();
    }

#if 0
    if (verbose_flag) {
	int i;
	printf("response: %s\n", req->response);
	for (i = 0; i < req->num_headers; i++)
	    printf("header[%d] %s\n", i, req->headers[i]);
	printf("body: %.*s\n", (int)req->body_size, (char *)req->body);
    }
#endif

    return 0;
}

static int
do_http(const char *host, const char *page, gss_OID mech_oid, gss_cred_id_t cred)
{
    struct http_req req;
    int i, done, print_body, gssapi_done, gssapi_started;
    char *headers[10]; /* XXX */
    int num_headers;
    gss_ctx_id_t context_hdl = GSS_C_NO_CONTEXT;
    gss_name_t server = GSS_C_NO_NAME;
    OM_uint32 flags = 0;
    int s;

    flags = 0;
    if (delegate_flag)
	flags |= GSS_C_DELEG_FLAG;
    if (mutual_flag)
	flags |= GSS_C_MUTUAL_FLAG;

    done = 0;
    num_headers = 0;
    gssapi_done = 1;
    gssapi_started = 0;

    s = do_connect(host, port_str);
    if (s < 0)
	errx(1, "connection failed");

    do {
	print_body = 0;

	http_query(s, host, page, headers, num_headers, &req);
	for (i = 0 ; i < num_headers; i++) 
	    free(headers[i]);
	num_headers = 0;

	if (strstr(req.response, " 200 ") != NULL) {
	    print_body = 1;
	    done = 1;
	} else if (strstr(req.response, " 401 ") != NULL) {
	    if (http_find_header(&req, "WWW-Authenticate:") == NULL)
		errx(1, "Got %s but missed `WWW-Authenticate'", req.response);
	    gssapi_done = 0;
	}

	if (!gssapi_done) {
	    const char *h = http_find_header(&req, "WWW-Authenticate:");
	    if (h == NULL)
		errx(1, "Got %s but missed `WWW-Authenticate'", req.response);

	    if (strncasecmp(h, "GSSAPI", 6) == 0) {
		OM_uint32 maj_stat, min_stat;
		gss_buffer_desc input_token, output_token;

		if (verbose_flag)
		    printf("Negotiate found\n");
		
#if 1
		if (server == GSS_C_NO_NAME) {
		    char *name;
		    asprintf(&name, "%s@%s", gss_service, host);
		    input_token.length = strlen(name);
		    input_token.value = name;

		    maj_stat = gss_import_name(&min_stat,
					       &input_token,
					       GSS_C_NT_HOSTBASED_SERVICE,
					       &server);
		    if (GSS_ERROR(maj_stat))
			gss_err (1, maj_stat, min_stat, "gss_inport_name");
		    free(name);
		    input_token.length = 0;
		    input_token.value = NULL;
		}
#endif

//		i = 9;
		i = 6;
		while(h[i] && isspace((unsigned char)h[i]))
		    i++;
		if (h[i] != '\0') {
		    int len = strlen(&h[i]);
		    if (len == 0)
			errx(1, "invalid Negotiate token");
		    input_token.value = malloc(len);
		    len = base64_decode(&h[i], input_token.value);
		    if (len < 0)
			errx(1, "invalid base64 Negotiate token %s", &h[i]);
		    input_token.length = len;
		} else {
		    if (gssapi_started)
			errx(1, "Negotiate already started");
		    gssapi_started = 1;

		    input_token.length = 0;
		    input_token.value = NULL;
		}

		maj_stat =
		    gss_init_sec_context(&min_stat,
					 cred,
					 &context_hdl,
					 server,
					 mech_oid,
					 flags,
					 0,
					 GSS_C_NO_CHANNEL_BINDINGS,
					 &input_token,
					 NULL,
					 &output_token,
					 NULL,
					 NULL);
		if (GSS_ERROR(maj_stat))
		    gss_err (1, maj_stat, min_stat, "gss_init_sec_context");
		else if (maj_stat & GSS_S_CONTINUE_NEEDED)
		    gssapi_done = 0;
		else {
		    gss_name_t targ_name, src_name;
		    gss_buffer_desc name_buffer;
		    gss_OID mech_type;

		    gssapi_done = 1;

		    printf("\nNegotiate done: %s\n", mech);

		    maj_stat = gss_inquire_context(&min_stat,
						   context_hdl,
						   &src_name,
						   &targ_name,
						   NULL,
						   &mech_type,
						   NULL,
						   NULL,
						   NULL);
		    if (GSS_ERROR(maj_stat))
			gss_err (1, maj_stat, min_stat, "gss_inquire_context");

		    maj_stat = gss_display_name(&min_stat,
						src_name,
						&name_buffer,
						NULL);
		    if (GSS_ERROR(maj_stat))
			gss_err (1, maj_stat, min_stat, "gss_display_name");

		    printf("Source: %.*s\n",
			   (int)name_buffer.length,
			   (char *)name_buffer.value);

		    gss_release_buffer(&min_stat, &name_buffer);

		    maj_stat = gss_display_name(&min_stat,
						targ_name,
						&name_buffer,
						NULL);
		    if (GSS_ERROR(maj_stat))
			gss_err (1, maj_stat, min_stat, "gss_display_name");

		    printf("Target: %.*s\n",
			   (int)name_buffer.length,
			   (char *)name_buffer.value);

		    gss_release_name(&min_stat, &targ_name);
		    gss_release_buffer(&min_stat, &name_buffer);
		}

		if (output_token.length) {
		    char *neg_token;

		    base64_encode(output_token.value,
				  output_token.length,
				  &neg_token);
		    
		    asprintf(&headers[0], "Authorization: GSSAPI %s",
			     neg_token);
		    num_headers = 1;
		    free(neg_token);
		    gss_release_buffer(&min_stat, &output_token);
		}
		if (input_token.length)
		    free(input_token.value);

	    } else
		done = 1;
	} else
	    done = 1;

	if (verbose_flag) {
	    printf("%s\n\n", req.response);

	    for (i = 0; i < req.num_headers; i++)
		printf("%s\n", req.headers[i]);
	    printf("\n");
	}
	if (print_body || verbose_flag)
	    printf("%.*s\n", (int)req.body_size, (char *)req.body);

	http_req_free(&req);
    } while (!done);

    close(s);

    if (gssapi_done == 0)
	errx(1, "gssapi not done but http dance done");

    return 0;
}

int
main(int argc, char *argv[])
{
    int c, ret;
    gss_buffer_desc token;
    gss_OID mech_oid = GSS_C_NO_OID;
    OM_uint32 maj_stat, min_stat;
    gss_name_t gss_username = GSS_C_NO_NAME;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    char *p, *host, *page;

    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != EOF) {
	switch (c) {
	    case 'h':
		usage(0);
	    case 'm':
		mech = optarg;
		mech_oid = select_mech(mech);
		break;
	    case 'p':
		pwd = optarg;
		break;
	    case 's':
		gss_service = optarg;
		break;
	    case 'u':
		user = optarg;
		break;
	    default:
		usage(1);
	}
    }

    if (optind >= argc)
	usage(1);

    p = argv[optind];
    if (strncmp(p, "http://", 7) == 0)
	p += 7;
    host = p;
    p = strchr(host, '/');
    if (p) {
	page = strdup(p);
	*p = '\0';
    } else
	page = strdup("/");

    if (user) {
	token.value = user;
	token.length = strlen(token.value);
	maj_stat = gss_import_name(&min_stat, &token,
				   GSS_C_NT_USER_NAME,
				   &gss_username);
	if (GSS_ERROR(maj_stat))
	    gss_err(1, maj_stat, min_stat, "Invalid user name %s", user);
    }

    if (pwd) {
	gss_OID_set_desc mechs, *mechsp = GSS_C_NO_OID_SET;

	token.value = pwd;
	token.length = strlen(token.value);
	mechs.elements = mech_oid;
	mechs.count = 1;
	mechsp = &mechs;
	maj_stat = gss_acquire_cred_with_password(&min_stat,
			gss_username, &token, 0,
			mechsp, GSS_C_INITIATE,
			&cred, NULL, NULL);
	if (GSS_ERROR(maj_stat))
	    gss_err(1, maj_stat, min_stat, "Failed to load initial credentials");
    }

    ret = do_http(host, page, mech_oid, cred);

    if (gss_username != GSS_C_NO_NAME)
	gss_release_name(&min_stat, &gss_username);

    if (cred != GSS_C_NO_CREDENTIAL)
	gss_release_cred(&min_stat, &cred);

    free(page);

    return (ret);
}
