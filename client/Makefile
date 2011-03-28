DEFS = -DHAVE_SYS_TYPES_H -DHAVE_UNISTD_H -DHAVE_SYS_SOCKET_H -DHAVE_NETINET_IN_H -DHAVE_NETDB_H -DHAVE_SYS_PARAM_H \
	-D_GNU_SOURCE
CPPFLAGS = $(DEFS) -Wall -O0 -g
LDFLAGS = -lgssapi_krb5

HTTP_OBJS = http_client.o gss_common.o base64.o net_write.o net_read.o

http_client: $(HTTP_OBJS)

clean:
	rm -f $(HTTP_OBJS) http_client
