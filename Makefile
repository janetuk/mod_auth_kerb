include makefile.include

KRB5_CPPFLAGS = `$(KRB5_ROOT)/bin/krb5-config --cflags gssapi`
KRB5_LDFLAGS = `$(KRB5_ROOT)/bin/krb5-config --libs gssapi`

KRB4_CPPFLAGS = -I$(KRB4_ROOT)/include -I$(KRB4_ROOT)/include/kerberosIV \
	-I$(KRB5_ROOT)/include/kerberosIV

CPPFLAGS = $(KRB5_CPPFLAGS) $(KRB4_CPPFLAGS) $(DEFS)
LDFLAGS = -Lspnegokrb5 -lspnegokrb5 $(KRB5_LDFLAGS) -lresolv

ifndef APXS
   APXS = apxs
endif

all: modauthkerb

libspnegokrb5:
	(cd spnegokrb5 && make)

modauthkerb: libspnegokrb5
	$(APXS) -c -i $(CPPFLAGS) $(LDFLAGS) src/mod_auth_kerb.c

clean:
	(cd spnegokrb5 && make clean)
	$(RM) *.o *.so *.a *.la *.lo *.slo core
	$(RM) src/*.{o,so,a,la,lo,slo}
