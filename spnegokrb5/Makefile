include ../makefile.include

CPPFLAGS = -I. -I$(KRB5_ROOT)/include -I$(KRB5_ROOT)/include/gssapi
CFLAGS = -Wall -g

gen_files = 			\
	asn1_MechType.c		\
	asn1_MechTypeList.c	\
	asn1_ContextFlags.c	\
	asn1_NegTokenInit.c	\
	asn1_NegTokenTarg.c

asn1_files =			\
	der_get.c               \
	der_put.c               \
	der_free.c              \
	der_length.c            \
	der_copy.c              \
	timegm.c

spnegokrb5_files =		\
	init_sec_context.c	\
	accept_sec_context.c	\
	encapsulate.c		\
	decapsulate.c		\
	external.c

all: libspnegokrb5.a

libspnegokrb5.a: $(gen_files:.c=.o) $(asn1_files:.c=.o) $(spnegokrb5_files:.c=.o)
	ar -rscu libspnegokrb5.a $^

test:
	$(CC) -g -o test -I/usr/heimdal-0.6/include test.c libspnegokrb5.a -L/usr/heimdal-0.6/lib -lgssapi
	
clean:
	$(RM) *.o core libspnegokrb5.a
