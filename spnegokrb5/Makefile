KRB5_ROOT = /usr/heimdal

CPPFLAGS = -I. -I$(KRB5_ROOT)/include
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

all: libspnegokrb5.a

libspnegokrb5.a: $(gen_files:.c=.o) $(asn1_files:.c=.o) init_sec_context.o accept_sec_context.o 
	ar -rscu libspnegokrb5.a $^

clean:
	$(RM) *.o core libspnegokrb5.a
