/*
 * XXX License
 */

#ifndef _MIT_INTERNALS_H_
#define _MIT_INTERNALS_H_

/* must be included after krb5.h to override definitons from there */

/*
 * MIT Kerberos 1.3.x replay cache implementation causes major problems
 * with Microsoft Kerberos5 implementation by incorrectly detecting
 * Microsoft authenticators as replays. The problem is being worked on
 * by both MIT and Microsoft but until a definite fix is available, we
 * must disable the replay cache in order to work with Microsoft clients.
 * The only working way to do this seems to be overriding the function
 * that stores authenticators in replay cache with one that does nothing.
 * Note that disabling replay cache is potentially unsecure.
 */

/* Definition from MIT krb5-1.3.3 krb5.h */
typedef struct _krb5_donot_replay {
    krb5_magic magic;
    char *server;                       /* null-terminated */
    char *client;                       /* null-terminated */
    krb5_int32 cusec;
    krb5_timestamp ctime;
} krb5_donot_replay;

/* Definitions from MIT krb5-1.3.3 k5-int.h */
struct _krb5_rc_ops {
    krb5_magic magic;
    char *type;
    krb5_error_code (KRB5_CALLCONV *init)
        (krb5_context, krb5_rcache,krb5_deltat); /* create */
    krb5_error_code (KRB5_CALLCONV *recover)
        (krb5_context, krb5_rcache); /* open */
    krb5_error_code (KRB5_CALLCONV *destroy)
        (krb5_context, krb5_rcache);
    krb5_error_code (KRB5_CALLCONV *close)
        (krb5_context, krb5_rcache);
    krb5_error_code (KRB5_CALLCONV *store)
        (krb5_context, krb5_rcache,krb5_donot_replay *);
    krb5_error_code (KRB5_CALLCONV *expunge)
        (krb5_context, krb5_rcache);
    krb5_error_code (KRB5_CALLCONV *get_span)
        (krb5_context, krb5_rcache,krb5_deltat *);
    char *(KRB5_CALLCONV *get_name)
        (krb5_context, krb5_rcache);
    krb5_error_code (KRB5_CALLCONV *resolve)
        (krb5_context, krb5_rcache, char *);
};

typedef struct _krb5_rc_ops krb5_rc_ops;

/* Definitions from MIT krb5-1.3.3 rc_dfl.h */
extern krb5_error_code KRB5_CALLCONV krb5_rc_dfl_init
        (krb5_context,
                   krb5_rcache,
                   krb5_deltat);
extern krb5_error_code KRB5_CALLCONV krb5_rc_dfl_recover
        (krb5_context,
                   krb5_rcache);
extern krb5_error_code KRB5_CALLCONV krb5_rc_dfl_destroy
        (krb5_context,
                   krb5_rcache);
extern krb5_error_code KRB5_CALLCONV krb5_rc_dfl_close
        (krb5_context,
                   krb5_rcache);
extern krb5_error_code KRB5_CALLCONV krb5_rc_dfl_expunge
        (krb5_context,
                   krb5_rcache);
extern krb5_error_code KRB5_CALLCONV krb5_rc_dfl_get_span
        (krb5_context,
                   krb5_rcache,
                   krb5_deltat *);
extern char * KRB5_CALLCONV krb5_rc_dfl_get_name
        (krb5_context,
                   krb5_rcache);
extern krb5_error_code KRB5_CALLCONV krb5_rc_dfl_resolve
        (krb5_context,
                   krb5_rcache,
                   char *);

/* Definition from MIT krb5-1.3.3 k5-int.h */
/* kouril: use the _internal suffix in order to avoid conflicts with 
 * the definition in krb5.h */
struct krb5_rc_st_internal {
	krb5_magic magic;
	const struct _krb5_rc_ops *ops;
	krb5_pointer data;
};

typedef struct krb5_rc_st_internal *krb5_rcache_internal;

/* Definitions from MIT krb5-1.3.3 gssapiP_krb5.h */
typedef struct _krb5_gss_cred_id_rec {
	/* name/type of credential */
	gss_cred_usage_t usage;
        krb5_principal princ;        /* this is not interned as a gss_name_t */
	int prerfc_mech;
	int rfc_mech;

        /* keytab (accept) data */
        krb5_keytab keytab;
	krb5_rcache_internal rcache;
	
        /* ccache (init) data */
	krb5_ccache ccache;
	krb5_timestamp tgt_expire;
} krb5_gss_cred_id_rec, *krb5_gss_cred_id_t;

#endif /* _MIT_INTERNALS_H_ */
