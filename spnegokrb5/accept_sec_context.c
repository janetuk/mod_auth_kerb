/*
 * SPNEGO wrapper for Kerberos5 GSS-API 
 * kouril@ics.muni.cz, 2003
 */
#include <stdlib.h>
#include <errno.h>

#include <gssapi.h>
#include <spnego_asn1.h>

#define ALLOC(X) (X) = calloc(1, sizeof(*(X)))

#define OID_cmp(o1, o2) \
	(((o1).length == (o2).length) && \
	 (memcmp((o1).components, (o2).components,(int) (o1).length) == 0))

static int
create_reply(OM_uint32 major_status, oid *mech, gss_buffer_t mech_token,
             gss_buffer_t output_token)
{
   NegTokenTarg targ_token;
   unsigned char *buf = NULL;
   size_t buf_size;
   size_t len;
   int ret;

   memset(&targ_token, 0, sizeof(targ_token));
   
   ALLOC(targ_token.negResult);
   if (targ_token.negResult == NULL)
      return ENOMEM;

   *targ_token.negResult = (major_status == 0) ? accept_completed : accept_incomplete;

   ALLOC(targ_token.supportedMech);
   if (targ_token.supportedMech == NULL) {
      ret = ENOMEM;
      goto end;
   }
   copy_MechType(mech, targ_token.supportedMech);

   if (mech_token->length > 0) {
      ALLOC(targ_token.responseToken);
      if (targ_token.responseToken == NULL) {
	 ret = ENOMEM;
	 goto end;
      }
      targ_token.responseToken->data = malloc(mech_token->length);
      memcpy(targ_token.responseToken->data, mech_token->value, mech_token->length);
      targ_token.responseToken->length = mech_token->length;
   }

   ASN1_MALLOC_ENCODE(NegTokenTarg, buf, buf_size, &targ_token, &len, ret);
   if (ret || buf_size != len) {
      ret = EINVAL;
      goto end;
   }

   output_token->value = buf;
   output_token->length = buf_size;
   buf = NULL;
   ret = 0;

end:
   free_NegTokenTarg(&targ_token);

   return ret;
}

OM_uint32 gss_accept_sec_context_spnego
           (OM_uint32 * minor_status,
            gss_ctx_id_t * context_handle,
            const gss_cred_id_t acceptor_cred_handle,
            const gss_buffer_t input_token_buffer,
            const gss_channel_bindings_t input_chan_bindings,
            gss_name_t * src_name,
            gss_OID * mech_type,
            gss_buffer_t output_token,
            OM_uint32 * ret_flags,
            OM_uint32 * time_rec,
            gss_cred_id_t * delegated_cred_handle)
{
   NegTokenInit init_token;
   OM_uint32 major_status;
   gss_buffer_desc krb5_output_token = GSS_C_EMPTY_BUFFER;
   gss_buffer_desc krb5_input_token = GSS_C_EMPTY_BUFFER;
   size_t len;
   int ret;
   unsigned krb5_oid_array[] =
       {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02};
   oid krb5_oid;

   krb5_oid.length = sizeof(krb5_oid_array);
   krb5_oid.components = krb5_oid_array;

   memset(&init_token, 0, sizeof(init_token));

   ret = decode_NegTokenInit(input_token_buffer->value, 
	                     input_token_buffer->length,
			     &init_token, &len);
   if (ret) {
      *minor_status = EINVAL; /* XXX */
      return GSS_S_DEFECTIVE_TOKEN;
   }

   if (init_token.mechTypes == NULL || init_token.mechTypes->len == 0 ||
       OID_cmp(init_token.mechTypes->val[0], krb5_oid)) {
      *minor_status = EINVAL;
      ret = GSS_S_BAD_MECH;
      goto end;
   }
       
   if (init_token.mechToken) {
      krb5_input_token.value = init_token.mechToken->data;
      krb5_input_token.length = init_token.mechToken->length;
   }
   
   major_status = gss_accept_sec_context(minor_status,
	 				 context_handle,
					 acceptor_cred_handle,
					 &krb5_input_token,
					 input_chan_bindings,
					 src_name,
					 mech_type,
					 &krb5_output_token,
					 ret_flags,
					 time_rec,
					 delegated_cred_handle);
   if (GSS_ERROR(major_status)) {
      ret = major_status;
      goto end;
   }

   ret = create_reply(major_status, &krb5_oid, &krb5_output_token, output_token);
   if (ret) {
      *minor_status = ret;
      ret = GSS_S_FAILURE;
      free(output_token);
   }

end:
   free_NegTokenInit(&init_token);

   return ret;
}

