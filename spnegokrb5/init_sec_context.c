/*
 *  SPNEGO wrapper for Kerberos5 GSS-API
 *  kouril@ics.muni.cz, 2003
 */
#include <stdlib.h>
#include <errno.h>

#include <gssapi.h>
#include <spnego_asn1.h>

#define ALLOC(X) (X) = calloc(1, sizeof(*(X)))

static int
add_mech(MechTypeList *mech_list, oid *mech)
{
   MechType *tmp;

   tmp = realloc(mech_list->val, (mech_list->len + 1) * sizeof(*tmp));
   if (tmp == NULL)
      return ENOMEM;
   mech_list->val = tmp;
   copy_MechType(mech, mech_list->val + mech_list->len);
   mech_list->len++;
   return 0;
}

static int
set_context_flags(OM_uint32 req_flags, ContextFlags *flags)
{
   if (req_flags & GSS_C_DELEG_FLAG)
      flags->delegFlag = 1;
   if (req_flags & GSS_C_MUTUAL_FLAG)
      flags->mutualFlag = 1;
   if (req_flags & GSS_C_REPLAY_FLAG)
      flags->replayFlag = 1;
   if (req_flags & GSS_C_SEQUENCE_FLAG)
      flags->sequenceFlag = 1;
   if (req_flags & GSS_C_ANON_FLAG)
      flags->anonFlag = 1;
   if (req_flags & GSS_C_CONF_FLAG)
      flags->confFlag = 1;
   if (req_flags & GSS_C_INTEG_FLAG)
      flags->integFlag = 1;
   return 0;
}

OM_uint32 gss_init_sec_context_spnego(
	    OM_uint32 * minor_status,
            const gss_cred_id_t initiator_cred_handle,
            gss_ctx_id_t * context_handle,
            const gss_name_t target_name,
            const gss_OID mech_type,
            OM_uint32 req_flags,
            OM_uint32 time_req,
            const gss_channel_bindings_t input_chan_bindings,
            const gss_buffer_t input_token,
            gss_OID * actual_mech_type,
            gss_buffer_t output_token,
            OM_uint32 * ret_flags,
            OM_uint32 * time_rec)
{
   NegTokenInit token_init;
   OM_uint32 major_status, minor_status2;
   gss_buffer_desc krb5_output_token = GSS_C_EMPTY_BUFFER;
   unsigned char *buf = NULL;
   size_t buf_size;
   size_t len;
   int ret;
   unsigned krb5_oid_array[] = 
   	{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02};
   oid krb5_oid;

   memset(&token_init, 0, sizeof(token_init));

   krb5_oid.length = sizeof(krb5_oid_array);
   krb5_oid.components = krb5_oid_array;

   ALLOC(token_init.mechTypes);
   if (token_init.mechTypes == NULL) {
      *minor_status = ENOMEM;
      return GSS_S_FAILURE;
   }

   ret = add_mech(token_init.mechTypes, &krb5_oid);
   if (ret) {
      *minor_status = ret;
      ret = GSS_S_FAILURE;
      goto end;
   }

   ALLOC(token_init.reqFlags);
   if (token_init.reqFlags == NULL) {
      *minor_status = ENOMEM;
      ret = GSS_S_FAILURE;
      goto end;
   }
   set_context_flags(req_flags, token_init.reqFlags);

   major_status = gss_init_sec_context(minor_status,
	 			       initiator_cred_handle,
				       context_handle,
				       target_name,
				       (gss_OID) &krb5_oid,
				       req_flags,
				       time_req,
				       input_chan_bindings,
				       input_token,
				       actual_mech_type,
				       &krb5_output_token,
				       ret_flags,
				       time_rec);
   if (GSS_ERROR(major_status)) {
      ret = major_status;
      goto end;
   }

   if (krb5_output_token.length > 0) {
      ALLOC(token_init.mechToken);
      if (token_init.mechToken == NULL) {
	 *minor_status = ENOMEM;
	 ret = GSS_S_FAILURE;
	 goto end;
      }
      token_init.mechToken->data = krb5_output_token.value;
      token_init.mechToken->length = krb5_output_token.length;
      krb5_output_token.length = 0; /* don't free it later */
   }

   /* The MS implementation of SPNEGO seems to not like the mechListMIC field,
    * so we omit it (it's optional anyway) */

   ASN1_MALLOC_ENCODE(NegTokenInit, buf, buf_size, &token_init, &len, ret);
   if (ret || buf_size != len) {
      *minor_status = EINVAL; /* XXX */
      ret = GSS_S_FAILURE;
      goto end;
   }

   output_token->value = buf;
   output_token->length = buf_size;
   buf = NULL;
   ret = major_status;

end:
   free_NegTokenInit(&token_init);
   if (krb5_output_token.length > 0)
      gss_release_buffer(&minor_status2, &krb5_output_token);
   if (buf)
      free(buf);

   return ret;
}
