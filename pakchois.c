/* 
   pakchois PKCS#11 interface
   Copyright (C) 2008, Joe Orton <joe@manyfish.co.uk>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

/*
  The interface is directly derived from the scute.org PKCS#11
  cryptoki interface, which is:

   Copyright 2006, 2007 g10 Code GmbH
   Copyright 2006 Andreas Jellinghaus

   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even
   the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
   PURPOSE.
*/

#include <dlfcn.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pakchois.h"

struct pakchois_module_s {
    void *handle;
    const struct ck_function_list *fns;
    struct slot *slots;
};

struct pakchois_session_s {
    pakchois_module_t *context;
    ck_session_handle_t id;
    pakchois_session_t *next; /* linked list. */
    pakchois_notify_t notify;
    void *notify_data;
};
    
struct pakchois_object_s {
    pakchois_session_t *session;
    ck_object_handle_t id;
};

struct slot {
    ck_slot_id_t id;
    pakchois_session_t *sessions;
    struct slot *next;
};

static const char *location_list[] = {
    "/usr/lib64/pkcs11",
    "/home/jorton/.pkcs11",
    NULL
};

static const char *suffix_list[] = {
    ".so",
    "-pkcs11.so",
    NULL
};

#define CALL(name, args) (ctx->fns->C_ ## name) args
#define CALLS(name, args) (sess->context->fns->C_ ## name) args
#define CALLS1(n, a) CALLS(n, (sess->id, a))
#define CALLS2(n, a, b) CALLS(n, (sess->id, a, b))
#define CALLS3(n, a, b, c) CALLS(n, (sess->id, a, b, c))
#define CALLS4(n, a, b, c, d) CALLS(n, (sess->id, a, b, c, d))
#define CALLS5(n, a, b, c, d, e) CALLS(n, (sess->id, a, b, c, d, e))
#define CALLS7(n, a, b, c, d, e, f, g) CALLS(n, (sess->id, a, b, c, d, e, f, g))

static void *find_pkcs11_module(const char *name)
{
    char path[PATH_MAX];
    unsigned i, j;
    void *h;
    
    for (i = 0; location_list[i]; i++) {
        for (j = 0; suffix_list[j]; j++) {
            snprintf(path, sizeof path, "%s/%s%s", location_list[i], name,
                     suffix_list[j]);

            h = dlopen(path, RTLD_LOCAL|RTLD_NOW);
            if (h != NULL)
                return h;
        }
    }

    return NULL;
}            

pakchois_module_t *pakchois_module_load(const char *name)
{
    void *h = find_pkcs11_module(name);
    CK_C_GetFunctionList gfl;
    pakchois_module_t *ctx;
    struct ck_function_list *fns;
    struct ck_c_initialize_args args;

    if (!h) {
        return NULL;
    }

    gfl = dlsym(h, "C_GetFunctionList");
    if (!gfl) {
        dlclose(h);
        return NULL;
    }
    
    if (gfl(&fns) != CKR_OK) {
        dlclose(h);
        return NULL;
    }

    /* Require OS locking, the only sane option. */
    memset(&args, 0, sizeof args);
    args.flags = CKF_OS_LOCKING_OK;          
    
    if (fns->C_Initialize(&args) != CKR_OK) {
        dlclose(h);
        return NULL;
    }

    ctx = malloc(sizeof *ctx);
    ctx->handle = h;
    ctx->fns = fns;
    
    return ctx;
}    

void pakchois_module_destroy(pakchois_module_t *ctx)
{
    CALL(Finalize, (NULL));
    dlclose(ctx->handle);
    free(ctx);
}

ck_rv_t pakchois_get_info(pakchois_module_t *ctx, struct ck_info *info)
{
    return CALL(GetInfo, (info));
}

ck_rv_t pakchois_get_slot_list(pakchois_module_t *ctx,
			       unsigned char token_present,
			       ck_slot_id_t *slot_list,
			       unsigned long *count)
{
    return CALL(GetSlotList, (token_present, slot_list, count));
}

ck_rv_t pakchois_get_slot_info(pakchois_module_t *ctx,
			       ck_slot_id_t slot_id,
			       struct ck_slot_info *info)
{
    return CALL(GetSlotInfo, (slot_id, info));
}

ck_rv_t pakchois_get_token_info(pakchois_module_t *ctx,
				ck_slot_id_t slot_id,
				struct ck_token_info *info)
{
    return CALL(GetTokenInfo, (slot_id, info));
}

ck_rv_t pakchois_wait_for_slot_event(pakchois_module_t *ctx,
				     ck_flags_t flags, ck_slot_id_t *slot,
				     void *reserved)
{
    return CALL(WaitForSlotEvent, (flags, slot, reserved));
}

ck_rv_t pakchois_get_mechanism_list(pakchois_module_t *ctx,
				    ck_slot_id_t slot_id,
				    ck_mechanism_type_t *mechanism_list,
				    unsigned long *count)
{
    return CALL(GetMechanismList, (slot_id, mechanism_list, count));
}

ck_rv_t pakchois_get_mechanism_info(pakchois_module_t *ctx,
				    ck_slot_id_t slot_id,
				    ck_mechanism_type_t type,
				    struct ck_mechanism_info *info)
{
    return CALL(GetMechanismInfo, (slot_id, type, info));
}

ck_rv_t pakchois_init_token(pakchois_module_t *ctx,
			    ck_slot_id_t slot_id, unsigned char *pin,
			    unsigned long pin_len, unsigned char *label)
{
    return CALL(InitToken, (slot_id, pin, pin_len, label));
}

ck_rv_t pakchois_init_pin(pakchois_session_t *sess, unsigned char *pin,
			  unsigned long pin_len)
{
    return CALLS2(InitPIN, pin, pin_len);
}

ck_rv_t pakchois_set_pin(pakchois_session_t *sess, unsigned char *old_pin,
			 unsigned long old_len, unsigned char *new_pin,
			 unsigned long new_len)
{
    return CALLS4(SetPIN, old_pin, old_len, new_pin, new_len);
}

static ck_rv_t notify_thunk(ck_session_handle_t session,
                            ck_notification_t event, void *application)
{
    pakchois_session_t *sess = application;

    return sess->notify(sess, event, sess->notify_data);
}

static struct slot *find_slot(pakchois_module_t *ctx, ck_slot_id_t id)
{
    struct slot *slot;

    for (slot = ctx->slots; slot; slot = slot->next)
        if (slot->id == id)
            return slot;

    return NULL;
}

static struct slot *find_or_create_slot(pakchois_module_t *ctx,
                                        ck_slot_id_t id)
{
    struct slot *slot = find_slot(ctx, id);

    if (slot) {
        return slot;
    }

    slot = malloc(sizeof *slot);
    slot->id = id;
    slot->sessions = NULL;
    slot->next = ctx->slots;
    ctx->slots = NULL;

    return slot;    
}

static void insert_session(pakchois_module_t *ctx,
                           pakchois_session_t *session,
                           ck_slot_id_t id)
{
    struct slot *slot = find_or_create_slot(ctx, id);

    session->next = slot->sessions;
    slot->sessions = session;
}

ck_rv_t pakchois_open_session(pakchois_module_t *ctx,
			      ck_slot_id_t slot_id, ck_flags_t flags,
			      void *application, pakchois_notify_t notify,
			      pakchois_session_t **session)
{
    ck_session_handle_t sh;
    pakchois_session_t *sess;
    ck_rv_t rv;

    sess = malloc(sizeof *sess);
    rv = CALL(OpenSession, (slot_id, flags, sess, notify_thunk, &sh));
    if (rv != CKR_OK) {
        free(sess);
        return rv;
    }
    
    *session = sess;
    sess->context = ctx;
    sess->id = sh;
    insert_session(ctx, sess, slot_id);
    
    return CKR_OK;
}

ck_rv_t pakchois_close_session(pakchois_session_t *sess)
{
    /* PKCS#11 says that all bets are off on failure, so destroy the
     * session object and just return the error code. */
    ck_rv_t rv = CALLS(CloseSession, (sess->id));
    free(sess);
    return rv;
}

ck_rv_t pakchois_close_all_sessions(pakchois_module_t *ctx,
				    ck_slot_id_t slot_id)
{
    struct slot *slot;
    pakchois_session_t *sess, *next;

    ck_rv_t rv = CALL(CloseAllSessions, (slot_id));

    slot = find_slot(ctx, slot_id);
    
    for (sess = slot->sessions; sess; sess = next) {
        next = sess->next;
        free(sess);
    }

    return rv;
}

ck_rv_t pakchois_get_session_info(pakchois_session_t *sess,
				  struct ck_session_info *info)
{
    return CALLS1(GetSessionInfo, info);
}

ck_rv_t pakchois_get_operation_state(pakchois_session_t *sess,
				     unsigned char *operation_state,
				     unsigned long *operation_state_len)
{
    return CALLS2(GetOperationState, operation_state, 
                  operation_state_len);
}

ck_rv_t pakchois_set_operation_state(pakchois_session_t *sess,
				     unsigned char *operation_state,
				     unsigned long operation_state_len,
				     pakchois_object_t *encryption_key,
				     pakchois_object_t *authentiation_key)
{
    return CALLS4(SetOperationState, operation_state, operation_state_len,
                  encryption_key->id, authentiation_key->id);
}

ck_rv_t pakchois_login(pakchois_session_t *sess, ck_user_type_t user_type,
		       unsigned char *pin, unsigned long pin_len)
{
    return CALLS3(Login, user_type, pin, pin_len);
}

ck_rv_t pakchois_logout(pakchois_session_t *sess)
{
    return CALLS(Logout, (sess->id));
}

static pakchois_object_t *object_new(pakchois_session_t *sess,
                                     ck_object_handle_t oh)
{
    pakchois_object_t *obj = calloc(sizeof 1, sizeof *obj);
    
    obj->session = sess;
    obj->id = oh;
    
    return obj;
}    

ck_rv_t pakchois_create_object(pakchois_session_t *sess,
			       struct ck_attribute *templ,
			       unsigned long count,
			       pakchois_object_t **object)
{
    ck_object_handle_t oh;
    ck_rv_t rv;
    
    rv = CALLS3(CreateObject, templ, count, &oh);
    if (rv != CKR_OK) {
        return rv;
    }

    *object = object_new(sess, oh);

    return CKR_OK;
}

ck_rv_t pakchois_copy_object(pakchois_session_t *sess,
			     pakchois_object_t *object,
			     struct ck_attribute *templ, unsigned long count,
			     pakchois_object_t **new_object)
{
    ck_object_handle_t oh;
    ck_rv_t rv;
    
    rv = CALLS4(CopyObject, object->id, templ, count, &oh);
    if (rv != CKR_OK) {
        return rv;
    }

    *new_object = object_new(sess, oh);

    return CKR_OK;
}

ck_rv_t pakchois_destroy_object(pakchois_session_t *sess,
				pakchois_object_t *object)
{
    ck_rv_t rv = CALLS1(DestroyObject, object->id);
    free(object);
    return rv;
}    

ck_rv_t pakchois_get_object_size(pakchois_session_t *sess,
				 pakchois_object_t *object,
				 unsigned long *size)
{
    return CALLS2(GetObjectSize, object->id, size);
}

ck_rv_t pakchois_get_attribute_value(pakchois_session_t *sess,
				     pakchois_object_t *object,
				     struct ck_attribute *templ,
				     unsigned long count)
{
    return CALLS3(GetAttributeValue, object->id, templ, count);
}

ck_rv_t pakchois_set_attribute_value(pakchois_session_t *sess,
				     pakchois_object_t *object,
				     struct ck_attribute *templ,
				     unsigned long count)
{
    return CALLS3(SetAttributeValue, object->id, templ, count);
}

ck_rv_t pakchois_find_objects_init(pakchois_session_t *sess,
				   struct ck_attribute *templ,
				   unsigned long count)
{
    return CALLS2(FindObjectsInit, templ, count);
}

ck_rv_t pakchois_find_objects(pakchois_session_t *sess,
			      pakchois_object_t **object,
			      unsigned long max_object_count,
			      unsigned long *object_count)
{
    ck_rv_t rv;
    ck_object_handle_t *oh;
    unsigned n;

    oh = malloc(max_object_count * sizeof *oh);
    rv = CALLS3(FindObjects, oh, max_object_count, object_count);
    if (rv != CKR_OK) {
        free(oh);
    }

    for (n = 0; n < *object_count; n++) {
        object[n] = object_new(sess, oh[n]);
    }

    free(oh);

    return CKR_OK;
}

ck_rv_t pakchois_find_objects_final(pakchois_session_t *sess)
{
    return CALLS(FindObjectsFinal, (sess->id));
}

ck_rv_t pakchois_encrypt_init(pakchois_session_t *sess,
			      struct ck_mechanism *mechanism,
			      pakchois_object_t *key)
{
    return CALLS2(EncryptInit, mechanism, key->id);
}

ck_rv_t pakchois_encrypt(pakchois_session_t *sess,
			 unsigned char *data, unsigned long data_len,
			 unsigned char *encrypted_data,
			 unsigned long *encrypted_data_len)
{
    return CALLS(Encrypt, (sess->id, data, data_len, 
                           encrypted_data, encrypted_data_len));
}

ck_rv_t pakchois_encrypt_update(pakchois_session_t *sess,
				unsigned char *part, unsigned long part_len,
				unsigned char *encrypted_part,
				unsigned long *encrypted_part_len)
{
    return CALLS(EncryptUpdate, (sess->id, part, part_len,
                                 encrypted_part, encrypted_part_len));
}

ck_rv_t pakchois_encrypt_final(pakchois_session_t *sess,
			       unsigned char *last_encrypted_part,
			       unsigned long *last_encrypted_part_len)
{
    return CALLS2(EncryptFinal, last_encrypted_part, last_encrypted_part_len);
}

ck_rv_t pakchois_decrypt_init(pakchois_session_t *sess,
			      struct ck_mechanism *mechanism,
			      pakchois_object_t *key)
{
    return CALLS2(DecryptInit, mechanism, key->id);
}

ck_rv_t pakchois_decrypt(pakchois_session_t *sess,
			 unsigned char *encrypted_data,
			 unsigned long encrypted_data_len,
			 unsigned char *data, unsigned long *data_len)
{
    return CALLS4(Decrypt, encrypted_data, encrypted_data_len, data, data_len);
}

ck_rv_t pakchois_decrypt_update(pakchois_session_t *sess,
				unsigned char *encrypted_part,
				unsigned long encrypted_part_len,
				unsigned char *part, unsigned long *part_len)
{
    return CALLS4(DecryptUpdate, encrypted_part, encrypted_part_len,
                  part, part_len);
}

ck_rv_t pakchois_decrypt_final(pakchois_session_t *sess,
			       unsigned char *last_part,
			       unsigned long *last_part_len)
{
    return CALLS2(DecryptFinal, last_part, last_part_len);
}

ck_rv_t pakchois_digest_init(pakchois_session_t *sess,
			     struct ck_mechanism *mechanism)
{
    return CALLS1(DigestInit, mechanism);
}

ck_rv_t pakchois_digest(pakchois_session_t *sess, unsigned char *data,
			unsigned long data_len, unsigned char *digest,
			unsigned long *digest_len)
{
    return CALLS4(Digest, data, data_len, digest, digest_len);
}

ck_rv_t pakchois_digest_update(pakchois_session_t *sess,
			       unsigned char *part, unsigned long part_len)
{
    return CALLS2(DigestUpdate, part, part_len);
}

ck_rv_t pakchois_digest_key(pakchois_session_t *sess,
			    pakchois_object_t *key)
{
    return CALLS1(DigestKey, key->id);
}

ck_rv_t pakchois_digest_final(pakchois_session_t *sess,
			      unsigned char *digest,
			      unsigned long *digest_len)
{
    return CALLS2(DigestFinal, digest, digest_len);
}

ck_rv_t pakchois_sign_init(pakchois_session_t *sess,
			   struct ck_mechanism *mechanism,
			   pakchois_object_t *key)
{
    return CALLS2(SignInit, mechanism, key->id);
}

ck_rv_t pakchois_sign(pakchois_session_t *sess, unsigned char *data,
		      unsigned long data_len, unsigned char *signature,
		      unsigned long *signature_len)
{
    return CALLS4(Sign, data, data_len, signature, signature_len);
}

ck_rv_t pakchois_sign_update(pakchois_session_t *sess,
			     unsigned char *part, unsigned long part_len)
{
    return CALLS2(SignUpdate, part, part_len);
}

ck_rv_t pakchois_sign_final(pakchois_session_t *sess,
			    unsigned char *signature,
			    unsigned long *signature_len)
{
    return CALLS2(SignFinal, signature, signature_len);
}

ck_rv_t pakchois_sign_recover_init(pakchois_session_t *sess,
				   struct ck_mechanism *mechanism,
				   pakchois_object_t *key)
{
    return CALLS2(SignRecoverInit, mechanism, key->id);
}

ck_rv_t pakchois_sign_recover(pakchois_session_t *sess,
			      unsigned char *data, unsigned long data_len,
			      unsigned char *signature,
			      unsigned long *signature_len)
{
    return CALLS4(SignRecover, data, data_len, signature, signature_len);
}

ck_rv_t pakchois_verify_init(pakchois_session_t *sess,
			     struct ck_mechanism *mechanism,
			     pakchois_object_t *key)
{
    return CALLS2(VerifyInit, mechanism, key->id);
}

ck_rv_t pakchois_verify(pakchois_session_t *sess, unsigned char *data,
			unsigned long data_len, unsigned char *signature,
			unsigned long signature_len)
{
    return CALLS4(Verify, data, data_len, signature, signature_len);
}

ck_rv_t pakchois_verify_update(pakchois_session_t *sess,
			       unsigned char *part, unsigned long part_len)
{
    return CALLS2(VerifyUpdate, part, part_len);
}

ck_rv_t pakchois_verify_final(pakchois_session_t *sess,
			      unsigned char *signature,
			      unsigned long signature_len)
{
    return CALLS2(VerifyFinal, signature, signature_len);
}

ck_rv_t pakchois_verify_recover_init(pakchois_session_t *sess,
				     struct ck_mechanism *mechanism,
				     pakchois_object_t *key)
{
    return CALLS2(VerifyRecoverInit, mechanism, key->id);
}

ck_rv_t pakchois_verify_recover(pakchois_session_t *sess,
				unsigned char *signature,
				unsigned long signature_len,
				unsigned char *data, unsigned long *data_len)
{
    return CALLS4(VerifyRecover, signature, signature_len, data, data_len);
}

ck_rv_t pakchois_digest_encrypt_update(pakchois_session_t *sess,
				       unsigned char *part,
				       unsigned long part_len,
				       unsigned char *encrypted_part,
				       unsigned long *encrypted_part_len)
{
    return CALLS4(DigestEncryptUpdate, part, part_len,
                  encrypted_part, encrypted_part_len);
}

ck_rv_t pakchois_decrypt_digest_update(pakchois_session_t *sess,
				       unsigned char *encrypted_part,
				       unsigned long encrypted_part_len,
				       unsigned char *part,
				       unsigned long *part_len)
{
    return CALLS4(DecryptDigestUpdate, encrypted_part, encrypted_part_len,
                  part, part_len);
}

ck_rv_t pakchois_sign_encrypt_update(pakchois_session_t *sess,
				     unsigned char *part,
				     unsigned long part_len,
				     unsigned char *encrypted_part,
				     unsigned long *encrypted_part_len)
{
    return CALLS4(SignEncryptUpdate, part, part_len,
                  encrypted_part, encrypted_part_len);
}

ck_rv_t pakchois_decrypt_verify_update(pakchois_session_t *sess,
				       unsigned char *encrypted_part,
				       unsigned long encrypted_part_len,
				       unsigned char *part,
				       unsigned long *part_len)
{
    return CALLS4(DecryptVerifyUpdate, encrypted_part, encrypted_part_len,
                  part, part_len);
}

ck_rv_t pakchois_generate_key(pakchois_session_t *sess,
			      struct ck_mechanism *mechanism,
			      struct ck_attribute *templ,
			      unsigned long count, pakchois_object_t **key)
{
    ck_object_handle_t oh;
    ck_rv_t rv;

    rv = CALLS4(GenerateKey, mechanism, templ, count, &oh);
    if (rv != CKR_OK) {
        return rv;
    }
    
    *key = object_new(sess, oh);

    return CKR_OK;
}

ck_rv_t pakchois_generate_key_pair(pakchois_session_t *sess,
				   struct ck_mechanism *mechanism,
				   struct ck_attribute *public_key_template,
				   unsigned long public_key_attribute_count,
				   struct ck_attribute *private_key_template,
				   unsigned long private_key_attribute_count,
				   pakchois_object_t **public_key,
				   pakchois_object_t **private_key)
{
    ck_rv_t rv;
    ck_object_handle_t pubkey, privkey;

    rv = CALLS(GenerateKeyPair, (sess->id, mechanism, public_key_template,
                                 public_key_attribute_count,
                                 private_key_template, 
                                 private_key_attribute_count,
                                 &pubkey, &privkey));
    if (rv != CKR_OK) {
        return rv;
    }

    *public_key = object_new(sess, pubkey);
    *private_key = object_new(sess, privkey);
    
    return CKR_OK;
}

ck_rv_t pakchois_wrap_key(pakchois_session_t *sess,
			  struct ck_mechanism *mechanism,
			  pakchois_object_t *wrapping_key,
			  pakchois_object_t *key, unsigned char *wrapped_key,
			  unsigned long *wrapped_key_len)
{
    return CALLS5(WrapKey, mechanism, wrapping_key->id,
                  key->id, wrapped_key, wrapped_key_len);
}    

ck_rv_t pakchois_unwrap_key(pakchois_session_t *sess,
			    struct ck_mechanism *mechanism,
			    pakchois_object_t *unwrapping_key,
			    unsigned char *wrapped_key,
			    unsigned long wrapped_key_len,
			    struct ck_attribute *templ,
			    unsigned long attribute_count,
			    pakchois_object_t **key)
{
    ck_object_handle_t oh;
    ck_rv_t rv;

    rv = CALLS7(UnwrapKey, mechanism, unwrapping_key->id, 
                wrapped_key, wrapped_key_len, templ, attribute_count,
                &oh);
    if (rv != CKR_OK) {
        return rv;
    }
    
    *key = object_new(sess, oh);

    return CKR_OK;
}

ck_rv_t pakchois_derive_key(pakchois_session_t *sess,
			    struct ck_mechanism *mechanism,
			    pakchois_object_t *base_key,
			    struct ck_attribute *templ,
			    unsigned long attribute_count,
			    pakchois_object_t **key)
{
    ck_object_handle_t oh;
    ck_rv_t rv;

    rv = CALLS5(DeriveKey, mechanism, base_key->id, 
                templ, attribute_count, &oh);
    if (rv != CKR_OK) {
        return rv;
    }
    
    *key = object_new(sess, oh);

    return CKR_OK;
}


ck_rv_t pakchois_seed_random(pakchois_session_t *sess,
			     unsigned char *seed, unsigned long seed_len)
{
    return CALLS2(SeedRandom, seed, seed_len);
}

ck_rv_t pakchois_generate_random(pakchois_session_t *sess,
				 unsigned char *random_data,
				 unsigned long random_len)
{
    return CALLS2(GenerateRandom, random_data, random_len);
}