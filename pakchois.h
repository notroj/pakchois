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

#ifndef PAKCHOIS_H
#define PAKCHOIS_H

#define CRYPTOKI_GNU

#include "pkcs11.h"

typedef struct pakchois_context_s pakchois_context_t;
typedef struct pakchois_session_s pakchois_session_t;
typedef struct pakchois_object_s pakchois_object_t;

pakchois_context_t *pakchois_context_create(const char *module);

void pakchois_context_destroy(pakchois_context_t *ctx);



ck_rv_t pakchois_get_info(pakchois_context_t *ctx, struct ck_info *info);

ck_rv_t pakchois_get_function_list(pakchois_context_t *ctx,
				   struct ck_function_list **function_list);

ck_rv_t pakchois_get_slot_list(pakchois_context_t *ctx,
			       unsigned char token_present,
			       ck_slot_id_t *slot_list,
			       unsigned long *count);

ck_rv_t pakchois_get_slot_info(pakchois_context_t *ctx,
			       ck_slot_id_t slot_id,
			       struct ck_slot_info *info);

ck_rv_t pakchois_get_token_info(pakchois_context_t *ctx,
				ck_slot_id_t slot_id,
				struct ck_token_info *info);

ck_rv_t pakchois_wait_for_slot_event(pakchois_context_t *ctx,
				     ck_flags_t flags, ck_slot_id_t *slot,
				     void *reserved);

ck_rv_t pakchois_get_mechanism_list(pakchois_context_t *ctx,
				    ck_slot_id_t slot_id,
				    ck_mechanism_type_t *mechanism_list,
				    unsigned long *count);

ck_rv_t pakchois_get_mechanism_info(pakchois_context_t *ctx,
				    ck_slot_id_t slot_id,
				    ck_mechanism_type_t type,
				    struct ck_mechanism_info *info);

ck_rv_t pakchois_init_token(pakchois_context_t *ctx,
			    ck_slot_id_t slot_id, unsigned char *pin,
			    unsigned long pin_len, unsigned char *label);

ck_rv_t pakchois_init_pin(pakchois_session_t *session, unsigned char *pin,
			  unsigned long pin_len);

ck_rv_t pakchois_set_pin(pakchois_session_t *session, unsigned char *old_pin,
			 unsigned long old_len, unsigned char *new_pin,
			 unsigned long new_len);

ck_rv_t pakchois_open_session(pakchois_context_t *ctx,
			      ck_slot_id_t slot_id, ck_flags_t flags,
			      void *application, ck_notify_t notify,
			      pakchois_session_t **session);

ck_rv_t pakchois_close_session(pakchois_session_t *session);

ck_rv_t pakchois_close_all_sessions(pakchois_context_t *ctx,
				    ck_slot_id_t slot_id);

ck_rv_t pakchois_get_session_info(pakchois_session_t *session,
				  struct ck_session_info *info);

ck_rv_t pakchois_get_operation_state(pakchois_session_t *session,
				     unsigned char *operation_state,
				     unsigned long *operation_state_len);
ck_rv_t pakchois_set_operation_state(pakchois_session_t *session,
				     unsigned char *operation_state,
				     unsigned long operation_state_len,
				     pakchois_object_t *encryption_key,
				     pakchois_object_t *authentiation_key);
ck_rv_t pakchois_login(pakchois_session_t *session, ck_user_type_t user_type,
		       unsigned char *pin, unsigned long pin_len);
ck_rv_t pakchois_logout(pakchois_session_t *session);

ck_rv_t pakchois_create_object(pakchois_session_t *session,
			       struct ck_attribute *templ,
			       unsigned long count,
			       pakchois_object_t **object);
ck_rv_t pakchois_copy_object(pakchois_session_t *session,
			     pakchois_object_t *object,
			     struct ck_attribute *templ, unsigned long count,
			     pakchois_object_t **new_object);
ck_rv_t pakchois_destroy_object(pakchois_session_t *session,
				pakchois_object_t *object);
ck_rv_t pakchois_get_object_size(pakchois_session_t *session,
				 pakchois_object_t *object,
				 unsigned long *size);
ck_rv_t pakchois_get_attribute_value(pakchois_session_t *session,
				     pakchois_object_t *object,
				     struct ck_attribute *templ,
				     unsigned long count);
ck_rv_t pakchois_set_attribute_value(pakchois_session_t *session,
				     pakchois_object_t *object,
				     struct ck_attribute *templ,
				     unsigned long count);
ck_rv_t pakchois_find_objects_init(pakchois_session_t *session,
				   struct ck_attribute *templ,
				   unsigned long count);
ck_rv_t pakchois_find_objects(pakchois_session_t *session,
			      pakchois_object_t **object,
			      unsigned long max_object_count,
			      unsigned long *object_count);
ck_rv_t pakchois_find_objects_final(pakchois_session_t *session);

ck_rv_t pakchois_encrypt_init(pakchois_session_t *session,
			      struct ck_mechanism *mechanism,
			      pakchois_object_t *key);
ck_rv_t pakchois_encrypt(pakchois_session_t *session,
			 unsigned char *data, unsigned long data_len,
			 unsigned char *encrypted_data,
			 unsigned long *encrypted_data_len);
ck_rv_t pakchois_encrypt_update(pakchois_session_t *session,
				unsigned char *part, unsigned long part_len,
				unsigned char *encrypted_part,
				unsigned long *encrypted_part_len);
ck_rv_t pakchois_encrypt_final(pakchois_session_t *session,
			       unsigned char *last_encrypted_part,
			       unsigned long *last_encrypted_part_len);

ck_rv_t pakchois_decrypt_init(pakchois_session_t *session,
			      struct ck_mechanism *mechanism,
			      pakchois_object_t *key);
ck_rv_t pakchois_decrypt(pakchois_session_t *session,
			 unsigned char *encrypted_data,
			 unsigned long encrypted_data_len,
			 unsigned char *data, unsigned long *data_len);
ck_rv_t pakchois_decrypt_update(pakchois_session_t *session,
				unsigned char *encrypted_part,
				unsigned long encrypted_part_len,
				unsigned char *part, unsigned long *part_len);
ck_rv_t pakchois_decrypt_final(pakchois_session_t *session,
			       unsigned char *last_part,
			       unsigned long *last_part_len);

ck_rv_t pakchois_digest_init(pakchois_session_t *session,
			     struct ck_mechanism *mechanism);
ck_rv_t pakchois_digest(pakchois_session_t *session, unsigned char *data,
			unsigned long data_len, unsigned char *digest,
			unsigned long *digest_len);
ck_rv_t pakchois_digest_update(pakchois_session_t *session,
			       unsigned char *part, unsigned long part_len);
ck_rv_t pakchois_digest_key(pakchois_session_t *session,
			    pakchois_object_t *key);
ck_rv_t pakchois_digest_final(pakchois_session_t *session,
			      unsigned char *digest,
			      unsigned long *digest_len);

ck_rv_t pakchois_sign_init(pakchois_session_t *session,
			   struct ck_mechanism *mechanism,
			   pakchois_object_t *key);
ck_rv_t pakchois_sign(pakchois_session_t *session, unsigned char *data,
		      unsigned long data_len, unsigned char *signature,
		      unsigned long *signature_len);
ck_rv_t pakchois_sign_update(pakchois_session_t *session,
			     unsigned char *part, unsigned long part_len);
ck_rv_t pakchois_sign_final(pakchois_session_t *session,
			    unsigned char *signature,
			    unsigned long *signature_len);
ck_rv_t pakchois_sign_recover_init(pakchois_session_t *session,
				   struct ck_mechanism *mechanism,
				   pakchois_object_t *key);
ck_rv_t pakchois_sign_recover(pakchois_session_t *session,
			      unsigned char *data, unsigned long data_len,
			      unsigned char *signature,
			      unsigned long *signature_len);

ck_rv_t pakchois_verify_init(pakchois_session_t *session,
			     struct ck_mechanism *mechanism,
			     pakchois_object_t *key);
ck_rv_t pakchois_verify(pakchois_session_t *session, unsigned char *data,
			unsigned long data_len, unsigned char *signature,
			unsigned long signature_len);
ck_rv_t pakchois_verify_update(pakchois_session_t *session,
			       unsigned char *part, unsigned long part_len);
ck_rv_t pakchois_verify_final(pakchois_session_t *session,
			      unsigned char *signature,
			      unsigned long signature_len);
ck_rv_t pakchois_verify_recover_init(pakchois_session_t *session,
				     struct ck_mechanism *mechanism,
				     pakchois_object_t *key);
ck_rv_t pakchois_verify_recover(pakchois_session_t *session,
				unsigned char *signature,
				unsigned long signature_len,
				unsigned char *data, unsigned long *data_len);

ck_rv_t pakchois_digest_encrypt_update(pakchois_session_t *session,
				       unsigned char *part,
				       unsigned long part_len,
				       unsigned char *encrypted_part,
				       unsigned long *encrypted_part_len);
ck_rv_t pakchois_decrypt_digest_update(pakchois_session_t *session,
				       unsigned char *encrypted_part,
				       unsigned long encrypted_part_len,
				       unsigned char *part,
				       unsigned long *part_len);
ck_rv_t pakchois_sign_encrypt_update(pakchois_session_t *session,
				     unsigned char *part,
				     unsigned long part_len,
				     unsigned char *encrypted_part,
				     unsigned long *encrypted_part_len);
ck_rv_t pakchois_decrypt_verify_update(pakchois_session_t *session,
				       unsigned char *encrypted_part,
				       unsigned long encrypted_part_len,
				       unsigned char *part,
				       unsigned long *part_len);

ck_rv_t pakchois_generate_key(pakchois_session_t *session,
			      struct ck_mechanism *mechanism,
			      struct ck_attribute *templ,
			      unsigned long count, pakchois_object_t **key);
ck_rv_t pakchois_generate_key_pair(pakchois_session_t *session,
				   struct ck_mechanism *mechanism,
				   struct ck_attribute *public_key_template,
				   unsigned long public_key_attribute_count,
				   struct ck_attribute *private_key_template,
				   unsigned long private_key_attribute_count,
				   pakchois_object_t **public_key,
				   pakchois_object_t **private_key);
ck_rv_t pakchois_wrap_key(pakchois_session_t *session,
			  struct ck_mechanism *mechanism,
			  pakchois_object_t *wrapping_key,
			  pakchois_object_t *key, unsigned char *wrapped_key,
			  unsigned long *wrapped_key_len);
ck_rv_t pakchois_unwrap_key(pakchois_session_t *session,
			    struct ck_mechanism *mechanism,
			    pakchois_object_t *unwrapping_key,
			    unsigned char *wrapped_key,
			    unsigned long wrapped_key_len,
			    struct ck_attribute *templ,
			    unsigned long attribute_count,
			    pakchois_object_t **key);
ck_rv_t pakchois_derive_key(pakchois_session_t *session,
			    struct ck_mechanism *mechanism,
			    pakchois_object_t *base_key,
			    struct ck_attribute *templ,
			    unsigned long attribute_count,
			    pakchois_object_t **key);

ck_rv_t pakchois_seed_random(pakchois_session_t *session,
			     unsigned char *seed, unsigned long seed_len);
ck_rv_t pakchois_generate_random(pakchois_session_t *session,
				 unsigned char *random_data,
				 unsigned long random_len);

#endif /* PAKCHOIS_H */
