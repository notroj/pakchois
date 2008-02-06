
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pakchois.h"

static void dump_cert(pakchois_session_t *sess, ck_object_handle_t obj)
{
    struct ck_attribute a[4];
    ck_object_class_t class;
    ck_certificate_type_t type;
    unsigned char label[1024];
    ck_rv_t rv;
    unsigned char value[8192];

    a[0].type = CKA_CLASS;
    a[0].value = &class;
    a[0].value_len = sizeof class;
    a[1].type = CKA_LABEL;
    a[1].value = &label;
    a[1].value_len = sizeof label;
    a[2].type = CKA_VALUE;
    a[2].value = &value;
    a[2].value_len = sizeof value;
    a[3].type = CKA_CERTIFICATE_TYPE;
    a[3].value = &type;
    a[3].value_len = sizeof type;

    rv = pakchois_get_attribute_value(sess, obj, a, 4);
    if (rv == CKR_OK) {
        printf(" object class: %ld\n", class);
        printf(" object type: %ld\n", type);
        printf(" object label: %s\n", label);
    }
}

int main(int argc, char **argv)
{
    pakchois_module_t *ctx;
    struct ck_info info;
    unsigned long count;
    ck_slot_id_t *slots;
    pakchois_session_t *sess;
    ck_mechanism_type_t *mlist;
    ck_rv_t rv;

    if (argc < 2) {
        printf("Specify provider name.\n");
        return 1;
    }

    if (strncmp(argv[1], "softokn", 7) == 0 && argc == 3)
        rv = pakchois_module_nssload(&ctx, argv[1], argv[2],
                                     NULL, NULL, NULL);
    else
        rv = pakchois_module_load(&ctx, argv[1]);

    if (rv != CKR_OK) {
        printf("create failed: %ld!\n", rv);
        return 1;
    }

    puts("ok");

    if (pakchois_get_info(ctx, &info) == CKR_OK) {
        printf("version: %u.%u\n", info.cryptoki_version.major, 
               info.cryptoki_version.minor);
        printf("manufacturer: %.32s\n", info.manufacturer_id);
        printf("library: %.32s\n", info.library_description);
    }    

    if (pakchois_get_slot_list(ctx, 1, NULL, &count) == CKR_OK
        && (slots = malloc(count * sizeof *slots)) != NULL
        && pakchois_get_slot_list(ctx, 1, slots, &count) == CKR_OK) {
        unsigned long n;

        printf("%lu slots:\n", count);

        for (n = 0; n < count; n++) {
            struct ck_slot_info si;
            struct ck_token_info ti;

            printf("  %lu: %lu\n", n, slots[n]);
            
            if (pakchois_get_slot_info(ctx, slots[n], &si) == CKR_OK) {
                printf("\tslot descr: %.32s\n"
                       "\tslot manuf: %.32s\n", 
                       si.slot_description, si.manufacturer_id);
            }

            if (pakchois_get_token_info(ctx, slots[n], &ti) == CKR_OK) {
                printf("\ttoken label: %.32s\n"
                       "\ttoken model: %.32s\n"
                       "\ttoken serial: %.32s\n",
                       ti.label, ti.manufacturer_id, ti.serial_number);
            }

        }
    }
    else {
        puts("no slots\n");
        return 1;
    }
        
    if (pakchois_open_session(ctx, slots[0], 
                              CKF_SERIAL_SESSION, 
                              NULL, NULL, &sess) == CKR_OK) {
        puts("session open!\n");
    }                         
    else {
        puts("sessopen failed\n");
        return 1;
    }

    if (pakchois_get_mechanism_list(ctx, slots[0], NULL, &count) == CKR_OK
        && (mlist = malloc(count * sizeof *mlist)) != NULL
        && pakchois_get_mechanism_list(ctx, slots[0], mlist, &count) == CKR_OK) {
        unsigned long n;

        printf("got mech list (%ld):\n", count);

        for (n = 0; n < count; n++) {
            printf("  0x%04lx\n", mlist[n]);
        }
    }

    rv = pakchois_find_objects_init(sess, NULL, 0);
    if (rv != CKR_OK) {
        puts("find_objects_init failed\n");
    }
    else {
        ck_object_handle_t obj;
        unsigned long count;

        do {
            rv = pakchois_find_objects(sess, &obj, 1, &count);
            
            dump_cert(sess, obj);
        } while (rv == CKR_OK && count);

        pakchois_find_objects_final(sess);
    }

    pakchois_close_session(sess);

    pakchois_module_destroy(ctx);

    return 0;
}
