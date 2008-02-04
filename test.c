
#include <stdio.h>
#include <stdlib.h>

#include "pakchois.h"

static ck_rv_t notify_fn(pakchois_session_t *sess,
                         ck_notification_t event,
                         void *application)
{
    puts("notify!");
    return CKR_OK;
}

int main(int argc, char **argv)
{
    pakchois_module_t *ctx;
    struct ck_info info;
    unsigned long count;
    ck_slot_id_t *slots;
    pakchois_session_t *sess;
    ck_mechanism_type_t *mlist;
    
    ctx = pakchois_module_load(argv[1]);

    if (ctx == NULL) {
        printf("create failed!\n");
        return 1;
    }

    puts("ok");

    if (pakchois_get_info(ctx, &info) == CKR_OK) {
        printf("version: %u.%u\n", info.cryptoki_version.major, 
               info.cryptoki_version.minor);
        printf("manufacturer: %.32s\n", info.manufacturer_id);
        printf("library: %.32s\n", info.library_description);
    }    

    if (pakchois_get_slot_list(ctx, 0, NULL, &count) == CKR_OK
        && (slots = malloc(count * sizeof *slots)) != NULL
        && pakchois_get_slot_list(ctx, 0, slots, &count) == CKR_OK) {
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
                              CKF_SERIAL_SESSION | CKF_RW_SESSION, 
                              notify_fn, NULL, &sess) == CKR_OK) {
        puts("session open!\n");
    }                         
    else {
        puts("sessopen failed\n");
        return 1;
    }

    if (pakchois_login(sess, CKU_USER, "foobar", 6) == CKR_OK) {
        puts("login OK\n");
    }
    else {
        puts("login failed\n");
    }

    if (pakchois_get_mechanism_list(ctx, slots[0], NULL, &count) == CKR_OK
        && (mlist = malloc(count * sizeof *mlist)) != NULL
        && pakchois_get_mechanism_list(ctx, slots[0], mlist, &count) == CKR_OK) {
        unsigned long n;

        printf("got mech list (%ld):\n", count);

        for (n = 0; n < count; n++) {
            printf("  0x%04x\n", mlist[n]);
        }
    }

    pakchois_close_session(sess);

    pakchois_module_destroy(ctx);

    return 0;
}
