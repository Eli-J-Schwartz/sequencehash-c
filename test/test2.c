#include "../src/sequence_hash.h"
#include <stdio.h>

int main() {
    sequence_hash_sha256_state state_1;
    sequence_hash_sha256_init(&state_1);
    sequence_hash_sha256_add(&state_1, "ab", 2);
    sequence_hash_sha256_add(&state_1, "cd", 2);
    uint8_t output_1[32];
    sequence_hash_sha256_finalize(&state_1, output_1);
    for (int i = 0; i < 32; i++) printf("%02x", output_1[i]);
    printf("\n");
    
    sequence_hash_sha256_state state_2;
    sequence_hash_sha256_init(&state_2);
    sequence_hash_sha256_add(&state_2, "abcd", 4);
    uint8_t output_2[32];
    sequence_hash_sha256_finalize(&state_2, output_2);
    for (int i = 0; i < 32; i++) printf("%02x", output_2[i]);
    printf("\n");

    sequence_hash_sha256_state state_3;
    sequence_hash_sha256_init(&state_3);
    sequence_hash_sha256_add(&state_3, "abcd", 4);
    uint8_t output_3[32];
    sequence_hash_sha256_finalize_with_customizer(&state_3, "customizer1", 11, output_3);
    for (int i = 0; i < 32; i++) printf("%02x", output_3[i]);
    printf("\n");
    
    sequence_hash_sha256_state state_4;
    sequence_hash_sha256_init(&state_4);
    sequence_hash_sha256_add(&state_4, "abcd", 4);
    uint8_t output_4[32];
    sequence_hash_sha256_finalize_with_customizer(&state_4, "customizer2", 11, output_4);
    for (int i = 0; i < 32; i++) printf("%02x", output_4[i]);
    printf("\n");

    sequence_mac_sha256_state state_5;
    uint8_t key_5[] = {
        0x1f, 0xc7, 0x9f, 0x24, 0x45, 0x02, 0x2b, 0xbc,
        0x44, 0xcf, 0xa1, 0x40, 0xd7, 0x6e, 0x59, 0x22,
        0xaa, 0x81, 0xac, 0xe6, 0xba, 0xdd, 0xba, 0x2f,
        0x8a, 0x59, 0xac, 0xaf, 0x8b, 0x49, 0xea, 0x06
    };
    sequence_mac_sha256_init(&state_5, key_5, 32);
    sequence_mac_sha256_add(&state_5, "abcd", 4);
    uint8_t output_5[32];
    sequence_mac_sha256_finalize(&state_5, output_5);
    for (int i = 0; i < 32; i++) printf("%02x", output_5[i]);
    printf("\n");

    sequence_mac_sha256_state state_6;
    uint8_t key_6[] = {
        0x65, 0x50, 0x6e, 0x9e, 0xc5, 0x4e, 0x98, 0x56,
        0x8f, 0x22, 0x88, 0xce, 0x7f, 0x9f, 0xcc, 0x41,
        0x71, 0x9e, 0xc1, 0x7e, 0x89, 0xd9, 0x5d, 0x7b,
        0x12, 0x07, 0x49, 0xa9, 0xc5, 0x70, 0x1c, 0x5a
    };
    sequence_mac_sha256_init(&state_6, key_6, 32);
    sequence_mac_sha256_add(&state_6, "abcd", 4);
    uint8_t output_6[32];
    sequence_mac_sha256_finalize(&state_6, output_6);
    for (int i = 0; i < 32; i++) printf("%02x", output_6[i]);
    printf("\n");

    sequence_mac_sha256_state state_7;
    uint8_t key_7[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    sequence_mac_sha256_init(&state_7, key_7, 32);
    sequence_mac_sha256_add(&state_7, "abcd", 4);
    uint8_t output_7[32];
    sequence_mac_sha256_finalize_with_customizer(&state_7, "customizer 0", 12, output_7);
    for (int i = 0; i < 32; i++) printf("%02x", output_7[i]);
    printf("\n");

    sequence_mac_sha256_state state_8;
    uint8_t key_8[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    sequence_mac_sha256_init(&state_8, key_8, 32);
    sequence_mac_sha256_add(&state_8, "abcd", 4);
    uint8_t output_8[32];
    sequence_mac_sha256_finalize_with_customizer(&state_8, "customizer 1", 12, output_8);
    for (int i = 0; i < 32; i++) printf("%02x", output_8[i]);
    printf("\n");
};
