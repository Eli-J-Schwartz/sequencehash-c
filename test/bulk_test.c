#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "../src/sequence_hash.h"

uint8_t decode_hex_char(char c) {
    if ('0' <= c && c <= '9') return c-'0';
    return c-'a'+10;
}

#define GENERATE_HASH_TEST(name) \
void sequence_hash_##name##_test() {\
    FILE* test_file = fopen("test/test_data/hash/" #name ".json", "r");\
    int test_count = 0;\
    int correct_count = 0;\
    \
    size_t input_len = 0;\
    char* input_line = NULL;\
    getline(&input_line, &input_len, test_file);\
    printf("Starting SequenceHash-" #name " Tests:\n");\
    while (true) {\
        bool correct = true;\
        getline(&input_line, &input_len, test_file);\
        if (strcmp(input_line, "]\n") == 0) break;\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        int customizer_len = getline(&input_line, &input_len, test_file);\
        customizer_len = (customizer_len - 26)/2;\
        uint8_t* customizer = (uint8_t*)malloc(customizer_len+1);\
        for (int i = 0; i < customizer_len; i++) customizer[i] = decode_hex_char(input_line[23+i*2])*16+decode_hex_char(input_line[24+i*2]);\
        customizer[customizer_len]=0;\
        printf("SequenceHash-" #name " Test #%03d: %s", test_count, customizer);\
        sequence_hash_##name##_state state;\
        if (sequence_hash_##name##_init(&state)) correct = false;\
        getline(&input_line, &input_len, test_file);\
        if (strcmp(input_line, "        \"inputs\": [],\n") != 0)\
            while (true) {\
                int in_len = getline(&input_line, &input_len, test_file);\
                if (strcmp(input_line, "        ],\n") == 0) break;\
                in_len = (in_len - 15)/2;\
                uint8_t* in = (uint8_t*)malloc(in_len);\
                for (int i = 0; i < in_len; i++) in[i] = decode_hex_char(input_line[13+i*2])*16+decode_hex_char(input_line[14+i*2]);\
                if (sequence_hash_##name##_add(&state, in, in_len)) correct = false;\
                free(in);\
            }\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        uint8_t output[sequence_hash_##name##_output_size()];\
        if (sequence_hash_##name##_finalize_with_customizer(&state, customizer, customizer_len, output)) correct = false;\
        uint8_t* expected = (uint8_t*)malloc(sequence_hash_##name##_output_size());\
        for (int i = 0; i < sequence_hash_##name##_output_size(); i++) expected[i] = decode_hex_char(input_line[25+i*2])*16+decode_hex_char(input_line[26+i*2]);\
        for (int i = 0; i < sequence_hash_##name##_output_size(); i++) if (output[i] != expected[i]) correct = false;\
        if (correct) printf(" [\x1b[32mPASS\x1b[0m]\n");\
        else printf(" [\x1b[31mFAIL\x1b[0m]\n");\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        test_count++;\
        if (correct) correct_count++;\
        free(expected);\
        free(customizer);\
    }\
    if (input_line) free(input_line);\
    fclose(test_file);\
    printf("Results for SequenceHash-" #name " Tests: %d/%d Correct", correct_count, test_count);\
    if (correct_count == test_count) printf(" [\x1b[32mALL PASSED\x1b[0m]\n");\
    else printf(" [\x1b[31mSOME FAILED\x1b[0m]\n");\
}

#define GENERATE_MAC_TEST(name) \
void sequence_mac_##name##_test() {\
    FILE* test_file = fopen("test/test_data/mac/" #name ".json", "r");\
    int test_count = 0;\
    int correct_count = 0;\
    \
    size_t input_len = 0;\
    char* input_line = NULL;\
    getline(&input_line, &input_len, test_file);\
    printf("Starting SequenceMAC-" #name " Tests:\n");\
    while (true) {\
        bool correct = true;\
        getline(&input_line, &input_len, test_file);\
        if (strcmp(input_line, "]\n") == 0) break;\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        int key_len = getline(&input_line, &input_len, test_file);\
        key_len = (key_len - 19)/2;\
        uint8_t* key = (uint8_t*)malloc(key_len);\
        for (int i = 0; i < key_len; i++) key[i] = decode_hex_char(input_line[16+i*2])*16+decode_hex_char(input_line[17+i*2]);\
        int customizer_len = getline(&input_line, &input_len, test_file);\
        customizer_len = (customizer_len - 26)/2;\
        uint8_t* customizer = (uint8_t*)malloc(customizer_len+1);\
        for (int i = 0; i < customizer_len; i++) customizer[i] = decode_hex_char(input_line[23+i*2])*16+decode_hex_char(input_line[24+i*2]);\
        customizer[customizer_len]=0;\
        printf("SequenceHash-" #name " Test #%03d: %s", test_count, customizer);\
        sequence_mac_##name##_state state;\
        if (sequence_mac_##name##_init(&state, key, key_len)) correct = false;\
        getline(&input_line, &input_len, test_file);\
        if (strcmp(input_line, "        \"inputs\": [],\n") != 0)\
            while (true) {\
                int in_len = getline(&input_line, &input_len, test_file);\
                if (strcmp(input_line, "        ],\n") == 0) break;\
                in_len = (in_len - 15)/2;\
                uint8_t* in = (uint8_t*)malloc(in_len);\
                for (int i = 0; i < in_len; i++) in[i] = decode_hex_char(input_line[13+i*2])*16+decode_hex_char(input_line[14+i*2]);\
                if (sequence_mac_##name##_add(&state, in, in_len)) correct = false;\
                free(in);\
            }\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        bool expected_fail = (strcmp(input_line, "        \"must_fail\": true,\n") == 0);\
        getline(&input_line, &input_len, test_file);\
        uint8_t output[sequence_mac_##name##_output_size()];\
        if (sequence_mac_##name##_finalize_with_customizer(&state, customizer, customizer_len, output)) correct = false;\
        if (!expected_fail) {\
            uint8_t* expected = (uint8_t*)malloc(sequence_mac_##name##_output_size());\
            for (int i = 0; i < sequence_mac_##name##_output_size(); i++) expected[i] = decode_hex_char(input_line[25+i*2])*16+decode_hex_char(input_line[26+i*2]);\
            for (int i = 0; i < sequence_mac_##name##_output_size(); i++) if (output[i] != expected[i]) correct = false;\
            free(expected);\
        }\
        if (expected_fail) correct = !correct;\
        if (correct) printf(" [\x1b[32mPASS\x1b[0m]\n");\
        else printf(" [\x1b[31mFAIL\x1b[0m]\n");\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        getline(&input_line, &input_len, test_file);\
        test_count++;\
        if (correct) correct_count++;\
        free(key);\
        free(customizer);\
    }\
    if (input_line) free(input_line);\
    fclose(test_file);\
    printf("Results for SequenceHash-" #name " Tests: %d/%d Correct", correct_count, test_count);\
    if (correct_count == test_count) printf(" [\x1b[32mALL PASSED\x1b[0m]\n");\
    else printf(" [\x1b[31mSOME FAILED\x1b[0m]\n");\
}

GENERATE_HASH_TEST(sha256)
GENERATE_HASH_TEST(sha512)
GENERATE_MAC_TEST(sha256)
GENERATE_MAC_TEST(sha512)

int main() {
    sequence_hash_sha256_test();
    sequence_hash_sha512_test();
    sequence_mac_sha256_test();
    sequence_mac_sha512_test();
}
