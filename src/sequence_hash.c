#include "sequence_hash.h"
#include <stddef.h>

#define F_SEQHSH 2
#define F_SEQMAC 1

void store_int_msb(uint64_t input, uint8_t* output) {
    for (int i = 0; i < 8; i++) output[i] = 0;
    for (int i = 0; i < 8; i++) output[i+8] = (input >> (56-i*8)) & 0xff;
}

void store_int_lsb(uint64_t input, uint8_t* output) {
    for (int i = 0; i < 8; i++) output[i] = (input >> (i*8)) & 0xff;
    for (int i = 0; i < 8; i++) output[i+8] = 0;
}

#define PAD_LEN(x, b) ((x) == 0 ? (b) : (x) % (b) == 0 ? 0 : ((b) - (x) % (b))) 

#define GENERATE_DERIVE_FUNCTION(name) \
void name##_derive_key(uint8_t* input, uint64_t input_len, uint8_t* output, uint8_t t) {\
    if (input_len <= name##_BLOCK_SIZE) {\
        for (int i = 0; i < input_len; i++) output[i] = input[i];\
        for (int i = input_len; i < name##_BLOCK_SIZE; i++) output[i] = 0;\
    } else {\
        name##_state state;\
        name##_init(&state);\
        name##_update(&state, input, input_len);\
        name##_finalize(output, &state);\
        for (int i = name##_OUTPUT_SIZE; i < name##_BLOCK_SIZE; i++) output[i] = 0;\
    }\
    output[0] ^= t;\
}

#define GENERATE_SEQUENCE_FUNCTION_INIT(name) \
bool name##_sequence_function_init(name##_sequence_function_state* state, uint8_t* k, uint64_t k_len, uint64_t f_type) {\
    if (k_len > 0 && k == NULL) return true;\
    uint8_t k_i[name##_BLOCK_SIZE];\
    name##_derive_key(k, k_len, k_i, 0x55);\
    name##_derive_key(k, k_len, state->k_o, 0xaa);\
    state->k_len = k_len;\
    state->input_count = 0;\
    \
    name##_init(&state->internal_state);\
    name##_update(&state->internal_state, k_i, name##_BLOCK_SIZE);\
    name##_update(&state->internal_state, "SEQHSH_I", 8);\
    uint8_t temp[16];\
    store_int_msb(f_type, temp);\
    name##_update(&state->internal_state, temp, 16);\
    store_int_msb(k_len, temp);\
    name##_update(&state->internal_state, temp, 16);\
    uint8_t pad[PAD_LEN(8+16+16, name##_BLOCK_SIZE)] = {0};\
    name##_update(&state->internal_state, pad, PAD_LEN(8+16+16, name##_BLOCK_SIZE));\
    state->status = SEQUENCE_FUNCTION_INITIALIZED;\
    return false;\
}

#define GENERATE_SEQUENCE_FUNCTION_ADD(name) \
bool name##_sequence_function_add(name##_sequence_function_state* state, uint8_t* input, uint64_t input_len) {\
    if (state->status != SEQUENCE_FUNCTION_INITIALIZED) return true;\
    if (input_len > 0 && input == NULL) return true;\
    name##_update(&state->internal_state, input, input_len);\
    uint8_t temp[16];\
    store_int_lsb(input_len, temp);\
    name##_update(&state->internal_state, temp, 16);\
    state->input_count++;\
    return false;\
}

#define GENERATE_SEQUENCE_FUNCTION_FINALIZE(name) \
bool name##_sequence_function_finalize(name##_sequence_function_state* state, uint8_t* s, uint64_t s_len, uint8_t* output, uint64_t f_type) {\
    if (state->status != SEQUENCE_FUNCTION_INITIALIZED) return true;\
    if ((s > 0 && s == NULL) || output == NULL) return true;\
    name##_state final_state;\
    name##_init(&final_state);\
    name##_update(&final_state, state->k_o, name##_BLOCK_SIZE);\
    name##_update(&final_state, "SEQHSH_O", 8);\
    uint8_t temp[16];\
    store_int_msb(f_type, temp);\
    name##_update(&final_state, temp, 16);\
    store_int_msb(s_len, temp);\
    name##_update(&final_state, temp, 16);\
    store_int_msb(state->k_len, temp);\
    name##_update(&final_state, temp, 16);\
    uint8_t pad[PAD_LEN(8+16+16+16, name##_BLOCK_SIZE)] = {0};\
    name##_update(&final_state, pad, PAD_LEN(8+16+16+16, name##_BLOCK_SIZE));\
    uint8_t s_p[name##_BLOCK_SIZE];\
    name##_derive_key(s, s_len, s_p, 0x00);\
    name##_update(&final_state, s_p, name##_BLOCK_SIZE);\
    store_int_msb(state->input_count, temp);\
    name##_update(&final_state, temp, 16);\
    store_int_msb(name##_OUTPUT_SIZE, temp);\
    name##_update(&final_state, temp, 16);\
    uint8_t internal_output[name##_OUTPUT_SIZE];\
    name##_finalize(internal_output, &state->internal_state);\
    name##_update(&final_state, internal_output, name##_OUTPUT_SIZE);\
    name##_finalize(output, &final_state);\
    state->status = SEQUENCE_FUNCTION_FINALIZED;\
    return false;\
}

#define GENERATE_SEQHSH(name) \
bool sequence_hash_##name##_init(sequence_hash_##name##_state* state) {\
    return name##_sequence_function_init(&state->internal_state, NULL, 0, F_SEQHSH);\
}\
bool sequence_hash_##name##_add(sequence_hash_##name##_state* state, uint8_t* input, uint64_t input_len) {\
    return name##_sequence_function_add(&state->internal_state, input, input_len);\
}\
bool sequence_hash_##name##_finalize(sequence_hash_##name##_state* state, uint8_t* output) {\
    return name##_sequence_function_finalize(&state->internal_state, NULL, 0, output, F_SEQHSH);\
}\
bool sequence_hash_##name##_finalize_with_customizer(sequence_hash_##name##_state* state, uint8_t* s, uint64_t s_len, uint8_t* output) {\
    return name##_sequence_function_finalize(&state->internal_state, s, s_len, output, F_SEQHSH);\
}\
uint64_t sequence_hash_##name##_output_size() {return name##_OUTPUT_SIZE;}\
uint64_t sequence_hash_##name##_block_size() {return name##_BLOCK_SIZE;}

#define GENERATE_SEQMAC(name) \
bool sequence_mac_##name##_init(sequence_mac_##name##_state* state, uint8_t* k, uint64_t k_len) {\
    if (k_len < 32) return true;\
    return name##_sequence_function_init(&state->internal_state, k, k_len, F_SEQMAC);\
}\
bool sequence_mac_##name##_add(sequence_mac_##name##_state* state, uint8_t* input, uint64_t input_len) {\
    return name##_sequence_function_add(&state->internal_state, input, input_len);\
}\
bool sequence_mac_##name##_finalize(sequence_mac_##name##_state* state, uint8_t* output) {\
    return name##_sequence_function_finalize(&state->internal_state, NULL, 0, output, F_SEQMAC);\
}\
bool sequence_mac_##name##_finalize_with_customizer(sequence_mac_##name##_state* state, uint8_t* s, uint64_t s_len, uint8_t* output) {\
    return name##_sequence_function_finalize(&state->internal_state, s, s_len, output, F_SEQMAC);\
}\
uint64_t sequence_mac_##name##_output_size() {return name##_OUTPUT_SIZE;}\
uint64_t sequence_mac_##name##_block_size() {return name##_BLOCK_SIZE;}

#define GENERATE_ALL(name) \
GENERATE_SEQUENCE_FUNCTION_STATE(name) \
GENERATE_DERIVE_FUNCTION(name) \
GENERATE_SEQUENCE_FUNCTION_INIT(name) \
GENERATE_SEQUENCE_FUNCTION_ADD(name) \
GENERATE_SEQUENCE_FUNCTION_FINALIZE(name) \
GENERATE_SEQHSH(name) \
GENERATE_SEQMAC(name)

GENERATE_ALL(sha256)
GENERATE_ALL(sha512)
GENERATE_ALL(sha3_256)
GENERATE_ALL(sha3_512)
GENERATE_ALL(blake2s)
GENERATE_ALL(blake2b)
