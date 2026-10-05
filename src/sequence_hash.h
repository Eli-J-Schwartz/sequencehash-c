#include <stdint.h>
#include <stdbool.h>

#include "hash_functions/sha2.h"
#include "hash_functions/sha3.h"

typedef enum sequence_function_status {
    SEQUENCE_FUNCTION_UNINITIALIZED = 0,
    SEQUENCE_FUNCTION_INITIALIZED = 1,
    SEQUENCE_FUNCTION_FINALIZED = 2,
} sequence_function_status;

#define GENERATE_SEQUENCE_FUNCTION_STATE(name) \
typedef struct name##_sequence_function_state {\
    uint8_t k_o[name##_BLOCK_SIZE];\
    uint8_t k_i[name##_BLOCK_SIZE];\
    uint64_t k_len;\
    uint64_t f_type;\
    uint64_t input_count;\
    name##_state internal_state;\
    sequence_function_status status;\
} name##_sequence_function_state;

#define GENERATE_SEQHSH_DEFS(name) \
typedef struct sequence_hash_##name##_state {name##_sequence_function_state internal_state;} sequence_hash_##name##_state;\
bool sequence_hash_##name##_init(sequence_hash_##name##_state* state);\
bool sequence_hash_##name##_add(sequence_hash_##name##_state* state, uint8_t* input, uint64_t input_len);\
bool sequence_hash_##name##_finalize(sequence_hash_##name##_state* state, uint8_t* output);\
bool sequence_hash_##name##_finalize_with_customizer(sequence_hash_##name##_state* state, uint8_t* s, uint64_t s_len, uint8_t* output);\
uint64_t sequence_hash_##name##_output_size();\
uint64_t sequence_hash_##name##_block_size();

#define GENERATE_SEQMAC_DEFS(name) \
typedef struct sequence_mac_##name##_state {name##_sequence_function_state internal_state;} sequence_mac_##name##_state;\
bool sequence_mac_##name##_init(sequence_mac_##name##_state* state, uint8_t* k, uint64_t k_len);\
bool sequence_mac_##name##_add(sequence_mac_##name##_state* state, uint8_t* input, uint64_t input_len);\
bool sequence_mac_##name##_finalize(sequence_mac_##name##_state* state, uint8_t* output);\
bool sequence_mac_##name##_finalize_with_customizer(sequence_mac_##name##_state* state, uint8_t* s, uint64_t s_len, uint8_t* output);\
uint64_t sequence_mac_##name##_output_size();\
uint64_t sequence_mac_##name##_block_size();

#define GENERATE_DEFS(name) \
GENERATE_SEQUENCE_FUNCTION_STATE(name) \
GENERATE_SEQHSH_DEFS(name) \
GENERATE_SEQMAC_DEFS(name)

GENERATE_DEFS(sha256)
GENERATE_DEFS(sha512)
GENERATE_DEFS(sha3_256)
GENERATE_DEFS(sha3_512)
