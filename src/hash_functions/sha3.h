#include <stdint.h>

#define sha3_256_BLOCK_SIZE 136
#define sha3_256_OUTPUT_SIZE 32
typedef struct sha3_256_state {
    uint64_t internal_state[25];
    uint64_t input_pos;
} sha3_256_state;
void sha3_256_init(sha3_256_state* state);
void sha3_256_update(sha3_256_state* state, const uint8_t* input, uint64_t input_len);
void sha3_256_finalize(uint8_t* output, sha3_256_state* state);

#define sha3_512_BLOCK_SIZE 72
#define sha3_512_OUTPUT_SIZE 64
typedef struct sha3_512state {
    uint64_t internal_state[25];
    uint64_t input_pos;
} sha3_512_state;
void sha3_512_init(sha3_512_state* state);
void sha3_512_update(sha3_512_state* state, const uint8_t* input, uint64_t input_len);
void sha3_512_finalize(uint8_t* output, sha3_512_state* state);
