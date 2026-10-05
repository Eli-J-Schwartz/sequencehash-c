#include <stdint.h>

#define sha256_BLOCK_SIZE 64
#define sha256_OUTPUT_SIZE 32
typedef struct sha256_state {
    uint32_t internal_state[8];
    uint8_t input_block[64];
    uint64_t input_len;
    uint64_t input_pos;
} sha256_state;
void sha256_init(sha256_state* state);
void sha256_update(sha256_state* state, const uint8_t* input, uint64_t input_len);
void sha256_finalize(uint8_t* output, sha256_state* state);

#define sha512_BLOCK_SIZE 128
#define sha512_OUTPUT_SIZE 64
typedef struct sha512_state {
    uint64_t internal_state[8];
    uint8_t input_block[128];
    uint64_t input_len;
    uint64_t input_pos;
} sha512_state;
void sha512_init(sha512_state* state);
void sha512_update(sha512_state* state, const uint8_t* input, uint64_t input_len);
void sha512_finalize(uint8_t* output, sha512_state* state);
