#include <stdint.h>

#define blake2s_BLOCK_SIZE 64
#define blake2s_OUTPUT_SIZE 32
typedef struct blake2s_state {
    uint32_t internal_state[8];
    uint8_t input_block[64];
    uint64_t input_len;
    uint64_t input_pos;
    uint64_t input_count;
} blake2s_state;
void blake2s_init(blake2s_state* state);
void blake2s_update(blake2s_state* state, const uint8_t* input, uint64_t input_len);
void blake2s_finalize(uint8_t* output, blake2s_state* state);

#define blake2b_BLOCK_SIZE 128
#define blake2b_OUTPUT_SIZE 64
typedef struct blake2b_state {
    uint64_t internal_state[8];
    uint8_t input_block[128];
    uint64_t input_len;
    uint64_t input_pos;
    uint64_t input_count;
} blake2b_state;
void blake2b_init(blake2b_state* state);
void blake2b_update(blake2b_state* state, const uint8_t* input, uint64_t input_len);
void blake2b_finalize(uint8_t* output, blake2b_state* state);
