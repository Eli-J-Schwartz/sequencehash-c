#include "sha3.h"

uint64_t sha3_RC[] = {
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008
};

uint64_t sha3_MOVS[] = {
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4
};

uint64_t sha3_ROTS[] = {
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
};

#define sha3_LROT(x,n) (((x)<<(n))^((x)>>(64-(n))))

void sha3_round_function(uint64_t* sha3_state) {
    for (int round = 0; round < 24; round++) {
        uint64_t temp[25] = {0};
        for (int i = 0; i < 25; i++) temp[i%5] ^= sha3_state[i];
        for (int i = 0; i < 25; i++) sha3_state[i] ^= temp[(i+4)%5] ^ sha3_LROT(temp[(i+1)%5], 1);
        temp[0] = sha3_state[0];
        for (int i = 1; i < 25; i++) temp[sha3_MOVS[i]] = sha3_LROT(sha3_state[i], sha3_ROTS[i]);
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                sha3_state[y*5+x] = temp[y*5+x] ^ (temp[y*5+(x+2)%5] & ~temp[y*5+(x+1)%5]);
            }
        }
        sha3_state[0] ^= sha3_RC[round];
    }
}

void sha3_256_init(sha3_256_state* state) {
    for (int i = 0; i < 25; i++) state->internal_state[i] = 0;
    state->input_pos = 0;
}

void sha3_256_update(sha3_256_state* state, const uint8_t* input, uint64_t input_len) {
    for (uint64_t i = 0; i < input_len; i++) {
        state->internal_state[state->input_pos/8] ^= ((uint64_t) input[i]) << (state->input_pos%8*8);
        if (++state->input_pos == sha3_256_BLOCK_SIZE) {
            sha3_round_function(state->internal_state);
            state->input_pos = 0;
        }
    }
}

void sha3_256_finalize(uint8_t* output, sha3_256_state* state) {
    state->internal_state[state->input_pos/8] ^= ((uint64_t) 0x06) << (state->input_pos%8*8);
    state->internal_state[sha3_256_BLOCK_SIZE/8-1] ^= ((uint64_t) 0x80) << 56;
    sha3_round_function(state->internal_state);
    for (int i = 0; i < sha3_256_OUTPUT_SIZE; i++) output[i] = (state->internal_state[i/8] >> (i%8*8)) & 0xff;
}



void sha3_512_init(sha3_512_state* state) {
    for (int i = 0; i < 25; i++) state->internal_state[i] = 0;
    state->input_pos = 0;
}

void sha3_512_update(sha3_512_state* state, const uint8_t* input, uint64_t input_len) {
    for (uint64_t i = 0; i < input_len; i++) {
        state->internal_state[state->input_pos/8] ^= ((uint64_t) input[i]) << (state->input_pos%8*8);
        if (++state->input_pos == sha3_512_BLOCK_SIZE) {
            sha3_round_function(state->internal_state);
            state->input_pos = 0;
        }
    }
}

void sha3_512_finalize(uint8_t* output, sha3_512_state* state) {
    state->internal_state[state->input_pos/8] ^= ((uint64_t) 0x06) << (state->input_pos%8*8);
    state->internal_state[sha3_512_BLOCK_SIZE/8-1] ^= ((uint64_t) 0x80) << 56;
    sha3_round_function(state->internal_state);
    for (int i = 0; i < sha3_512_OUTPUT_SIZE; i++) {
        output[i] = (state->internal_state[i/8] >> (i%8*8)) & 0xff;
    }
}
