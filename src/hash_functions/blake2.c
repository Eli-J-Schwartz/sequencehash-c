#include "blake2.h"

uint32_t blake2_SELECTORS[12][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
};

uint32_t blake2s_IV[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

#define blake2s_RROT(x,n) (((x)>>(n))^((x)<<(32-(n))))

#define blake2s_GFUNC(a, b, c, d, m0, m1) \
a = a + b + m0;\
d = blake2s_RROT(d^a, 16);\
c = c + d;\
b = blake2s_RROT(b^c, 12);\
a = a + b + m1;\
d = blake2s_RROT(d^a, 8);\
c = c + d;\
b = blake2s_RROT(b^c, 7);

void blake2s_round_function(blake2s_state* state, uint64_t count, uint32_t final) {
    uint32_t message_vars[16] = {0};
    for (int i = 0; i < blake2s_BLOCK_SIZE; i++) {
        message_vars[i/4] ^= ((uint32_t) state->input_block[i]) << (8*(i%4));
    }

    uint32_t internal_state[16] = {0};
    for (int i = 0; i < 8; i++) {
        internal_state[i] = state->internal_state[i];
        internal_state[i+8] = blake2s_IV[i];
    }
    internal_state[12] ^= count & 0xffffffff;
    internal_state[13] ^= count >> 32;
    internal_state[14] ^= final;

    for (int i = 0; i < 10; i++) {
        blake2s_GFUNC(internal_state[0], internal_state[4], internal_state[8], internal_state[12], message_vars[blake2_SELECTORS[i][0]], message_vars[blake2_SELECTORS[i][1]])
        blake2s_GFUNC(internal_state[1], internal_state[5], internal_state[9], internal_state[13], message_vars[blake2_SELECTORS[i][2]], message_vars[blake2_SELECTORS[i][3]])
        blake2s_GFUNC(internal_state[2], internal_state[6], internal_state[10], internal_state[14], message_vars[blake2_SELECTORS[i][4]], message_vars[blake2_SELECTORS[i][5]])
        blake2s_GFUNC(internal_state[3], internal_state[7], internal_state[11], internal_state[15], message_vars[blake2_SELECTORS[i][6]], message_vars[blake2_SELECTORS[i][7]])
        blake2s_GFUNC(internal_state[0], internal_state[5], internal_state[10], internal_state[15], message_vars[blake2_SELECTORS[i][8]], message_vars[blake2_SELECTORS[i][9]])
        blake2s_GFUNC(internal_state[1], internal_state[6], internal_state[11], internal_state[12], message_vars[blake2_SELECTORS[i][10]], message_vars[blake2_SELECTORS[i][11]])
        blake2s_GFUNC(internal_state[2], internal_state[7], internal_state[8], internal_state[13], message_vars[blake2_SELECTORS[i][12]], message_vars[blake2_SELECTORS[i][13]])
        blake2s_GFUNC(internal_state[3], internal_state[4], internal_state[9], internal_state[14], message_vars[blake2_SELECTORS[i][14]], message_vars[blake2_SELECTORS[i][15]])
    }

    for (int i = 0; i < 8; i++) {
        state->internal_state[i] ^= internal_state[i] ^ internal_state[i+8];
    }
}

void blake2s_init(blake2s_state* state) {
    for (int i = 0; i < 8; i++) state->internal_state[i] = blake2s_IV[i];
    state->internal_state[0] ^= 0x01010020;
    for (int i = 0; i < blake2s_BLOCK_SIZE; i++) state->input_block[i] = 0;
    state->input_len = 0;
    state->input_pos = 0;
    state->input_count = 0;
}

void blake2s_update(blake2s_state* state, const uint8_t* input, uint64_t input_len) {
    for (int i = 0; i < input_len; i++) {
        if (state->input_pos == blake2s_BLOCK_SIZE) {
            state->input_count += blake2s_BLOCK_SIZE;
            blake2s_round_function(state, state->input_count, 0);
            state->input_pos = 0;
        }
        state->input_block[state->input_pos] = input[i];
        state->input_pos++;
    }
    state->input_len += input_len;
}

void blake2s_finalize(uint8_t* output, blake2s_state* state) {
    for (int i = state->input_pos; i < blake2s_BLOCK_SIZE; i++) state->input_block[i] = 0;
    blake2s_round_function(state, state->input_len, 0xffffffff);
    for (int i = 0; i < blake2s_OUTPUT_SIZE; i++) {
        output[i] = (state->internal_state[i/4] >> (8*(i%4))) & 0xff;
    }
}



uint64_t blake2b_IV[] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
};

#define blake2b_RROT(x,n) (((x)>>(n))^((x)<<(64-(n))))

#define blake2b_GFUNC(a, b, c, d, m0, m1) \
a = a + b + m0;\
d = blake2b_RROT(d^a, 32);\
c = c + d;\
b = blake2b_RROT(b^c, 24);\
a = a + b + m1;\
d = blake2b_RROT(d^a, 16);\
c = c + d;\
b = blake2b_RROT(b^c, 63);

void blake2b_round_function(blake2b_state* state, uint64_t count, uint64_t final) {
    uint64_t message_vars[16] = {0};
    for (int i = 0; i < blake2b_BLOCK_SIZE; i++) {
        message_vars[i/8] ^= ((uint64_t) state->input_block[i]) << (8*(i%8));
    }

    uint64_t internal_state[16] = {0};
    for (int i = 0; i < 8; i++) {
        internal_state[i] = state->internal_state[i];
        internal_state[i+8] = blake2b_IV[i];
    }
    internal_state[12] ^= count;
    internal_state[14] ^= final;

    for (int i = 0; i < 12; i++) {
        blake2b_GFUNC(internal_state[0], internal_state[4], internal_state[8], internal_state[12], message_vars[blake2_SELECTORS[i][0]], message_vars[blake2_SELECTORS[i][1]])
        blake2b_GFUNC(internal_state[1], internal_state[5], internal_state[9], internal_state[13], message_vars[blake2_SELECTORS[i][2]], message_vars[blake2_SELECTORS[i][3]])
        blake2b_GFUNC(internal_state[2], internal_state[6], internal_state[10], internal_state[14], message_vars[blake2_SELECTORS[i][4]], message_vars[blake2_SELECTORS[i][5]])
        blake2b_GFUNC(internal_state[3], internal_state[7], internal_state[11], internal_state[15], message_vars[blake2_SELECTORS[i][6]], message_vars[blake2_SELECTORS[i][7]])
        blake2b_GFUNC(internal_state[0], internal_state[5], internal_state[10], internal_state[15], message_vars[blake2_SELECTORS[i][8]], message_vars[blake2_SELECTORS[i][9]])
        blake2b_GFUNC(internal_state[1], internal_state[6], internal_state[11], internal_state[12], message_vars[blake2_SELECTORS[i][10]], message_vars[blake2_SELECTORS[i][11]])
        blake2b_GFUNC(internal_state[2], internal_state[7], internal_state[8], internal_state[13], message_vars[blake2_SELECTORS[i][12]], message_vars[blake2_SELECTORS[i][13]])
        blake2b_GFUNC(internal_state[3], internal_state[4], internal_state[9], internal_state[14], message_vars[blake2_SELECTORS[i][14]], message_vars[blake2_SELECTORS[i][15]])
    }

    for (int i = 0; i < 8; i++) {
        state->internal_state[i] ^= internal_state[i] ^ internal_state[i+8];
    }
}

void blake2b_init(blake2b_state* state) {
    for (int i = 0; i < 8; i++) state->internal_state[i] = blake2b_IV[i];
    state->internal_state[0] ^= 0x01010040;
    for (int i = 0; i < blake2b_BLOCK_SIZE; i++) state->input_block[i] = 0;
    state->input_len = 0;
    state->input_pos = 0;
    state->input_count = 0;
}

void blake2b_update(blake2b_state* state, const uint8_t* input, uint64_t input_len) {
    for (int i = 0; i < input_len; i++) {
        if (state->input_pos == blake2b_BLOCK_SIZE) {
            state->input_count += blake2b_BLOCK_SIZE;
            blake2b_round_function(state, state->input_count, 0);
            state->input_pos = 0;
        }
        state->input_block[state->input_pos] = input[i];
        state->input_pos++;
    }
    state->input_len += input_len;
}

void blake2b_finalize(uint8_t* output, blake2b_state* state) {
    for (int i = state->input_pos; i < blake2b_BLOCK_SIZE; i++) state->input_block[i] = 0;
    blake2b_round_function(state, state->input_len, 0xffffffffffffffff);
    for (int i = 0; i < blake2b_OUTPUT_SIZE; i++) {
        output[i] = (state->internal_state[i/8] >> (8*(i%8))) & 0xff;
    }
}
