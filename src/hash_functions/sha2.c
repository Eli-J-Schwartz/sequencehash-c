#include "sha2.h"

uint32_t sha256_IV[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

uint32_t sha256_RC[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define sha256_RROT(x,n) (((x)>>(n))^((x)<<(32-(n))))

void sha256_round_function(sha256_state* state) {
    uint32_t message_vars[64] = {0};
    for (int i = 0; i < sha256_BLOCK_SIZE; i++) {
        message_vars[i/4] ^= ((uint32_t) state->input_block[i]) << (uint32_t)(24-8*(i%4));
    }

    for (int i = 16; i < 64; i++) {
        uint32_t s0 = sha256_RROT(message_vars[i-15], 7) ^ sha256_RROT(message_vars[i-15], 18) ^ (message_vars[i-15] >> 3);
        uint32_t s1 = sha256_RROT(message_vars[i-2], 17) ^ sha256_RROT(message_vars[i-2], 19) ^ (message_vars[i-2] >> 10);
        message_vars[i] = message_vars[i-16] + message_vars[i-7] + s0 + s1;
    }

    uint32_t 
        a = state->internal_state[0],
        b = state->internal_state[1],
        c = state->internal_state[2],
        d = state->internal_state[3],
        e = state->internal_state[4],
        f = state->internal_state[5],
        g = state->internal_state[6],
        h = state->internal_state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = sha256_RROT(e, 6) ^ sha256_RROT(e, 11) ^ sha256_RROT(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + message_vars[i] + sha256_RC[i];
        uint32_t S0 = sha256_RROT(a, 2) ^ sha256_RROT(a, 13) ^ sha256_RROT(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state->internal_state[0] += a;
    state->internal_state[1] += b;
    state->internal_state[2] += c;
    state->internal_state[3] += d;
    state->internal_state[4] += e;
    state->internal_state[5] += f;
    state->internal_state[6] += g;
    state->internal_state[7] += h;
}

void sha256_init(sha256_state* state) {
    for (int i = 0; i < 8; i++) state->internal_state[i] = sha256_IV[i];
    for (int i = 0; i < sha256_BLOCK_SIZE; i++) state->input_block[i] = 0;
    state->input_len = 0;
    state->input_pos = 0;
}

void sha256_update(sha256_state* state, const uint8_t* input, uint64_t input_len) {
    for (uint64_t i = 0; i < input_len; i++) {
        state->input_block[state->input_pos] = input[i];
        if (++state->input_pos == sha256_BLOCK_SIZE) {
            sha256_round_function(state);
            state->input_pos = 0;
        }
    }
    state->input_len += input_len;
}

void sha256_finalize(uint8_t* output, sha256_state* state) {
    state->input_block[state->input_pos] = 0x80;
    if (++state->input_pos > 56) {
        for (int i = state->input_pos; i < sha256_BLOCK_SIZE; i++) state->input_block[i] = 0;
        sha256_round_function(state);
        state->input_pos = 0;
    }
    for (uint64_t i = state->input_pos; i < 64; i++) state->input_block[i] = 0;
    state->input_len *= 8;
    for (int i = 0; i < 8; i++) state->input_block[63-i] = (state->input_len >> (8*i)) & 0xff;
    sha256_round_function(state);
    for (int i = 0; i < sha256_OUTPUT_SIZE; i++) output[i] = (state->internal_state[i/4] >> (24-8*(i%4))) & 0xff;
}



uint64_t sha512_IV[] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
};

uint64_t sha512_RC[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

#define sha512_RROT(x,n) (((x)>>(n))^((x)<<(64-(n))))

void sha512_round_function(sha512_state* state) {
    uint64_t message_vars[80] = {0};
    for (int i = 0; i < sha512_BLOCK_SIZE; i++) {
        message_vars[i/8] ^= ((uint64_t) state->input_block[i]) << (56-8*(i%8));
    }

    for (int i = 16; i < 80; i++) {
        uint64_t s0 = sha512_RROT(message_vars[i-15], 1) ^ sha512_RROT(message_vars[i-15], 8) ^ (message_vars[i-15] >> 7);
        uint64_t s1 = sha512_RROT(message_vars[i-2], 19) ^ sha512_RROT(message_vars[i-2], 61) ^ (message_vars[i-2] >> 6);
        message_vars[i] = message_vars[i-16] + message_vars[i-7] + s0 + s1;
    }

    uint64_t 
        a = state->internal_state[0],
        b = state->internal_state[1],
        c = state->internal_state[2],
        d = state->internal_state[3],
        e = state->internal_state[4],
        f = state->internal_state[5],
        g = state->internal_state[6],
        h = state->internal_state[7];

    for (int i = 0; i < 80; i++) {
        uint64_t S1 = sha512_RROT(e, 14) ^ sha512_RROT(e, 18) ^ sha512_RROT(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t temp1 = h + S1 + ch + message_vars[i] + sha512_RC[i];
        uint64_t S0 = sha512_RROT(a, 28) ^ sha512_RROT(a, 34) ^ sha512_RROT(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state->internal_state[0] += a;
    state->internal_state[1] += b;
    state->internal_state[2] += c;
    state->internal_state[3] += d;
    state->internal_state[4] += e;
    state->internal_state[5] += f;
    state->internal_state[6] += g;
    state->internal_state[7] += h;
}

void sha512_init(sha512_state* state) {
    for (int i = 0; i < 8; i++) state->internal_state[i] = sha512_IV[i];
    for (int i = 0; i < sha512_BLOCK_SIZE; i++) state->input_block[i] = 0;
    state->input_len = 0;
    state->input_pos = 0;
}

void sha512_update(sha512_state* state, const uint8_t* input, uint64_t input_len) {
    for (uint64_t i = 0; i < input_len; i++) {
        state->input_block[state->input_pos] = input[i];
        if (++state->input_pos == sha512_BLOCK_SIZE) {
            sha512_round_function(state);
            state->input_pos = 0;
        }
    }
    state->input_len += input_len;
}

void sha512_finalize(uint8_t* output, sha512_state* state) {
    state->input_block[state->input_pos] = 0x80;
    if (++state->input_pos > 112) {
        for (int i = state->input_pos; i < sha512_BLOCK_SIZE; i++) state->input_block[i] = 0;
        sha512_round_function(state);
        state->input_pos = 0;
    }
    for (uint64_t i = state->input_pos; i < 128; i++) state->input_block[i] = 0;
    state->input_block[127] = (state->input_len << 3) & 0xff;
    for (int i = 1; i < 9; i++) state->input_block[127-i] = (state->input_len >> (8*i-3)) & 0xff;
    sha512_round_function(state);
    for (int i = 0; i < sha512_OUTPUT_SIZE; i++) output[i] = (state->internal_state[i/8] >> (56-8*(i%8))) & 0xff;
}
