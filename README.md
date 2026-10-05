# SequenceHash and SequenceMAC for C

This repository provides the SequenceHash and SequenceMAC functions for the C programming language. You can find more details about the SequenceHash family of functions [here](https://c2sp.org/sequencehash), but the short version is that writing to SequenceHash and SequenceMAC objects is an _atomic_ operation: writing `abcd` is _not_ the same as writing `ab` and `cd` separately.

Right now, SequenceHash and SequenceMAC are only available with the hash functions SHA-256, SHA-512, SHA3-256, and SHA3-512. More will be added soon, and custom hash functions can be added by following the hash function API described below.

# How to Use SequenceHash and SequenceMAC

## Using SequenceHash

To create an SequenceHash object:

```c
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
```

Note that the outputs are different:

```
db972883a869d94f6c9ded7513f83e1b5e8b6c57996859aaa61ccac8386d656c
12714159e45e2865f914d1ba69437d271375dd8028cd510365c546f8f6d2d116
```

You can add domain separation strings if you'll be hashing the same inputs to be  used for separate purposes:

```c
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
```

```
d383645c5e97f9addde6dbb0f750f6029ad69f94398ee8f3e285278d40a89c73
e1b71fac279ffba3d82d17692142392567cf7984f10bbf7310543743211f6b85
```

## Using SequenceMAC

SequenceMAC works similarly to SequenceHash, though the `New` command can return an error if the key you provide is too short:

```c
sequence_mac_sha256_state state_5;
uint8_t key_5[] = {  // key = SHA256("Give Jerry Solinas a raise")
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
```

You'll get `a44519966b12499fd13c9764446e4ca8d57035a21fc5aad669f8029b4405c515` as your output.

Obviously, different keys should give you different outputs:

```c
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
```

The output will be

```
a44519966b12499fd13c9764446e4ca8d57035a21fc5aad669f8029b4405c515
f83e5e78cfb84b52da35e8427953b659ba72073b2ebf48af89e319b4f4b4265a
```

Similarly, changing the domain separator strings will result in distinct outputs. The code

```c
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
```

generates the output

```
a941cd3d19b062b8fd25219c3665d0f53350e8d3abb859ee1eb21000687d7807
e161acb4eade5516c8cc12a37a83f0daa5bec479180d8177e768b3ef2755a493
```

## Adding Additional Hash Functions

The SequenceHash and SequenceMac defenitions are automatically generated using C macros, when provided an API to the underlying hash function.

The API requires the following functions and defenitions to generate properly:

```c
#define [hash name]_BLOCK_SIZE 64
#define [hash name]_OUTPUT_SIZE 32
typedef struct [hash name]_state {
    ...
} [hash name]_state;
void [hash name]_init([hash name]_state* state);
void [hash name]_update([hash name]_state* state, const uint8_t* input, uint64_t input_len);
void [hash name]_finalize(uint8_t* output, [hash name]_state* state);
```

To add functionality for additional hash functions, include the header file with all of these defenitions at the top of the `src/sequence_hash.h` file.

Then, add `GENERATE_DEFS([hash name])` to the end of the `src/sequence_hash.h` to create the function pre-defenitions, and add `GENERATE_ALL([hash name])` to generate the functions themselves.

# Contribution Notice

The SequenceHash and SequenceMAC functions were designed and developed by Trail of Bits. This project is not associated with them or the developers in any way.
