mkdir test_data
mkdir test_data/hash
mkdir test_data/mac

for hash_name in sha256 sha512 sha3_256 sha3_512; do
    wget -O "test_data/hash/${hash_name}.json" \
        "https://raw.githubusercontent.com/C2SP/CCTV/refs/heads/main/sequencehash/hash/vectors_${hash_name}.json"
    wget -O "test_data/mac/${hash_name}.json" \
        "https://raw.githubusercontent.com/C2SP/CCTV/refs/heads/main/sequencehash/mac/vectors_${hash_name}.json"
done
