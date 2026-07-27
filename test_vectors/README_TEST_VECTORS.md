# Test files

## PQCrystals NIST KATs (PQCsignKAT)

| File | Parameter set |
|------|----------------|
| `PQCsignKAT_Dilithium2.rsp` | ML-DSA-44 |
| `PQCsignKAT_Dilithium3.rsp` | ML-DSA-65 |
| `PQCsignKAT_Dilithium5.rsp` | ML-DSA-87 |

Source: generated with the official reference implementation
https://github.com/pq-crystals/dilithium (`ref/nistkat/PQCgenKAT_sign{2,3,5}`).

To regenerate:

```bash
git clone https://github.com/pq-crystals/dilithium
cd dilithium/ref
# needs OpenSSL headers/libs
make nistkat/PQCgenKAT_sign2 nistkat/PQCgenKAT_sign3 nistkat/PQCgenKAT_sign5 \
  CC="cc -I$(brew --prefix openssl@3)/include" \
  LDFLAGS="-L$(brew --prefix openssl@3)/lib"
./nistkat/PQCgenKAT_sign2
./nistkat/PQCgenKAT_sign3
./nistkat/PQCgenKAT_sign5
cp PQCsignKAT_Dilithium{2,3,5}.rsp /path/to/qp-rusty-crystals/test_vectors/
```

## Other

- `SHAKE256ShortMsg.rsp` / `SHAKE256LongMsg.rsp` — SHAKE256 KATs
