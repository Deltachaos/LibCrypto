# LibCrypto

LibCrypto is a LoadOnDemand WoW library of pure Lua 5.1 cryptography. It exposes BLAKE2s, ChaCha20, XChaCha20, HKDF, X25519, and a small password seal on top of LibStub.

The algorithms come from [pure-lua-5.1-crypto](https://github.com/BernhardZat/pure-lua-5.1-crypto) (MIT, Copyright (c) 2022-2026 BernhardZat). The bitwise helpers in `util/bitops.lua` are original. Lua cannot promise constant-time execution, so this library does not claim it.

## Install

```
## Dependencies: LibCrypto
```

The BigWigs packager reads `.pkgmeta` and fetches LibStub. The TOC loads `LibStub/LibStub.lua` before the library.

```lua
local Crypto = LibStub("LibCrypto-1.0")
```

The library checks BLAKE2s, ChaCha20, X25519, and `Seal`/`Open` against known vectors while it loads. A mismatch raises an error.

Keys, nonces, and digests are raw byte strings. `Hex` and `Unhex` convert those strings. `Hex` writes lowercase hex. `Unhex` returns nil when the text is empty, has an odd length, or contains a non-hex character.

## Hash and MAC

```lua
Crypto:Blake2s(message)                 -- 32 raw bytes
Crypto:Blake2s(message, key)            -- keyed BLAKE2s
Crypto:Blake2s(message, key, outlen)    -- outlen defaults to 32
Crypto:MAC(key, message)                -- same keyed BLAKE2s, 32 bytes
```

A key longer than 32 bytes is hashed down to 32 bytes before it is used as a BLAKE2s key. `MAC` turns a non-string key into a string first. An omitted message is hashed as the empty string.

## Streams

```lua
Crypto:ChaCha20(key, nonce, data, counter)
Crypto:XChaCha20(key, nonce, data, counter)
```

Both calls XOR `data` with the keystream and return the result, so the same call encrypts and decrypts. The key is 32 bytes. A ChaCha20 nonce is 12 bytes and an XChaCha20 nonce is 24. `counter` is the starting block index and defaults to 0. A wrong length raises an error.

```lua
local rng = Crypto:ChaCha20Rng(seed)   -- seed is 32 bytes
rng:next_bytes(n)
rng:next_u32()
rng:reseed(newSeed)
```

`ChaCha20Rng` uses a zero nonce and reads the ChaCha20 keystream. The seed is the key, so it has to come from somewhere with enough entropy. `Crypto:Random(n)` is not that generator: it returns `n` bytes from `math.random`.

## Key derivation and key agreement

```lua
Crypto:HKDF(ikm, salt, info, length)
```

HKDF here is the RFC 5869 construction with keyed BLAKE2s in place of HMAC-SHA256. A missing salt is 32 zero bytes. A missing info string is empty. `length` is capped at 255 blocks of 32 bytes.

```lua
local public = Crypto:X25519Public(secret)             -- both are 32 bytes
local shared = Crypto:X25519Shared(secret, peerPublic)
```

`secret` and `peerPublic` must each be 32 bytes.

## Sealing a password message

```lua
local blob = Crypto:Seal(password, context, plaintext)
local opened = Crypto:Open(password, context, blob)    -- plaintext, or nil
```

`Seal` returns raw bytes: a 12-byte nonce, a 32-byte BLAKE2s tag, then the ChaCha20 ciphertext. `Open` returns nil when the blob is shorter than 44 bytes or the tag does not match. The password is the HKDF input and `context` separates two messages that share a password. The same password with a different context does not open the blob.

`Seal` draws its nonce with `math.random`. It does not encode the result for a WoW addon channel. LibMultiplayer does that with LibDeflate around `Seal` and `Open` for password-locked lobby broadcasts.

## Encoding

```lua
Crypto:Hex(bytes)
Crypto:Unhex(text)
Crypto:Base64(bytes)
Crypto:Unbase64(text)
Crypto:Random(n)
```

Base64 uses the standard alphabet and `=` padding.

## Tests

```
lua5.1 tests/test_crypto.lua
```

The suite checks the public API against RFC 7693, RFC 8439, RFC 7748, and the XChaCha draft, and it checks the 32-bit shifts that are not exact if a full word is multiplied in a Lua double. GitHub Actions checks out LibStub, then runs the same command on Ubuntu with Lua 5.1.
