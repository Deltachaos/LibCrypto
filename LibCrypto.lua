--[[
LibCrypto-1.0
Pure Lua 5.1 cryptography for WoW addons.

BLAKE2s, ChaCha20, XChaCha20, HKDF, and X25519 are the MIT-licensed
implementations from https://github.com/BernhardZat/pure-lua-5.1-crypto
(Copyright (c) 2022-2026 BernhardZat). The bitwise helpers are original:
the upstream ones need three large lookup tables, and their OR table is
loaded from the XOR table. Lua cannot promise constant-time execution.

    local Crypto = LibStub("LibCrypto-1.0")
    Crypto:Blake2s(message, key, outlen)
    Crypto:ChaCha20(key, nonce, data, counter)   -- key 32 bytes, nonce 12
    Crypto:XChaCha20(key, nonce, data, counter)  -- nonce 24
    Crypto:HKDF(ikm, salt, info, length)
    Crypto:X25519Public(secret)                  -- secret is 32 bytes
    Crypto:X25519Shared(secret, peerPublic)
    Crypto:MAC(key, message)                     -- keyed BLAKE2s
    Crypto:Seal(password, context, plaintext)    -- nonce || tag || cipher
    Crypto:Open(password, context, blob)         -- plaintext, or nil
    Crypto:Random(n)
    Crypto:Hex(bytes)
    Crypto:Unhex(text)
    Crypto:Base64(bytes)
    Crypto:Unbase64(text)
]]

local MAJOR, MINOR = "LibCrypto-1.0", 1
local Lib = LibStub:NewLibrary(MAJOR, MINOR)
if not Lib then return end

Lib._modules = {}
