local Test = require("test")
local Crypto = LibStub("LibCrypto-1.0")

Test.suite("LibCrypto", "crypto")

local function hex(value)
    return (value:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function unhex(text)
    return (text:gsub("%x%x", function(pair) return string.char(tonumber(pair, 16)) end))
end

Test.test("BLAKE2s matches RFC 7693", function()
    Test.assertEq(hex(Crypto:Blake2s("")), "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
    Test.assertEq(hex(Crypto:Blake2s("abc")), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
    Test.assertEq(#Crypto:Blake2s("abc", nil, 16), 16)
    Test.assertEq(hex(Crypto:Blake2s("abc", nil, 16)), "aa4938119b1dc7b87cbad0ffd200d0ae")
    Test.assertEq(hex(Crypto:Blake2s("abc", "key")), "3f9723437b033bf0c1f4df43cafd0776068cb0a95912de13f3b2952a3aba764d")
    Test.assertEq(Crypto:Blake2s(nil), Crypto:Blake2s(""))
end)

Test.test("MAC is keyed BLAKE2s and folds a long key", function()
    Test.assertEq(Crypto:MAC("key", "abc"), Crypto:Blake2s("abc", "key"))
    Test.assertEq(Crypto:MAC(nil, nil), Crypto:Blake2s(""))
    local long = string.rep("k", 40)
    Test.assertEq(hex(Crypto:MAC(long, "message")), "e5a223c6113fc486b020e5a8f47e9ea79c4b4c203c767572614311fa639a8975")
    Test.assertEq(Crypto:MAC(long, "message"), Crypto:Blake2s("message", Crypto:Blake2s(long)))
end)

Test.test("ChaCha20 matches RFC 8439", function()
    local key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    local nonce = unhex("000000090000004a00000000")
    local block = Crypto:ChaCha20(key, nonce, string.rep("\0", 64), 1)
    Test.assertEq(hex(block),
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" ..
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")

    local poem = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe."
    Test.assertEq(#poem, 127)
    local cipher = Crypto:ChaCha20(
        unhex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
        unhex("000000000000000000000002"),
        poem,
        42)
    Test.assertEq(hex(cipher),
        "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf" ..
        "166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb" ..
        "f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77" ..
        "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1")
    Test.assertEq(Crypto:ChaCha20(
        unhex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
        unhex("000000000000000000000002"),
        cipher,
        42), poem)
    Test.assertTrue(Crypto:ChaCha20(key, nonce, poem, 0) ~= Crypto:ChaCha20(key, nonce, poem, 1))
    Test.assertError(function() Crypto:ChaCha20(string.rep("\0", 16), nonce, "x", 0) end)
    Test.assertError(function() Crypto:ChaCha20(key, string.rep("\0", 8), "x", 0) end)
end)

Test.test("XChaCha20 matches draft-irtf-cfrg-xchacha", function()
    local key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    local nonce = unhex("404142434445464748494a4b4c4d4e4f5051525354555658")
    local text = 'The dhole (pronounced "dole") is also known as the Asiatic wild dog, red dog, and whistling dog. It is about the size of a German shepherd but looks more like a long-legged fox. This highly elusive and skilled jumper is classified with wolves, coyotes, jackals, and foxes in the taxonomic family Canidae.'
    local cipher = Crypto:XChaCha20(key, nonce, text, 0)
    Test.assertEq(hex(cipher),
        "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9" ..
        "8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d" ..
        "4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da" ..
        "ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744" ..
        "3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240" ..
        "7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c" ..
        "09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae" ..
        "577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c" ..
        "cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663" ..
        "93b93111c1a55dd7421a10184974c7c5")
    Test.assertEq(Crypto:XChaCha20(key, nonce, cipher, 0), text)
    Test.assertError(function() Crypto:XChaCha20(key, string.rep("\0", 12), text, 0) end)
end)

Test.test("HKDF-BLAKE2s derives the requested length", function()
    Test.assertEq(hex(Crypto:HKDF("ikm", "salt", "info", 64)),
        "61dfc3bfca3199b499e70470012c77723d5ea178cf181e90ae1cb652ab21f0f5" ..
        "ff021fe09d737a55f1f9abe9d6f129f31280577b0b0eeb196312c4369ee8eb80")
    Test.assertEq(hex(Crypto:HKDF("ikm", nil, nil, 32)), "22bcfa9225edd058be38a0907eb2c5a70ec42a6129dcb4491a90f9ddb32a76dd")
    Test.assertEq(Crypto:HKDF("ikm", nil, nil, 32), Crypto:HKDF("ikm", string.rep("\0", 32), "", 32))
    Test.assertEq(#Crypto:HKDF("ikm", "salt", "info", 33), 33)
    Test.assertTrue(Crypto:HKDF("ikm", "salt", "one", 32) ~= Crypto:HKDF("ikm", "salt", "two", 32))
    Test.assertError(function() Crypto:HKDF("ikm", "salt", "info", 255 * 32 + 1) end)
end)

Test.test("X25519 matches RFC 7748", function()
    local alice = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    local bob = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    Test.assertEq(hex(Crypto:X25519Public(alice)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    Test.assertEq(hex(Crypto:X25519Public(bob)), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    local shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    Test.assertEq(hex(Crypto:X25519Shared(alice, Crypto:X25519Public(bob))), shared)
    Test.assertEq(hex(Crypto:X25519Shared(bob, Crypto:X25519Public(alice))), shared)
    Test.assertError(function() Crypto:X25519Public(string.rep("\0", 16)) end)
    Test.assertError(function() Crypto:X25519Shared(alice, string.rep("\0", 16)) end)
end)

Test.test("32-bit shifts stay exact past 2^53", function()
    local bitops = LibStub("LibCrypto-1.0")._modules["util.bitops.bitops"]
    Test.assertEq(bitops.u32_lsh(0xFFFFFFFF, 22), 0xFFC00000)
    Test.assertEq(bitops.u32_lrot(0x80000001, 22), 0x00600000)
    Test.assertEq(bitops.u32_rrot(0x00600000, 22), 0x80000001)
    Test.assertEq(bitops.u32_lrot(0x80000001, 1), 0x00000003)
    Test.assertEq(bitops.u32_rsh(0x80000000, 31), 1)
    Test.assertEq(bitops.u32_lsh(0x1, 32), 0)
    Test.assertEq(bitops.u32_add(0xFFFFFFFF, 2), 1)
    Test.assertEq(bitops.u32_xor(0xFF00FF00, 0x0F0F0F0F), 0xF00FF00F)
    Test.assertEq(bitops.u32_and(0xFF00FF00, 0x0F0F0F0F), 0x0F000F00)
    Test.assertEq(bitops.u32_or(0xFF00FF00, 0x0F0F0F0F), 0xFF0FFF0F)
    Test.assertEq(bitops.u32_not(0), 0xFFFFFFFF)
    Test.assertEq(bitops.u8_lsh(0xFF, 4), 0xF0)
    Test.assertEq(bitops.u8_add(200, 100), 44)
end)

Test.test("hex and base64 round-trip", function()
    Test.assertEq(Crypto:Hex("\0\255Az"), "00ff417a")
    Test.assertEq(Crypto:Unhex("00FF417a"), "\0\255Az")
    Test.assertNil(Crypto:Unhex(""))
    Test.assertNil(Crypto:Unhex("0"))
    Test.assertNil(Crypto:Unhex("zz"))
    Test.assertNil(Crypto:Unhex("abc"))
    Test.assertEq(Crypto:Base64(""), "")
    Test.assertEq(Crypto:Base64("f"), "Zg==")
    Test.assertEq(Crypto:Base64("fo"), "Zm8=")
    Test.assertEq(Crypto:Base64("foo"), "Zm9v")
    Test.assertEq(Crypto:Base64("foobar"), "Zm9vYmFy")
    Test.assertEq(Crypto:Unbase64("Zm9vYmFy"), "foobar")
    Test.assertEq(Crypto:Unbase64(Crypto:Base64("hello\0lobby")), "hello\0lobby")
end)

Test.test("ChaCha20Rng follows the ChaCha20 keystream", function()
    local seed = string.rep("\1", 32)
    local nonce = string.rep("\0", 12)
    local rng = Crypto:ChaCha20Rng(seed)
    local first = rng:next_bytes(20)
    Test.assertEq(first, Crypto:ChaCha20(seed, nonce, string.rep("\0", 20), 0))
    local word = rng:next_u32()
    local next4 = Crypto:ChaCha20(seed, nonce, string.rep("\0", 24), 0):sub(21, 24)
    local b1, b2, b3, b4 = next4:byte(1, 4)
    Test.assertEq(word, b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000)
    rng:reseed(string.rep("\2", 32))
    Test.assertEq(rng:next_bytes(8), Crypto:ChaCha20(string.rep("\2", 32), nonce, string.rep("\0", 8), 0))
    Test.assertEq(Crypto:ChaCha20Rng(seed):next_bytes(8), Crypto:ChaCha20Rng(seed):next_bytes(8))
    Test.assertError(function() Crypto:ChaCha20Rng(string.rep("\0", 16)) end)
    Test.assertError(function() rng:reseed("short") end)
end)

Test.test("Random returns the requested number of bytes", function()
    math.randomseed(1)
    Test.assertEq(Crypto:Random(0), "")
    local sample = Crypto:Random(16)
    Test.assertEq(#sample, 16)
end)

Test.test("Seal opens only with the same password and context", function()
    math.randomseed(7)
    local blob = Crypto:Seal("secret", "ABC123", "hello lobby")
    Test.assertEq(#blob, 12 + 32 + #"hello lobby")
    Test.assertEq(Crypto:Open("secret", "ABC123", blob), "hello lobby")
    Test.assertNil(Crypto:Open("wrong", "ABC123", blob))
    Test.assertNil(Crypto:Open("secret", "OTHER", blob))
    Test.assertNil(Crypto:Open("secret", "ABC123", blob:sub(1, 43)))
    Test.assertNil(Crypto:Seal("secret", "ABC123", nil))
    local flipped = blob:sub(1, -2) .. string.char((blob:byte(-1) + 1) % 256)
    Test.assertNil(Crypto:Open("secret", "ABC123", flipped))
    local again = Crypto:Seal("secret", "ABC123", "hello lobby")
    Test.assertTrue(again ~= blob)
    Test.assertEq(Crypto:Open("secret", "ABC123", again), "hello lobby")
    local empty = Crypto:Seal("secret", "ABC123", "")
    Test.assertEq(Crypto:Open("secret", "ABC123", empty), "")
    local long = Crypto:Seal(string.rep("p", 40), "lobby", "sealed")
    Test.assertEq(Crypto:Open(string.rep("p", 40), "lobby", long), "sealed")
    Test.assertNil(Crypto:Open(string.rep("p", 39), "lobby", long))
end)

Test.test("a second load keeps the sealed library", function()
    Test.loadXml(Test.root .. "/lib.xml")
    local again = LibStub("LibCrypto-1.0")
    Test.assertTrue(again == Crypto)
    Test.assertEq(hex(again:Blake2s("abc")), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
end)
