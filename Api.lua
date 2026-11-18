local Lib = LibStub:GetLibrary("LibCrypto-1.0", true)
if not Lib or Lib._sealed then return end

local misc = Lib._modules["util.misc"]
local base64 = Lib._modules["util.base64.base64"]
local blake2s = Lib._modules["crypto.blake2s.blake2s"]
local ChaCha20 = Lib._modules["crypto.chacha20.chacha20"]
local XChaCha20 = Lib._modules["crypto.chacha20.xchacha20"]
local ChaCha20Rng = Lib._modules["crypto.chacha20.chacha20rng"]
local hkdf = Lib._modules["crypto.hkdf"]
local x25519 = Lib._modules["crypto.x25519.x25519"]

local function hexOf(bytes)
    return misc.hex_from_bytestring(bytes)
end

local function unhexOf(text)
    if type(text) ~= "string" or text == "" or #text % 2 ~= 0 or text:find("[^%x]") then
        return nil
    end
    return misc.hex_to_bytestring(text)
end

local function randomBytes(count)
    local out = {}
    for i = 1, count do out[i] = string.char(math.random(0, 255)) end
    return table.concat(out)
end

local function macKey(key)
    key = tostring(key or "")
    if #key > 32 then key = blake2s.digest(key) end
    return key
end

local function same(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do
        if a:byte(i) ~= b:byte(i) then diff = diff + 1 end
    end
    return diff == 0
end

function Lib:Blake2s(message, key, outlen)
    if key and #key > 32 then key = blake2s.digest(key) end
    return blake2s.digest(message or "", key, outlen)
end

function Lib:ChaCha20(key, nonce, data, counter)
    return ChaCha20.new(key, nonce, counter):apply_keystream(data)
end

function Lib:XChaCha20(key, nonce, data, counter)
    return XChaCha20.new(key, nonce, counter):apply_keystream(data)
end

function Lib:ChaCha20Rng(seed)
    return ChaCha20Rng.new(seed)
end

function Lib:HKDF(ikm, salt, info, length)
    return hkdf.derive(ikm, salt, info, length)
end

function Lib:X25519Public(secret)
    return x25519.get_public_key(secret)
end

function Lib:X25519Shared(secret, peerPublic)
    return x25519.get_shared_secret(secret, peerPublic)
end

function Lib:MAC(key, message)
    return blake2s.digest(message or "", macKey(key))
end

function Lib:Random(count)
    return randomBytes(count)
end

function Lib:Hex(bytes)
    return hexOf(bytes)
end

function Lib:Unhex(text)
    return unhexOf(text)
end

function Lib:Base64(bytes)
    return base64.encode(bytes)
end

function Lib:Unbase64(text)
    return base64.decode(text)
end

-- nonce(12) || BLAKE2s tag(32) || ChaCha20 ciphertext. The password is the
-- HKDF input; context separates two messages that share a password.
function Lib:Seal(password, context, plaintext)
    if type(plaintext) ~= "string" then return nil end
    local okm = hkdf.derive(tostring(password or ""), "LibCrypto-1", tostring(context or "") .. "\0seal", 64)
    local encKey, macKeyBytes = okm:sub(1, 32), okm:sub(33, 64)
    local nonce = randomBytes(12)
    local cipher = ChaCha20.new(encKey, nonce, 1):apply_keystream(plaintext)
    local tag = blake2s.digest(nonce .. cipher, macKeyBytes)
    return nonce .. tag .. cipher
end

function Lib:Open(password, context, blob)
    if type(blob) ~= "string" or #blob < 44 then return nil end
    local okm = hkdf.derive(tostring(password or ""), "LibCrypto-1", tostring(context or "") .. "\0seal", 64)
    local encKey, macKeyBytes = okm:sub(1, 32), okm:sub(33, 64)
    local nonce, tag, cipher = blob:sub(1, 12), blob:sub(13, 44), blob:sub(45)
    if not same(tag, blake2s.digest(nonce .. cipher, macKeyBytes)) then return nil end
    return ChaCha20.new(encKey, nonce, 1):apply_keystream(cipher)
end

local function expect(label, got, want)
    if got ~= want then error("LibCrypto " .. label .. " self-test failed") end
end

expect("BLAKE2s", hexOf(blake2s.digest("")), "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")

local chachaKey = unhexOf("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
local chachaNonce = unhexOf("000000090000004a00000000")
local keystream = ChaCha20.new(chachaKey, chachaNonce, 1):apply_keystream(("\0"):rep(64))
expect(
    "ChaCha20",
    hexOf(keystream),
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" ..
    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
)

local scalar = unhexOf("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
expect("X25519", hexOf(x25519.get_public_key(scalar)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

local sealed = Lib:Seal("secret", "ABC123", "hello lobby")
expect("Seal", Lib:Open("secret", "ABC123", sealed), "hello lobby")
if Lib:Open("wrong", "ABC123", sealed) ~= nil then error("LibCrypto Seal self-test failed") end

Lib._sealed = true
