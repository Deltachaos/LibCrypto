local Lib = LibStub:GetLibrary("LibCrypto-1.0", true)
if not Lib or Lib._sealed then return end

local floor = math.floor

local WIDTH = { [8] = 256, [16] = 65536, [32] = 4294967296 }
local POW = { [0] = 1 }
for i = 1, 32 do POW[i] = POW[i - 1] * 2 end

-- 4-bit tables. A full byte table is unnecessary, and the result stays exact
-- in a double because every intermediate product is below 2^32.
local nand, nor, nxor = {}, {}, {}
for a = 0, 15 do
    for b = 0, 15 do
        local aa, bb = a, b
        local band, bor, bxor, place = 0, 0, 0, 1
        for _ = 1, 4 do
            local ba, bb2 = aa % 2, bb % 2
            if ba == 1 and bb2 == 1 then band = band + place end
            if ba == 1 or bb2 == 1 then bor = bor + place end
            if ba ~= bb2 then bxor = bxor + place end
            aa = floor(aa / 2)
            bb = floor(bb / 2)
            place = place * 2
        end
        nand[a * 16 + b] = band
        nor[a * 16 + b] = bor
        nxor[a * 16 + b] = bxor
    end
end

local function mask(a, bits)
    local m = WIDTH[bits]
    a = a % m
    if a < 0 then a = a + m end
    return a
end

local function binop(table, a, b, bits)
    a = mask(a, bits)
    b = mask(b, bits)
    local result, place = 0, 1
    for _ = 1, bits / 4 do
        result = result + table[(a % 16) * 16 + (b % 16)] * place
        a = floor(a / 16)
        b = floor(b / 16)
        place = place * 16
    end
    return result
end

-- Shift by masking first, then multiplying. Multiplying a full 32-bit word
-- by 2^n is not exact in a double once the product passes 2^53.
local function lsh(a, n, bits)
    a = mask(a, bits)
    n = floor(n)
    if n <= 0 then return a end
    if n >= bits then return 0 end
    return (a % POW[bits - n]) * POW[n]
end

local function rsh(a, n, bits)
    a = mask(a, bits)
    n = floor(n)
    if n <= 0 then return a end
    if n >= bits then return 0 end
    return floor(a / POW[n])
end

local function lrot(a, n, bits)
    n = floor(n) % bits
    if n == 0 then return mask(a, bits) end
    return lsh(a, n, bits) + rsh(a, bits - n, bits)
end

local function rrot(a, n, bits)
    n = floor(n) % bits
    if n == 0 then return mask(a, bits) end
    return rsh(a, n, bits) + lsh(a, bits - n, bits)
end

local function add(a, b, bits)
    return (mask(a, bits) + mask(b, bits)) % WIDTH[bits]
end

local function bnot(a, bits)
    return WIDTH[bits] - 1 - mask(a, bits)
end

local function op(name, bits)
    return function(a, b) return binop(name, a, b, bits) end
end

local bitops = {
    u8_and = op(nand, 8),
    u8_or = op(nor, 8),
    u8_xor = op(nxor, 8),
    u8_not = function(a) return bnot(a, 8) end,
    u8_lsh = function(a, n) return lsh(a, n, 8) end,
    u8_rsh = function(a, n) return rsh(a, n, 8) end,
    u8_lrot = function(a, n) return lrot(a, n, 8) end,
    u8_rrot = function(a, n) return rrot(a, n, 8) end,
    u8_add = function(a, b) return add(a, b, 8) end,

    u16_and = op(nand, 16),
    u16_or = op(nor, 16),
    u16_xor = op(nxor, 16),
    u16_not = function(a) return bnot(a, 16) end,
    u16_lsh = function(a, n) return lsh(a, n, 16) end,
    u16_rsh = function(a, n) return rsh(a, n, 16) end,
    u16_lrot = function(a, n) return lrot(a, n, 16) end,
    u16_rrot = function(a, n) return rrot(a, n, 16) end,
    u16_add = function(a, b) return add(a, b, 16) end,

    u32_and = op(nand, 32),
    u32_or = op(nor, 32),
    u32_xor = op(nxor, 32),
    u32_not = function(a) return bnot(a, 32) end,
    u32_lsh = function(a, n) return lsh(a, n, 32) end,
    u32_rsh = function(a, n) return rsh(a, n, 32) end,
    u32_lrot = function(a, n) return lrot(a, n, 32) end,
    u32_rrot = function(a, n) return rrot(a, n, 32) end,
    u32_add = function(a, b) return add(a, b, 32) end,
}

Lib._modules["util.bitops.bitops"] = bitops
