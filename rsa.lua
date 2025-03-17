local rsa = {}

-- Helper function for modular exponentiation
local function modExp(base, exponent, modulus)
    local result = 1
    base = base % modulus
    while exponent > 0 do
        if exponent % 2 == 1 then
            result = (result * base) % modulus
        end
        exponent = math.floor(exponent / 2)
        base = (base * base) % modulus
    end
    return result
end

-- Function to check if a number is prime (basic implementation)
local function isPrime(n)
    if n <= 1 then return false end
    for i = 2, math.sqrt(n) do
        if n % i == 0 then return false end
    end
    return true
end

-- Function to generate a prime number within a range
local function generatePrime(min, max)
    while true do
        local num = math.random(min, max)
        if isPrime(num) then return num end
    end
end

-- Function to calculate the greatest common divisor (GCD)
local function gcd(a, b)
    while b ~= 0 do
        a, b = b, a % b
    end
    return a
end

-- Function to find the modular multiplicative inverse
local function modInverse(a, m)
    local m0, x0, x1 = m, 0, 1
    while a > 1 do
        local q = math.floor(a / m)
        local t = m

        m = a % m
        a = t
        t = x0

        x0 = x1 - q * x0
        x1 = t
    end

    if x1 < 0 then
        x1 = x1 + m0
    end

    return x1
end

-- Key pair
local keyPair = nil

-- Function to generate RSA key pair
function rsa.generateKeypair()
    local p = generatePrime(100, 200) -- Example range, adjust as needed
    local q = generatePrime(201, 300) -- Ensure p and q are distinct
    local n = p * q
    local phi = (p - 1) * (q - 1)

    -- Choose an integer e such that 1 < e < phi and gcd(e, phi) = 1
    local e = 65537 -- Commonly used public exponent

    -- Calculate the modular multiplicative inverse of e modulo phi
    local d = modInverse(e, phi)

	keyPair = {publicKey = {n = n, e = e}, privateKey = {n = n, d = d}}
    return keyPair
end

-- Function to encrypt a message
function rsa.encrypt(message, publicKey)
    local n, e = publicKey.n, publicKey.e
    local ciphertext = {}
    for i = 1, #message do
        local charCode = string.byte(message, i)
        ciphertext[i] = modExp(charCode, e, n)
    end
    return textutils.serialize(ciphertext)
end

-- Function to decrypt a ciphertext
function rsa.decrypt(ciphertext, privateKey)
    ciphertext = textutils.unserialize(ciphertext)
    local n, d = privateKey.n, privateKey.d
    local message = ""
    for i = 1, #ciphertext do
        local charCode = modExp(ciphertext[i], d, n)
        if charCode >= 0 and charCode <= 255 then
            message = message .. string.char(charCode)
        else
            print("Warning: charCode out of range: " .. charCode)
            message = message .. "?"  -- Substitute invalid characters with '?'
        end
    end
    return message
end

return rsa