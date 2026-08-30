--[[
    Void Scripts Universal Loader v1.0
    Server-Gated Key System & Secure In-Memory Decryption
]]

-- 1. Anti-Tamper & Pristine Native Closures
local _loadstring = (typeof(clonefunction) == "function" and typeof(loadstring) == "function" and clonefunction(loadstring)) or loadstring
local _pcall = (typeof(clonefunction) == "function" and typeof(pcall) == "function" and clonefunction(pcall)) or pcall
local _request = (syn and syn.request) or (http and http.request) or http_request or request
local _setclipboard = (typeof(clonefunction) == "function" and clonefunction(setclipboard or toclipboard or (syn and syn.write_clipboard))) or setclipboard or toclipboard or (syn and syn.write_clipboard)

local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer or Players.PlayerAdded:Wait()

if typeof(isfunctionhooked) == "function" then
    local hooked = false
    if typeof(_loadstring) == "function" then
        local ok, res = pcall(isfunctionhooked, _loadstring)
        if ok and res == true then hooked = true end
    end
    if typeof(_request) == "function" then
        local ok, res = pcall(isfunctionhooked, _request)
        if ok and res == true then hooked = true end
    end
    if hooked and LocalPlayer then
        LocalPlayer:Kick("[Void Scripts] Environment integrity check failed.")
        return
    end
end

-- LIVE VERCEL KEY SERVER
local API_URL = "https://detour-key-system.vercel.app"
local SAVE_FILE = "VoidKey.txt"

local HttpService = game:GetService("HttpService")
local RbxAnalytics = game:GetService("RbxAnalyticsService")

if not _request then
    LocalPlayer:Kick("[Void Scripts] Your executor does not support HTTP requests.")
    return
end

local function GetHWID()
    local ok, id = _pcall(function() return RbxAnalytics:GetClientId() end)
    if ok and id and #id > 0 then return id end
    return LocalPlayer.UserId .. "_DEVICE"
end

-- Lightweight In-Memory SHA-256 for Key Derivation
local function sha256_bytes(str)
    -- If executor provides crypt.hash, use native fast crypto
    if crypt and crypt.hash then
        local hex = crypt.hash(str, "sha256")
        local bytes = {}
        for k = 1, #hex, 2 do
            table.insert(bytes, tonumber(hex:sub(k, k + 1), 16))
        end
        return bytes
    end

    -- Pure Lua fallback SHA256
    local K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    }
    local function ror(x, n) return bit32.rrotate(x, n) end
    local H = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
    local msg = {string.byte(str, 1, #str)}
    local bit_len = #msg * 8
    table.insert(msg, 0x80)
    while (#msg % 64) ~= 56 do table.insert(msg, 0x00) end
    for b = 7, 0, -1 do
        table.insert(msg, bit32.band(bit32.rshift(bit_len, b * 8), 0xFF))
    end

    for chunk = 1, #msg, 64 do
        local W = {}
        for i = 0, 15 do
            W[i + 1] = bit32.bor(
                bit32.lshift(msg[chunk + i * 4], 24),
                bit32.lshift(msg[chunk + i * 4 + 1], 16),
                bit32.lshift(msg[chunk + i * 4 + 2], 8),
                msg[chunk + i * 4 + 3]
            )
        end
        for i = 17, 64 do
            local s0 = bit32.bxor(ror(W[i - 15], 7), ror(W[i - 15], 18), bit32.rshift(W[i - 15], 3))
            local s1 = bit32.bxor(ror(W[i - 2], 17), ror(W[i - 2], 19), bit32.rshift(W[i - 2], 10))
            W[i] = bit32.band(W[i - 16] + s0 + W[i - 7] + s1, 0xFFFFFFFF)
        end
        local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
        for i = 1, 64 do
            local S1 = bit32.bxor(ror(e, 6), ror(e, 11), ror(e, 25))
            local ch = bit32.bxor(bit32.band(e, f), bit32.band(bit32.bnot(e), g))
            local temp1 = bit32.band(h + S1 + ch + K[i] + W[i], 0xFFFFFFFF)
            local S0 = bit32.bxor(ror(a, 2), ror(a, 13), ror(a, 22))
            local maj = bit32.bxor(bit32.band(a, b), bit32.band(a, c), bit32.band(b, c))
            local temp2 = bit32.band(S0 + maj, 0xFFFFFFFF)
            h, g, f, e, d, c, b, a = g, f, e, bit32.band(d + temp1, 0xFFFFFFFF), c, b, a, bit32.band(temp1 + temp2, 0xFFFFFFFF)
        end
        H[1] = bit32.band(H[1] + a, 0xFFFFFFFF)
        H[2] = bit32.band(H[2] + b, 0xFFFFFFFF)
        H[3] = bit32.band(H[3] + c, 0xFFFFFFFF)
        H[4] = bit32.band(H[4] + d, 0xFFFFFFFF)
        H[5] = bit32.band(H[5] + e, 0xFFFFFFFF)
        H[6] = bit32.band(H[6] + f, 0xFFFFFFFF)
        H[7] = bit32.band(H[7] + g, 0xFFFFFFFF)
        H[8] = bit32.band(H[8] + h, 0xFFFFFFFF)
    end
    local res = {}
    for _, word in ipairs(H) do
        table.insert(res, bit32.band(bit32.rshift(word, 24), 0xFF))
        table.insert(res, bit32.band(bit32.rshift(word, 16), 0xFF))
        table.insert(res, bit32.band(bit32.rshift(word, 8), 0xFF))
        table.insert(res, bit32.band(word, 0xFF))
    end
    return res
end

-- Decrypts transport payload in memory
local function DecryptPayload(hexCipher, key, hwid, salt)
    local parts = key:split("-")
    local sig = parts[3] or ""
    local seed = key:upper() .. ":" .. hwid .. ":" .. salt .. ":" .. sig
    local keyBytes = sha256_bytes(seed)

    local S = {}
    for i = 0, 255 do S[i] = i end
    local j = 0
    for i = 0, 255 do
        j = (j + S[i] + keyBytes[(i % #keyBytes) + 1]) % 256
        S[i], S[j] = S[j], S[i]
    end

    local cipherLen = #hexCipher / 2
    local out = table.create(cipherLen)
    local i = 0
    j = 0
    for k = 1, cipherLen do
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        local K = S[(S[i] + S[j]) % 256]
        local byte = tonumber(hexCipher:sub((k - 1) * 2 + 1, k * 2), 16)
        out[k] = string.char(bit32.bxor(byte, K))
    end
    return table.concat(out)
end

local function LoadSavedKey()
    if readfile and isfile then
        if isfile(SAVE_FILE) then
            local ok, key = _pcall(readfile, SAVE_FILE)
            if ok and key and #key > 5 then
                return key:gsub("%s+", "")
            end
        end
        if isfile("DetourKey.txt") then
            local ok, key = _pcall(readfile, "DetourKey.txt")
            if ok and key and #key > 5 then
                return key:gsub("%s+", "")
            end
        end
    end
    return nil
end

local function SaveKey(key)
    if writefile then
        _pcall(writefile, SAVE_FILE, key)
    end
end

local function VerifyKey(key)
    local hwid = GetHWID()
    local response = _request({
        Url = API_URL .. "/api/verify",
        Method = "POST",
        Headers = { ["Content-Type"] = "application/json" },
        Body = HttpService:JSONEncode({
            key = key,
            hwid = hwid,
            placeId = tostring(game.PlaceId),
            gameId = tostring(game.GameId)
        })
    })

    if response and response.Body then
        local ok, data = _pcall(HttpService.JSONDecode, HttpService, response.Body)
        if ok and data then
            if data.unsupported then
                LocalPlayer:Kick("[Void Scripts] This game is not currently supported.")
                return nil
            end
            if data.success and data.encrypted and data.payload and data.salt then
                local code = DecryptPayload(data.payload, key, hwid, data.salt)
                data.payload = code
            end
            return data
        end
    end
    return { success = false, message = "Could not reach verification server." }
end

-- 1. Try Auto-Login with saved key
local savedKey = LoadSavedKey()
if savedKey then
    local check = VerifyKey(savedKey)
    if check and check.success and check.payload then
        print("[Void Scripts] Auto-login verified with saved key!")
        local fn, err = _loadstring(check.payload)
        if fn then fn() else warn("[Void Scripts] Load error:", err) end
        return
    end
end

-- 2. If auto-login fails or no key saved, open Key UI
local Rayfield = _loadstring(game:HttpGet("https://sirius.menu/gen2"))()
if not Rayfield then return end

local Window = Rayfield:CreateWindow({
    name = "Void Scripts",
    subtitle = "Universal Hub Verification",
    theme = "cobalt",
    configuration = { autoSave = false, autoLoad = false }
})

local KeyTab = Window:CreateTab({ name = "Key Verification", icon = 93364949241311 })
KeyTab:CreateSection({ name = "Access Key Required" })

local enteredKey = ""
KeyTab:CreateInput({
    name = "Access Key",
    placeholderText = "Paste VOID-XXXX-YYYY here...",
    callback = function(t)
        enteredKey = t:gsub("%s+", "")
    end
})

KeyTab:CreateButton({
    name = "Verify & Launch",
    callback = function()
        if enteredKey == "" then
            Window:Notify({ title = "Error", content = "Please enter your key above.", duration = 3 })
            return
        end

        Window:Notify({ title = "Verifying", content = "Checking key with server...", duration = 1.5 })
        local res = VerifyKey(enteredKey)

        if res and res.unsupported then
            LocalPlayer:Kick("[Void Scripts] This game is not currently supported.")
            return
        end

        if res and res.success and res.payload then
            SaveKey(enteredKey)
            Window:Notify({ title = "Success", content = "Access granted! Loading script...", duration = 2 })
            task.wait(1)
            Window:Unload()
            local fn, err = _loadstring(res.payload)
            if fn then fn() else warn("[Void Scripts] Load error:", err) end
        else
            Window:Notify({ title = "Invalid Key", content = (res and res.message) or "Verification failed.", duration = 4 })
        end
    end
})

KeyTab:CreateSection({ name = "Need a Key? (Free & 100% Ad-Free)" })
KeyTab:CreateButton({
    name = "Join Discord to Get Key",
    callback = function()
        local link = "https://discord.gg/Y733pGaXR"
        if _setclipboard then _setclipboard(link) end
        Window:Notify({ title = "Discord Invite", content = "Discord link copied to clipboard! Join to get your free key (No ads).", duration = 4 })
    end
})
