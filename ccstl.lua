local rsa = require("rsa")
local expect = require("cc.expect")
local server = {listening = false, requests = {}, publicKey = {}, privateKey = {}}
local _internal_Timer = nil;
peripheral.find("modem", rednet.open)

-- Split function to split strings by a delimiter
function string:split(delimiter)
    local result = {}
    local from = 1
    local delim_from, delim_to = string.find(self, delimiter, from)
    while delim_from do
        table.insert(result, string.sub(self, from, delim_from - 1))
        from = delim_to + 1
        delim_from, delim_to = string.find(self, delimiter, from)
    end
    table.insert(result, string.sub(self, from))
    return result
end

local function onRequest(req) end
local function onResponse(res) end

if not rednet.isOpen() then
    print("No modem found")
    return
end

local function handleCertificate(id, type, body, ack)
    --ccstl:certificate:request
    --ccstl:certificate:response
    --ccstl:certificate:challenge:request
    --ccstl:certificate:challenge:solution

    -- Return error if server is not listening and the certificate is a request
    if not server.listening and type[3] == "request" then
        rednet.send(id, "ccstl:response:error:503$&Service Unavailable$&" .. ack)
        return
    end

    if type[3] == "request" then
        local request = {
            id = id,
            body = body,
            ack = ack,
            type = type,
            challenge = "none"
        }

        server.requests[ack .. id] = request

        rednet.send(id, "ccstl:certificate:response$&".. server.publicKey.signee .. "-" .. server.publicKey.e .. "-" .. server.publicKey.n .. "$&" .. ack)
        return
    end

    if type[3] == "response" then
        local request = server.requests[ack .. id]
        if request == nil then
            rednet.send(id, "ccstl:response:error:500$&Internal Server Error$&" .. ack)
            return
        end

        request.server.publicKey = {signee = tonumber(body:split("-")[1]), e = tonumber(body:split("-")[2]), n = tonumber(body:split("-")[3])}
        request.server.challengeSolution = math.random(2^15, 2^16)
        request.server.challenge = rsa.encrypt("" .. request.server.challengeSolution, request.server.publicKey)
        rednet.send(id, "ccstl:certificate:challenge:request$&" .. request.server.challenge .. "$&" .. ack)
        
        -- Save the request to the server because I've no idea if Lua is by reference or value
        server.requests[ack .. id] = request

        return
    end

    if type[3] == "challenge" and type[4] == "solution" then
        local request = server.requests[ack .. id]
        if request == nil then
            rednet.send(id, "ccstl:response:error:500$&Internal Server Error$&" .. ack)
            return
        end

        body = tonumber(body)

        if request.server.challengeSolution == body then
            request.server.verified = true
            -- send request if verified
            rednet.send(id, "ccstl:request$&" .. request.body .. "$&" .. ack)
            return
        end

        rednet.send(id, "ccstl:response:error:401$&Unauthorized$&" .. ack)
        return
    end

    if type[3] == "challenge" and type[4] == "request" then
        local request = {
            id = id,
            body = body,
            ack = ack,
            type = type,
            challenge = "pending"
        }

        server.requests[ack .. id] = request

        body = rsa.decrypt(body, server.privateKey)

        rednet.send(id, "ccstl:certificate:challenge:solution$&" .. body .. "$&" .. ack)
        return
    end
end

function getType(value)
    return type(value)
end

local function handleRequest(id, type, body, ack)
    --ccstl:request

    if not server.listening then
        rednet.send(id, "ccstl:response:error:503$&Service Unavailable$&" .. ack)
        return
    end

    local request = server.requests[ack .. id]
    if request == nil then
        rednet.send(id, "ccstl:response:error:500$&Internal Server Error$&" .. ack)
        return
    end
    request.body = body

    function request:write(res, status_code, failed)
        expect(1, res, "string")
        expect(2, status_code, "number", "nil")
        expect(3, failed, "boolean", "nil")

        if not status_code then status_code = 200 end

        if failed then
            rednet.send(self.id, "ccstl:response:error:" .. status_code .. "$&" .. res .. "$&" .. self.ack)
            return
        end

        rednet.send(self.id, "ccstl:response:success:" .. status_code .. "$&" .. res .. "$&" .. self.ack)
    end

    function request:bye ()
        rednet.send(self.id, "ccstl:bye$&Bye$&" .. self.ack)
    end

    onRequest(request)
end

local function handleResponse(id, type, body, ack)
    --ccstl:response
    local request = server.requests[ack .. id]
    if request == nil then
        rednet.send(id, "ccstl:response:error:500$&Internal Server Error$&" .. ack)
        return
    end

    request.response = body

    function request:write(res, status_code, failed)
        expect(1, res, "string")
        expect(2, status_code, "number", "nil")
        expect(3, failed, "boolean", "nil")
        
        if not status_code then status_code = 200 end

        if failed then
            rednet.send(self.id, "ccstl:response:error:" .. status_code .. "$&" .. res .. "$&" .. self.ack)
            return
        end

        rednet.send(self.id, "ccstl:response:success:" .. status_code .. "$&" .. res .. "$&" .. self.ack)
    end

    function request:bye ()
        rednet.send(self.id, "ccstl:bye$&Bye$&" .. self.ack)
    end

    onResponse(request)
end

local ccstl = {}

-- Register the server as open such that it doesnt reject incoming requests
function ccstl.open()
    server.listening = true
end

function ccstl.createRequest(id, body, timeout)
    local ack = math.random(2^15, 2^16)
    local request = {
        id = id,
        body = body,
        ack = ack,
        server = {
            publicKey = nil,
            privateKey = nil,
            challenge = nil,
            challengeSolution = nil,
            verified = false
        }
    }

    server.requests[ack .. id] = request

    rednet.send(id, "ccstl:certificate:request$&nil$&" .. ack)
    ccstl.listen(timeout or 5)
end

function ccstl.onRequest(callback)
    onRequest = callback
end

function ccstl.onResponse(callback)
    onResponse = callback
end

function ccstl.generateKeypair()
    local keyPair = rsa.generateKeypair()
    server.publicKey = keyPair.publicKey
    server.publicKey.signee = "self"
    server.privateKey = keyPair.privateKey

    local private = fs.open("private.key", "w")
    private.write(textutils.serialize(server.privateKey))
    private.close()

    local public = fs.open("public.key", "w")
    public.write(textutils.serialize(server.publicKey))
    public.close()

    return keyPair
end

local function handleMessage(id, msg, protocol)
    msg = msg:split("$&")
    local type = msg[1]:split(":")
    local body = msg[2]
    local ack = msg[3]
    if not (type[1] == "ccstl") then return end

    if type[2] == "certificate" then
        handleCertificate(id, type, body, ack)
        return
    end

    if type[2] == "request" then
        handleRequest(id, type, body, ack)
        return
    end

    if type[2] == "response" then
        handleResponse(id, type, body, ack)
        return
    end

    if type[2] == "bye" then
        server.requests[ack .. id] = nil

        if #server.requests == 0 then
            --trigger timer manually if there are no requests present anymore
            os.cancelTimer(_internal_Timer)
            os.queueEvent("timer", _internal_Timer)
        end

        rednet.send(id, "ccstl:bye$&Bye$&" .. ack)

        return
    end

    rednet.send(id, "ccstl:response:error:400$&Bad Request$&" .. ack)
end

-- Limitation of CC sadly you have to busy loop this
-- Im giving the user control over said busy loop with this
-- Bit shitty api design ngl
function ccstl.listen(timeout)
    if not timeout then timeout = 5 end

    _internal_Timer = os.startTimer(timeout)
    while true do
        local event, id, msg, protocol = os.pullEvent()
        if event == "rednet_message" then
            handleMessage(id, msg, protocol)
        elseif event == "timer" and id == _internal_Timer then
            break
        end
    end
end

return ccstl