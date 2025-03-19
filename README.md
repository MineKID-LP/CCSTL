# CCSTL Documentation

## Overview
CCSTL (ComputerCraft Secure Transfer Layer) is a Lua library designed for "secure" communication in ComputerCraft. It provides an easy way of transfering anything you'd like.

## Installation
1. Drag and Drop `ccstl.lua` and `rsa.lua` into your folder
2. `local ccstl = require("ccstl")`

## API Reference

### `ccstl.open()`
Registers the server as open, allowing it to accept incoming requests.

### `ccstl.createRequest(id, body, timeout)`
Creates a new request to a specified `id` with the given `body`.
- **Parameters:**
  - `id` (number): The ID of the target device.
  - `body` (string): The message body to send.
  - `timeout` (number, optional): The timeout duration for the request. Defaults to 10 seconds.

### `ccstl.onRequest(callback)`
Registers a callback function to handle incoming requests.
- **Parameters:**
  - `callback` (function): A function that takes a `request` object as its parameter.

### `ccstl.onResponse(callback)`
Registers a callback function to handle incoming responses.
- **Parameters:**
  - `callback` (function): A function that takes a `response` object as its parameter.

### `ccstl.generateKeypair()`
Generates an RSA key pair for secure communication. The keys are saved to `private.key` and `public.key` files.
- **Returns:**
  - A table containing `publicKey` and `privateKey`.

### `ccstl.listen(timeout)`
Listens for incoming messages and processes them.
- **Parameters:**
  - `timeout` (number, optional): The duration to listen for messages. Defaults to 5 seconds.

## Request Object
The `request` object is passed to the `onRequest` callback and contains the following fields:
- `id` (number): The ID of the sender.
- `body` (string): The message body.
- `ack` (number): The acknowledgment number.

### Methods
#### `request:write(res, status_code, failed)`
Sends a response to the sender.
- **Parameters:**
  - `res` (string): The response message.
  - `status_code` (number, optional): The HTTP-like status code. Defaults to 200.
  - `failed` (boolean, optional): Whether the response indicates a failure.

#### `request:bye()`
Sends a goodbye message to the sender.

## Response Object
The `response` object is passed to the `onResponse` callback and contains the following fields:
- `id` (number): The ID of the sender.
- `body` (string): The response body.
- `ack` (number): The acknowledgment number.

### Methods
#### `response:write(res, status_code, failed)`
Sends a response to the sender.
- **Parameters:**
  - `res` (string): The response message.
  - `status_code` (number, optional): The HTTP-like status code. Defaults to 200.
  - `failed` (boolean, optional): Whether the response indicates a failure.

#### `response:bye()`
Sends a goodbye message to the sender.

## Example Usage

### Server Example
```lua
local ccstl = require("ccstl")

ccstl.generateKeypair()
ccstl.open()

ccstl.onRequest(function(request)
    print("Received request from " .. request.id)
    print("Request body: " .. request.body)
    request:write("Hello, client!")
end)

while true do
    ccstl.listen()
end
```

### Client Example
```lua
local ccstl = require("ccstl")

ccstl.onResponse(function(response)
    print("Received response: " .. response.body)
    response:bye()
end)

ccstl.createRequest(0, "Hello, server!")
```

## Notes
- Ensure that the modem peripheral is attached before trying to use CCSTL.
- The library uses RSA encryption for secure communication. Keep your private key secure.
- The RSA library was also coded by idiots with courtesy of [@YannickMyxe](https://github.com/YannickMyxe/)
