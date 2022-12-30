# lua-resty-nghttp2
openresty http2 client by nghttp2
# How to use
The API input and output like the `lua-resty-http` library

1. you should new client obj
```lua
client = nghttp2.new(
        {
            host = "127.0.0.1",
            port = 18081,
            scheme = "http",
            timeout = 100000
        }
```
2. Call `request` method
``` lua
local res, err = nghttp2.request(client, {
                    headers = {
                        hello = "1"
                    },
                    method = "GET",
                })
```
