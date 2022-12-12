local nghttp2 = require 'resty.nghttp2'
describe('nghttp2.org', function()
    local client = assert(nghttp2.new({ uri = '1', scheme = 'http', host = 'nghttp2.org', detach = true }))
    it('send', function()
        local response = assert(nghttp2.request(client, {
            method = 'GET',
            scheme = 'http',
            host = 'nghttp2.org',
            headers = {
                hello = "1"
            },
            timeout = 2,
        }))
        assert(response.status == 200)
        ngx.say("end send")
    end)
end)
