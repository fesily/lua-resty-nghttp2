local nghttp2 = require 'resty.nghttp2'
describe('nghttp2.org', function()
    local client = assert(nghttp2.new("http://nghttp2.org"))
    it('send', function()
        local submit = assert(client:new_submit("GET", "http://nghttp2.org/", nil))
        local headers = {
            hello = 1
        }
        assert(submit:send_headers(headers))
        assert.equal(submit:submit(true, 10), 200)
    end)
end)

describe('localhost', function()
    local client = assert(nghttp2.new("http://localhost:8002"))
    it('send', function()
        local submit = assert(client:new_submit("GET", "http://localhost:8002", nil))
        local headers = {
            hello = 1
        }
        assert(submit:send_headers(headers))
        assert.equal(submit:submit(true, 1), 200)
    end)
end)
