local lib = require('resty.nghttp2.libnghttp2')
local ffi = require('ffi')
local bit = require 'bit'

---@class nghttp2.header
---@field value string
---@field sensitive boolean

---@alias nghttp2.headers table<string, nghttp2.header>

---@class nghttp2.uri_ref
---@field scheme string
---@field host string
---@field path string
---@field raw_path string
---@field raw_query string
---@field fragment string

---@class nghttp2.request
local request = {
    response_cb = function(response)
    end,
    push_request_cb = function(request)
    end,
    close_cb = function(error_code)
    end,
    generator_cb = function(buf, len, data_flags)
    end,
}
local request_mt = { __index = request }

local function create_request(stream)
    ---@class nghttp2.request
    return setmetatable({
        ---@type nghttp2.headers
        headers = {},
        ---@type nghttp2.uri_ref
        uri = {
            scheme = "",
            host = "",
            path = "",
            raw_path = "",
            raw_query = "",
            fragment = "",
        },
        ---@type ngx.http.method
        method = "",
        header_buffer_size = 0,
        ---@type nghttp2.stream
        stream = stream,
    }, request_mt)
end

function request:update_header_buffer_size(len)
    self.header_buffer_size = self.header_buffer_size + len
end

function request:resume()
    self.stream.session:resume(self.stream)
end

function request:call_on_read(buf, len, data_flags)
    if (self.generator_cb) then
        return self.generator_cb(buf, len, data_flags)
    end
    data_flags[0] = bit.bor(data_flags[0], lib.NGHTTP2_DATA_FLAG_EOF)
    return 0
end

function request:call_on_close(error_code)
    if (self.close_cb) then
        self.close_cb(error_code)
    end
end

function request:call_on_push(request)
    if (self.push_request_cb) then
        self.push_request_cb(request)
    end
end

function request:call_on_response(response)
    if (self.response_cb) then
        self.response_cb(response)
    end
end

function request:cancel(error_code)
    self.stream.session:cancel(self.stream, error_code)
end

function request:write_trailer(headers)
    self.stream.session:write_trailer(self.stream, headers)
end

---@class nghttp2.response
local response = {
    data_cb = function(data, len)
    end,
}
local response_mt = { __index = response }

local function create_response(stream)
    ---@class nghttp2.response
    return setmetatable({
        status_code = 0,
        content_length = 0,
        header_buffer_size = 0,
        ---@type nghttp2.stream
        stream = stream,
        ---@type nghttp2.headers
        headers = {},
    }, response_mt)
end

function response:update_header_buffer_size(len)
    self.header_buffer_size = self.header_buffer_size + len
end

function response:call_on_data(data, len)
    if (self.data_cb) then
        self.data_cb(data, len)
    end
end

---@class nghttp2.stream
---@field session nghttp2.session
---@field stream_id integer
---@field response nghttp2.response
---@field request nghttp2.request
local stream = {}

---@return boolean
function stream:expect_final_response()
    return self.response.status_code / 100 == 1
end

local stream_mt = { __index = stream }

---@return nghttp2.stream
return function(stream_id, session)
    local strm = setmetatable({ stream_id = stream_id, session = session }, stream_mt);
    strm.request = create_request(strm)
    strm.response = create_response(strm)
    return strm
end
