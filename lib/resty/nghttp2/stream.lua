local lib = require('resty.nghttp2.libnghttp2')
local ffi = require('ffi')
local bit = require 'bit'

---@class nghttp2.header
---@field value string
---@field sensitive boolean

---@alias nghttp2.headers table<string, nghttp2.header|string>

---@class nghttp2.uri_ref
---@field scheme string
---@field host string
---@field path string
---@field raw_path string
---@field raw_query string
---@field fragment string

---@class nghttp2.request
---@field on_response nil|fun(request:nghttp2.request,response:nghttp2.response)
---@field on_push_request nil|fun(request:nghttp2.request)
---@field on_close nil|fun(request:nghttp2.request,error_code)
---@field generator_cb nil|fun(request:nghttp2.request, buf, len, data_flags)
local request = {}
local request_mt = { __index = request }

local function create_request(stream)
    ---@class nghttp2.request
    return setmetatable({
        ---@type nghttp2.headers
        headers = nil,
        ---@type nghttp2.uri_ref
        uri = {
            scheme = nil,
            host = nil,
            path = nil,
            raw_path = nil,
            raw_query = nil,
            fragment = nil,
        },
        ---@type ngx.http.method
        method = nil,
        body = nil,
        header_buffer_size = 0,
        ---@type nghttp2.stream
        stream = stream,
        generator_cb = nil,
        on_close = nil,
        sem = nil,
        close_season = nil,
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
    if (self.on_close) then
        self:on_close(error_code)
    end
end

function request:call_on_push(request)
    if (self.on_push_request) then
        self.on_push_request(request)
    end
end

function request:call_on_response(response)
    if (self.on_response) then
        self:on_response(response)
    end
end

function request:cancel(error_code)
    self.stream.session:cancel(self.stream, error_code)
end

function request:write_trailer(headers)
    self.headers = headers
    self.stream.session:write_trailer(self.stream, headers)
end

---@class nghttp2.response
---@field on_data fun(response:nghttp2.response,data)
local response = {}
local response_mt = { __index = response }

local function create_response(stream)
    ---@class nghttp2.response
    return setmetatable({
        status = 0,
        content_length = 0,
        header_buffer_size = 0,
        ---@type nghttp2.stream
        stream = stream,
        ---@type nghttp2.headers
        headers = {},
        on_data = nil,
        has_body = false,
        ---@type string[]|nil
        body = nil,
    }, response_mt)
end

function response:update_header_buffer_size(len)
    self.header_buffer_size = self.header_buffer_size + len
end

function response:call_on_data(data)
    if (self.on_data) then
        self:on_data(data)
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
    return self.response.status / 100 == 1
end

local stream_mt = { __index = stream }

---@return nghttp2.stream
return function(stream_id, session)
    local strm = setmetatable({ stream_id = stream_id, session = session }, stream_mt);
    strm.request = create_request(strm)
    strm.response = create_response(strm)
    return strm
end
