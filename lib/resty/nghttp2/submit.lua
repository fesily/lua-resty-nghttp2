local ffi = require "ffi"
local base = require 'resty.core.base'
local lib = require "resty.nghttp2.libnghttp2"
local semaphore = require 'ngx.semaphore'

local tab_new = require("table.new")
local tab_insert = table.insert
local c_str_arr_t = ffi.typeof("const char*[?]")
local tab_is_array = require 'table.isarray'
local errlen = 1024

local _M = {}
local _mt = {
    __index = _M
}
---@alias header_value string|boolean
---@param headers table<string,string>| header_value[]
function _M:send_headers(headers)
    assert(not self.submited)
    if type(headers) ~= 'table' then
        return nil, 'headers must be a table'
    end

    if tab_is_array(headers) then

        for _, v in ipairs(headers) do
            if type(v) ~= 'table' then
                return nil, 'array headers value must be a table'
            end
            local key = tostring(v[0])
            local value = tostring(v[1])
            local sensitive = tostring(v[3])

            lib.nghttp2_asio_request_push_headers(self.handler, key, value, sensitive)
        end
    else
        for k, v in pairs(headers) do
            lib.nghttp2_asio_request_push_headers(self.handler, tostring(k), tostring(v), false)
        end
    end
    return true
end

function _M:send_body(body)
    assert(not self.submited)
    if type(body) == 'function' then
        --lib.nghttp2_asio_client_submit_request_set_body_iter(self.handler, body)
    else

        return lib.nghttp2_asio_request_set_body(self.handler, tostring(body)) == 0
    end
    return nil, 'Not implemented body type'
end

local nghttp2_http2_err = {
    [0] = "no_error",
    "protocol_error",
    "internal_error",
    "flow_control_error",
    "settings_timeout",
    "stream_closed",
    "frame_size_error",
    "refused_stream",
    "cancel",
    "compression_error",
    "connect_error",
    "enhance_your_calm",
    "inadequate_security",
    "http_1_1_required",
}

local function get_error(msg)
    return nghttp2_http2_err[tonumber(msg)] or "unknown"
end

---@return ngx.http.status_code?,string?
function _M:submit(read_response_headers, timeout)
    assert(not self.submited)
    local sem, err = semaphore.new()
    if not sem then
        return nil, err
    end
    self.read_response_headers = read_response_headers
    self.submited = true
    if lib.nghttp2_asio_client_submit(self.client, self.handler, not not read_response_headers, sem.sem) ~= 0 then
        return nil, self.get_client_error(self.client)
    end
    local ok, err = sem:wait(timeout)
    if not ok then
        ffi.gc(self.handler, nil)
        -- delete sem handler right now
        lib.nghttp2_asio_submit_delete(self.handler)
        return nil, err
    end

    local status_code = lib.nghttp2_asio_response_code(self.handler);
    if status_code == 0 then
        local msg = lib.nghttp2_asio_submit_error(self.handler)
        local NGHTTP2_REFUSED_STREAM = 7
        if msg == NGHTTP2_REFUSED_STREAM then
            return nil, "retry"
        end
        return nil, get_error(msg)
    end
    return status_code
end

local keys = c_str_arr_t(128)
local values = c_str_arr_t(128)
local function get_cache_keys(len)
    if len > 128 then
        return c_str_arr_t(len)
    else
        return keys
    end
end

local function get_cache_values(len)
    if len > 128 then
        return c_str_arr_t(len)
    else
        return values
    end
end

function _M:read_headers()
    if self.read_response_headers then
        local len = lib.nghttp2_asio_response_header_length(self.handler);
        if len == 0 then
            return
        end
        local keys = get_cache_keys(len)
        local values = get_cache_values(len)
        len = lib.nghttp2_asio_response_headers(self.handler, keys, values,
            self.read_response_headers)
        if len == 0 then
            return
        end
        local headers = tab_new(0, len)
        for i = 1, len do
            local key = ffi.string(keys[i - 1])
            local value = ffi.string(values[i - 1])
            headers[key] = value
        end
        return headers
    end
    return nil, 'cant read headers'
end

function _M:bodys_length()
    return lib.nghttp2_asio_response_body_length(self.handler)
end
---@return string[]|string?
function _M:read_bodys()
    local datalen = lib.nghttp2_asio_response_body_length(self.handler);
    if datalen > 0 then
        if datalen == 1 then
            local data = lib.nghttp2_asio_response_body(self.handler, 0)
            if data == nil then
                return nil, 'cant read body'
            end
            return ffi.string(data)
        end
        local bodys = tab_new(datalen, 0)
        for i = 1, datalen, 1 do
            local data = lib.nghttp2_asio_response_body(self.handler, i - 1)
            if data then
                tab_insert(bodys, ffi.string(data))
            end
        end
        return bodys
    end
end

---@param maxlength? number
---@return string?,string?
function _M:read_body(maxlength)
    local content_length = lib.nghttp2_asio_response_content_length(self.handler);
    if content_length == -1 then
        local bodys, err = _M.read_bodys(self)
        if not bodys then
            return nil, err
        end
        if type(bodys) ~= 'table' then
            return bodys
        end
        return table.concat(bodys, "")
    end
    if maxlength and content_length > maxlength then
        content_length = maxlength
    end
    local buf = base.get_string_buf(content_length, false)

    content_length = lib.nghttp2_asio_response_content(self.handler, buf, content_length)

    if content_length == 0 then
        return nil, 'no body'
    end

    return ffi.string(buf, content_length)
end

function _M.new(handler, get_client_error, client)
    return setmetatable({
        handler = handler,
        get_client_error = get_client_error,
        client = client,
        read_response_headers = false,
        submited = false,
    }, _mt)
end

return _M
