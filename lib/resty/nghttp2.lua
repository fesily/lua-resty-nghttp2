---
--- Generated by Luanalysis
--- Created by fesil.
--- DateTime: 2022/10/31 10:48
---
local semaphore = require 'ngx.semaphore'
local ffi = require 'ffi'
local base = require 'resty.core.base'
local lib = require 'resty.nghttp2.libnghttp2'
local submit = require 'resty.nghttp2.submit'
local ctx = require 'lib.resty.nghttp2.ctx'

local _M = {}
local _mt = {
    __index = _M
}

local errlen = 1024

local function get_client_error(client)
    local buf = base.get_string_buf(errlen, false)
    local ret = lib.nghttp2_asio_client_error(client, buf, errlen)
    if ret == 0 then
        return ffi.string(buf)
    end
    if ret == 1 then
        return
    end
    return "unknown error"
end

---@param uri string
---@param connection_timeout? number
---@param read_timeout? number
function _M.new(uri, connection_timeout, read_timeout)
    local nghttp2_ctx, err = ctx.init_ctx()
    if not nghttp2_ctx then
        return nil, err
    end

    if not uri then
        return nil, 'uri is required'
    end

    if ctx.clients[uri] then
        local client = ctx.clients[uri]
        if lib.nghttp2_asio_client_is_ready(client) then
            return client
        end
    end

    connection_timeout = connection_timeout or 10;
    read_timeout = read_timeout or 10;
    local sem, err = semaphore.new()
    if not sem then
        ngx.log(ngx.ERR, 'Could not create semaphore:', err)
        return true
    end

    local handler = lib.nghttp2_asio_client_new(nghttp2_ctx, uri, read_timeout, connection_timeout, sem.sem)
    if handler == nil then
        return nil, ctx.get_error(nghttp2_ctx)
    end

    local ok, err = sem:wait(connection_timeout)
    if not ok then
        lib.nghttp2_asio_client_delete(handler)
        return nil, err
    end
    ffi.gc(handler, lib.nghttp2_asio_client_delete)

    if not lib.nghttp2_asio_client_is_ready(handler) then
        return nil, get_client_error(handler)
    end

    local client = setmetatable({
        nghttp2_ctx,
        handler = handler,
        uri = uri,
        read_timeout = read_timeout,
        connection_timeout = connection_timeout,
    }, _mt)
    -- set error event
    ctx.clients[uri] = client
    return client
end

---@param method "GET"|"POST"|"PUT"|"DELETE"
---@param uri string
---@param data? string
function _M:new_submit(method, uri, data)
    if not lib.nghttp2_asio_client_is_ready(self.handler) then
        -- session is stopped,so we need create a new session
        return nil, 'retry'
    end
    local handler = lib.nghttp2_asio_submit_new(self.handler, method, uri, data, nil)
    if handler == nil then
        return nil, 'can\' create submit'
    end
    ffi.gc(handler, lib.nghttp2_asio_submit_delete)
    return submit.new(handler, get_client_error, self.handler)
end

function _M:restart()
    ctx.clients[self.uri] = nil
    return _M.new(self.uri, self.connection_timeout, self.read_timeout)
end

local function retry(self, method, uri, headers, data, read_headers, timeout)
    local client, err = self:restart()
    if not client then return nil, err end
    return client:request(method, uri, headers, data, read_headers, timeout)
end

---@param method "GET"|"POST"|"PUT"|"DELETE"
---@param uri string
---@param headers? table<string,string>
---@param data? string
---@param read_headers? boolean
---@param timeout? number
function _M:request(method, uri, headers, data, read_headers, timeout)
    local submit, err = _M.new_submit(self, method, uri, data)
    if not submit then
        if err == 'retry' then
            return retry(self, method, uri, headers, data, read_headers, timeout)
        end
        return nil, err
    end
    if headers then
        submit:send_headers(headers)
    end
    local status_code, err = submit:submit(read_headers, timeout or 10)
    if not status_code then
        if err == 'retry' then
            return retry(self, method, uri, headers, data, read_headers, timeout)
        end
        return nil, err
    end

    submit.status = status_code
    submit.has_body = submit:bodys_length() > 0
    return submit
end

return _M
