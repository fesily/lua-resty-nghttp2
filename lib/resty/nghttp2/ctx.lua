local lib = require "resty.nghttp2.libnghttp2"
local base = require "resty.core.base"
local ffi = require 'ffi'

local subsystem = ngx.config.subsystem
local C = ffi.C
local ngx_lua_ffi_sema_post
if subsystem == 'http' then
    ngx_lua_ffi_sema_post = C.ngx_http_lua_ffi_sema_post

elseif subsystem == 'stream' then
    ngx_lua_ffi_sema_post = C.ngx_stream_lua_ffi_sema_post
end

local _M = { clients = {} }

local errlen = 1024

local tick = 0
local nghttp2_ctx

local function timer(p)
    if p then
        nghttp2_ctx = nil
        return
    end
    local count = 0
    while nghttp2_ctx do
        if lib.nghttp2_asio_run(nghttp2_ctx) > 0 then
            local err = _M.get_error(nghttp2_ctx)
            if err then
                ngx.log(ngx.ERR, "nghttp2 run err:", err)
            end
        end
        ngx.sleep(tick)
        count = count + 1
        if count > 100 then
            break
        end
    end
    ngx.timer.at(tick, timer, nghttp2_ctx)
end
local function nghttp2_asio_release_ctx(ctx)
    for k, v in pairs(_M.clients) do
        ffi.gc(v, nil)
        lib.nghttp2_asio_client_delete(v.handler)
    end
    _M.clients = {}
    lib.nghttp2_asio_release_ctx(ctx)
end
function _M.init_ctx()
    if nghttp2_ctx then
        return nghttp2_ctx
    end
    local ctx = lib.nghttp2_asio_init_ctx(ngx_lua_ffi_sema_post)
    if ctx == nil then
        return nil, 'Could not initialize nghttp2_asio_client'
    end
    ffi.gc(ctx, nghttp2_asio_release_ctx)
    ngx.timer.at(tick, timer, ctx)
    nghttp2_ctx = ctx
    return ctx
end

function _M.release_ctx()
    if not nghttp2_ctx then
        return
    end
    nghttp2_ctx = nil
end

function _M.get_error(ctx)
    local buf = base.get_string_buf(errlen, false)
    local ret = lib.nghttp2_asio_error(ctx, buf, errlen)

    if ret == 0 then
        return ffi.string(buf)
    end
    if ret == 1 then
        return nil
    end
    return "unknown error"
end

return _M
