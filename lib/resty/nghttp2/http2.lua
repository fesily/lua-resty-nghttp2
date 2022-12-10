local lib = require 'resty.nghttp2.libnghttp2'
local libresty_nghttp2 = require 'resty.nghttp2.libresty_nghttp2'
local ffi = require 'ffi'
local ffi_string = ffi.string
local ffi_cast = ffi.cast
local bit = require 'bit'
local band = bit.band
local lshift = bit.lshift
local _M = {
    HD__AUTHORITY = 0,
    HD__HOST = 1,
    HD__METHOD = 2,
    HD__PATH = 3,
    HD__PROTOCOL = 4,
    HD__SCHEME = 5,
    HD__STATUS = 6,
    HD_ACCEPT_ENCODING = 7,
    HD_ACCEPT_LANGUAGE = 8,
    HD_ALT_SVC = 9,
    HD_CACHE_CONTROL = 10,
    HD_CONNECTION = 11,
    HD_CONTENT_LENGTH = 12,
    HD_CONTENT_TYPE = 13,
    HD_COOKIE = 14,
    HD_DATE = 15,
    HD_EARLY_DATA = 16,
    HD_EXPECT = 17,
    HD_FORWARDED = 18,
    HD_HOST = 19,
    HD_HTTP2_SETTINGS = 20,
    HD_IF_MODIFIED_SINCE = 21,
    HD_KEEP_ALIVE = 22,
    HD_LINK = 23,
    HD_LOCATION = 24,
    HD_PROXY_CONNECTION = 25,
    HD_SEC_WEBSOCKET_ACCEPT = 26,
    HD_SEC_WEBSOCKET_KEY = 27,
    HD_SERVER = 28,
    HD_TE = 29,
    HD_TRAILER = 30,
    HD_TRANSFER_ENCODING = 31,
    HD_UPGRADE = 32,
    HD_USER_AGENT = 33,
    HD_VIA = 34,
    HD_X_FORWARDED_FOR = 35,
    HD_X_FORWARDED_PROTO = 36,
    HD_MAXIDX = 37,
}
---@class nghttp2.nv
---@field name string
---@field value string
---@field namelen integer
---@field valuelen integer
---@field flags integer

---@param nv nghttp2.nv
function _M.make_nv_ls(nv, name, value, flags)
    flags = flags and lib.NGHTTP2_NV_FLAG_NO_INDEX or lib.NGHTTP2_NV_FLAG_NONE
    nv.name = name
    nv.namelen = #name
    nv.value = value
    nv.valuelen = #value
    nv.flags = band(flags, lib.NGHTTP2_NV_FLAG_NO_COPY_NAME, lib.NGHTTP2_NV_FLAG_NO_COPY_VALUE)
end

function _M.lookup_token(name, namelen)
    return libresty_nghttp2.lookup_token(name, namelen or #name)
end

local const_char_ptr = ffi.typeof "const char *"
function _M.copy_url_component(u, field, url)
    if band(u.field_set, lshift(1, field)) ~= 0 then
        return ffi_string(ffi_cast(const_char_ptr, url) + u.field_set[field].off, u.field_set[field].len)
    end
end

return _M
