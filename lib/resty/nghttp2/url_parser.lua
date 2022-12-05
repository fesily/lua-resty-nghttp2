local lib = require 'resty.nghttp2.libresty_nghttp2'
local ffi = require 'ffi'
local _M = {
    UF_SCHEMA = 0
    , UF_HOST = 1
    , UF_PORT = 2
    , UF_PATH = 3
    , UF_QUERY = 4
    , UF_FRAGMENT = 5
    , UF_USERINFO = 6
    , UF_MAX = 7
}

local http_parser_url_t = ffi.typeof "http_parser_url[1]"
function _M.http_parser_parse_url(url)
    local u = http_parser_url_t()
    if lib.http_parser_parse_url(url, #url, 0, u) ~= 0 then
        return nil, "invalid url: " .. url
    end
    return u
end

function _M.ipv6_numeric_addr(host)
    return lib.ipv6_numeric_addr(host)
end

return _M
