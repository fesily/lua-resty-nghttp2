require 'ffi.loader'
local ffi = require("ffi")

ffi.cdef[[
    int lookup_token(const uint8_t *name, size_t namelen);
    struct http_parser_url {
        uint16_t field_set;           /* Bitmask of (1 << UF_*) values */
        uint16_t port;                /* Converted UF_PORT string */
      
        struct {
          uint16_t off;               /* Offset into buffer in which field starts */
          uint16_t len;               /* Length of run in buffer */
        } field_data[7];
      };
      
      /* Parse a URL; return nonzero on failure */
      int http_parser_parse_url(const char *buf, size_t buflen,
                                int is_connect,
                                struct http_parser_url *u);
      bool ipv6_numeric_addr(const char* host);
]]

local lib = ffi.load('resty_nghttp2')

return lib

