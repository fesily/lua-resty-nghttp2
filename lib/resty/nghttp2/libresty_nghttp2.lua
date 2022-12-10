require 'ffi.loader'
local ffi = require("ffi")

ffi.cdef [[
  ssize_t resty_nghttp2_data_provider_read_callback(
        nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
        uint32_t *data_flags, nghttp2_data_source *source, void *user_data);
  ssize_t resty_nghttp2_data_provider_string_generator(
        nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t len,
        uint32_t *data_flags, nghttp2_data_source *source, void *user_data);
    int lookup_token(const uint8_t *name, size_t namelen);
    typedef struct http_parser_url {
        uint16_t field_set;           /* Bitmask of (1 << UF_*) values */
        uint16_t port;                /* Converted UF_PORT string */
      
        struct {
          uint16_t off;               /* Offset into buffer in which field starts */
          uint16_t len;               /* Length of run in buffer */
        } field_data[7];
      } http_parser_url;
      
      /* Parse a URL; return nonzero on failure */
      int http_parser_parse_url(const char *buf, size_t buflen,
                                int is_connect,
                                struct http_parser_url *u);
      bool ipv6_numeric_addr(const char* host);
]]

local lib = ffi.load('resty_nghttp2')
local nghttp2 = require 'libresty_nghttp2'
return setmetatable(nghttp2, { __index = lib })
