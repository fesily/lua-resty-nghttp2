//
// Created by fesil on 2022/12/6.
//

#ifndef RESTY_NGHTTP2_RESTY_NGHTTP2_H
#define RESTY_NGHTTP2_RESTY_NGHTTP2_H
extern "C" {
ssize_t resty_nghttp2_data_provider_read_callback(
        nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
        uint32_t *data_flags, nghttp2_data_source *source, void *user_data) noexcept;
ssize_t resty_nghttp2_data_provider_string_generator(
        nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t len,
        uint32_t *data_flags, nghttp2_data_source *source, void *user_data) noexcept;
int luaopen_libresty_nghttp2(lua_State *L) noexcept;
int lookup_token(const uint8_t *name, size_t namelen) noexcept;
bool ipv6_numeric_addr(const char *host) noexcept;
};
#endif //RESTY_NGHTTP2_RESTY_NGHTTP2_H
