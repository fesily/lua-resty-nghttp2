#include <dlfcn.h>
#include "luajit_cdata_pointer.h"
#include <string>

extern "C" {
#include <nghttp2/nghttp2.h>
}

#include "resty_nghttp2.h"

#if defined(__clang__) || defined(__GNUC__)
#define LIKELY(x)    __builtin_expect(!!(x), 1)
#define UNLIKELY(x)    __builtin_expect(!!(x), 0)
#else
#define LIKELY(x)    (x)
#define UNLIKELY(x)   (x)
#endif

static lua_State *luajit_nghttp2_current_state;
static char luajit_nghttp2_mask;

static int luajit_nghttp2_session_mem_recv(lua_State *L) noexcept {
    luajit::check_lua_stack check{L, 2};
    auto sz = lua_gettop(L);
    if (UNLIKELY(sz != 2)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "args number must is 2");
        return 2;
    }
    if (UNLIKELY(lua_type(L, 1) != 10)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "first arg must is nghttp2_session*");
        return 2;
    }

    nghttp2_session *session = luajit::lua_get_from_cdata_unsafe<nghttp2_session *>(L, 1);
    size_t inlen = 0;
    const char *in = lua_tolstring(L, 2, &inlen);
    if (UNLIKELY(in == nullptr)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "second arg must is string or const char*");
        return 2;
    }
    luajit_nghttp2_current_state = L;
    auto ret = nghttp2_session_mem_recv(session, (const uint8_t *) in, inlen);
    luajit_nghttp2_current_state = nullptr;
    if (UNLIKELY(ret != inlen)) {
        lua_pushnil(L);
        if (ret < 0) {
            lua_pushstring(L, nghttp2_strerror((int) ret));
        } else {
            lua_pushstring(L, "General protocol error");
        }
        return 2;
    }
    check.offset = 1;
    lua_pushinteger(L, ret);
    return 1;
}

static int luajit_nghttp2_session_mem_send(lua_State *L) noexcept {
    luajit::check_lua_stack check{L, 2};
    auto sz = lua_gettop(L);
    assert(sz == 1);
    if (UNLIKELY(sz != 1)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "args number must is 1");
        return 2;
    }
    auto tt = lua_type(L, 1);
    assert(tt == 10);
    if (UNLIKELY(tt != 10)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "first arg must is nghttp2_session*");
        return 2;
    }
    luajit_nghttp2_current_state = L;
    auto session = luajit::lua_get_from_cdata_unsafe<nghttp2_session *>(L, 1);
    const uint8_t *data = nullptr;
    auto ret = nghttp2_session_mem_send(session, &data);
    luajit_nghttp2_current_state = nullptr;
    if (UNLIKELY(ret < 0)) {
        lua_pushnil(L);
        lua_pushstring(L, nghttp2_strerror((int) ret));
        return 2;
    }
    if (ret != 0) {
        assert(data);
        lua_pushlstring(L, (const char *) data, ret);
        check.offset = 1;
        return 1;
    }
    check.offset = 0;
    return 0;
}

static int luajit_nghttp2_on_stream_close_callback(nghttp2_session *session,
                                                   int32_t stream_id,
                                                   uint32_t error_code,
                                                   void *user_data) {
    assert(luajit_nghttp2_current_state);
    if (UNLIKELY(!luajit_nghttp2_current_state)) {
        return nghttp2_error::NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto L = luajit_nghttp2_current_state;
    luajit::check_lua_stack checkLuaStack{L};

    lua_pushlightuserdata(L, &luajit_nghttp2_mask);
    lua_gettable(L, LUA_REGISTRYINDEX);
    lua_getfield(L, -1, "on_stream_close");
    assert(lua_type(L, -1) == LUA_TFUNCTION);

    lua_pushlightuserdata(L, session);
    lua_pushinteger(L, stream_id);
    lua_pushinteger(L, error_code);
    lua_pushlightuserdata(L, user_data);
    auto rv = lua_pcall(L, 4, 1, 0);
    if (rv != 0) {
        return nghttp2_error::NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto ret = (int) lua_tointeger(L, -1);
    lua_pop(L, 2);
    return ret;
}

static int luajit_nghttp2_on_data_chunk_recv_callback(nghttp2_session *session,
                                                      uint8_t flags,
                                                      int32_t stream_id,
                                                      const uint8_t *data,
                                                      size_t len, void *user_data) {
    assert(luajit_nghttp2_current_state);
    if (UNLIKELY(!luajit_nghttp2_current_state)) {
        return nghttp2_error::NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto L = luajit_nghttp2_current_state;
    luajit::check_lua_stack checkLuaStack{L};

    lua_pushlightuserdata(L, &luajit_nghttp2_mask);
    lua_gettable(L, LUA_REGISTRYINDEX);
    lua_getfield(L, -1, "on_data_chunk_recv");
    assert(lua_type(L, -1) == LUA_TFUNCTION);

    lua_pushlightuserdata(L, session);
    lua_pushinteger(L, flags);
    lua_pushinteger(L, stream_id);
    lua_pushlstring(L, (const char *) data, len);
    lua_pushlightuserdata(L, user_data);
    auto rv = lua_pcall(L, 5, 1, 0);
    if (rv != 0) {
        return nghttp2_error::NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto ret = (int) lua_tointeger(L, -1);
    lua_pop(L, 2);
    return ret;
}

static int luajit_nghttp2_on_frame_recv_callback(nghttp2_session *session,
                                                 const nghttp2_frame *frame,
                                                 void *user_data) {
    assert(luajit_nghttp2_current_state);
    if (UNLIKELY(!luajit_nghttp2_current_state)) {
        return nghttp2_error::NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto L = luajit_nghttp2_current_state;
    luajit::check_lua_stack checkLuaStack{L};

    lua_pushlightuserdata(L, &luajit_nghttp2_mask);
    lua_gettable(L, LUA_REGISTRYINDEX);
    lua_getfield(L, -1, "on_frame_recv");
    assert(lua_type(L, -1) == LUA_TFUNCTION);

    lua_pushlightuserdata(L, session);
    lua_pushlightuserdata(L, (void *) frame);
    lua_pushlightuserdata(L, user_data);
    auto rv = lua_pcall(L, 3, 1, 0);
    if (rv != 0) {
        return nghttp2_error::NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto ret = (int) lua_tointeger(L, -1);
    lua_pop(L, 2);
    return ret;
}

static int luajit_nghttp2_on_header_callback(nghttp2_session *session,
                                             const nghttp2_frame *frame,
                                             const uint8_t *name, size_t namelen,
                                             const uint8_t *value, size_t valuelen,
                                             uint8_t flags, void *user_data) {
    assert(luajit_nghttp2_current_state);
    if (UNLIKELY(!luajit_nghttp2_current_state)) {
        return nghttp2_error::NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto L = luajit_nghttp2_current_state;
    luajit::check_lua_stack checkLuaStack{L};

    lua_pushlightuserdata(L, &luajit_nghttp2_mask);
    lua_gettable(L, LUA_REGISTRYINDEX);
    lua_getfield(L, -1, "on_header");
    assert(lua_type(L, -1) == LUA_TFUNCTION);

    lua_pushlightuserdata(L, session);
    lua_pushlightuserdata(L, (void *) frame);
    lua_pushlstring(L, (const char *) name, namelen);
    lua_pushlstring(L, (const char *) value, valuelen);
    lua_pushinteger(L, flags);
    lua_pushlightuserdata(L, user_data);
    auto rv = lua_pcall(L, 6, 1, 0);
    if (rv != 0) {
        return nghttp2_error::NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto ret = (int) lua_tointeger(L, -1);
    lua_pop(L, 2);
    return ret;
}

static int luajit_nghttp2_on_begin_headers_callback(nghttp2_session *session,
                                                    const nghttp2_frame *frame,
                                                    void *user_data) {
    assert(luajit_nghttp2_current_state);
    if (UNLIKELY(!luajit_nghttp2_current_state)) {
        return nghttp2_error::NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto L = luajit_nghttp2_current_state;
    luajit::check_lua_stack checkLuaStack{L};

    lua_pushlightuserdata(L, &luajit_nghttp2_mask);
    lua_gettable(L, LUA_REGISTRYINDEX);
    lua_getfield(L, -1, "on_begin_headers");
    assert(lua_type(L, -1) == LUA_TFUNCTION);

    lua_pushlightuserdata(L, session);
    lua_pushlightuserdata(L, (void *) frame);
    lua_pushlightuserdata(L, user_data);
    auto rv = lua_pcall(L, 3, 1, 0);
    if (rv != 0) {
        return nghttp2_error::NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto ret = (int) lua_tointeger(L, -1);
    lua_pop(L, 2);
    return ret;
}

static int luajit_nghttp2_init_callbacks(lua_State *L) {
    luajit::check_lua_stack checkLuaStack{L};
    auto sz = lua_gettop(L);
    if (UNLIKELY(sz != 1)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "args number must is 1");
        return 2;
    }
    if (UNLIKELY(lua_type(L, 1) != 10)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "first arg must is nghttp2_session*");
        return 2;
    }
    auto cb = luajit::lua_get_from_cdata_unsafe<nghttp2_session_callbacks *>(L, 1);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, luajit_nghttp2_on_stream_close_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, luajit_nghttp2_on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cb, luajit_nghttp2_on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, luajit_nghttp2_on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_header_callback(cb, luajit_nghttp2_on_header_callback);
    return 0;
}


static std::string get_libnghttp2_path() {
    Dl_info info;
    if (dladdr((void *) &nghttp2_session_mem_send, &info) == 0) {
        return {};
    }
    return info.dli_fname;
}

static int libnghttp2_path(lua_State *L) {
    static std::string path = get_libnghttp2_path();
    lua_pushlstring(L, path.c_str(), path.size());
    return 1;
}

int luaopen_libresty_nghttp2(lua_State *L) noexcept {
    luajit::check_lua_stack check{L, 1};
    luaL_Reg fns[] = {
            {"mem_recv",       luajit_nghttp2_session_mem_recv},
            {"mem_send",       luajit_nghttp2_session_mem_send},
            {"init_callbacks", luajit_nghttp2_init_callbacks},
            {"lib_path",       libnghttp2_path},
            {nullptr,          nullptr}
    };
    luaL_newlib(L, fns);
    lua_pushlightuserdata(L, &luajit_nghttp2_mask);
    lua_pushvalue(L, -2);
    lua_settable(L, LUA_REGISTRYINDEX);
    return 1;
}

struct nghttp2_data_string_source {
    const char *data;
    size_t data_len;
    size_t left;
};

ssize_t resty_nghttp2_data_provider_string_generator(
        nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t len,
        uint32_t *data_flags, nghttp2_data_source *source, void *user_data) noexcept {
    if (source && source->ptr) {
        auto string_source = static_cast<nghttp2_data_string_source *>(source->ptr);
        auto &left = string_source->left;
        auto &data = string_source->data;
        auto n = std::min(len, left);
        std::copy_n(data + string_source->data_len - left, n, buf);
        left -= n;
        if (left == 0) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return (long) n;
    }
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return 0;
}

typedef ssize_t (*resty_nghttp2_data_provider_read_callback1)(int32_t stream_id, uint8_t *buf, size_t length,
                                                              uint32_t *data_flags, void *user_data);

ssize_t resty_nghttp2_data_provider_read_callback(
        nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
        uint32_t *data_flags, nghttp2_data_source *source, void *user_data) noexcept {
    if (LIKELY(source->ptr)) {
        auto cb = (resty_nghttp2_data_provider_read_callback1) source->ptr;
        return cb(stream_id, buf, length, data_flags, user_data);
    }
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return 0;
}


namespace util {

    template<typename InputIt1, typename InputIt2>
    bool streq(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2) {
        if (std::distance(first1, last1) != std::distance(first2, last2)) {
            return false;
        }
        return std::equal(first1, last1, first2);
    }

    template<typename T, typename S>
    bool streq(const T &a, const S &b) {
        return streq(a.begin(), a.end(), b.begin(), b.end());
    }

    template<typename CharT, typename InputIt, size_t N>
    bool streq_l(const CharT (&a)[N], InputIt b, size_t blen) {
        return streq(a, a + (N - 1), b, b + blen);
    }

    template<typename CharT, size_t N, typename T>
    bool streq_l(const CharT (&a)[N], const T &b) {
        return streq(a, a + (N - 1), b.begin(), b.end());
    }
}
enum {
    HD__AUTHORITY,
    HD__HOST,
    HD__METHOD,
    HD__PATH,
    HD__PROTOCOL,
    HD__SCHEME,
    HD__STATUS,
    HD_ACCEPT_ENCODING,
    HD_ACCEPT_LANGUAGE,
    HD_ALT_SVC,
    HD_CACHE_CONTROL,
    HD_CONNECTION,
    HD_CONTENT_LENGTH,
    HD_CONTENT_TYPE,
    HD_COOKIE,
    HD_DATE,
    HD_EARLY_DATA,
    HD_EXPECT,
    HD_FORWARDED,
    HD_HOST,
    HD_HTTP2_SETTINGS,
    HD_IF_MODIFIED_SINCE,
    HD_KEEP_ALIVE,
    HD_LINK,
    HD_LOCATION,
    HD_PROXY_CONNECTION,
    HD_SEC_WEBSOCKET_ACCEPT,
    HD_SEC_WEBSOCKET_KEY,
    HD_SERVER,
    HD_TE,
    HD_TRAILER,
    HD_TRANSFER_ENCODING,
    HD_UPGRADE,
    HD_USER_AGENT,
    HD_VIA,
    HD_X_FORWARDED_FOR,
    HD_X_FORWARDED_PROTO,
    HD_MAXIDX,
};

int lookup_token(const uint8_t *name, size_t namelen) noexcept {
    switch (namelen) {
        case 2:
            switch (name[1]) {
                case 'e':
                    if (util::streq_l("t", name, 1)) {
                        return HD_TE;
                    }
                    break;
            }
            break;
        case 3:
            switch (name[2]) {
                case 'a':
                    if (util::streq_l("vi", name, 2)) {
                        return HD_VIA;
                    }
                    break;
            }
            break;
        case 4:
            switch (name[3]) {
                case 'e':
                    if (util::streq_l("dat", name, 3)) {
                        return HD_DATE;
                    }
                    break;
                case 'k':
                    if (util::streq_l("lin", name, 3)) {
                        return HD_LINK;
                    }
                    break;
                case 't':
                    if (util::streq_l("hos", name, 3)) {
                        return HD_HOST;
                    }
                    break;
            }
            break;
        case 5:
            switch (name[4]) {
                case 'h':
                    if (util::streq_l(":pat", name, 4)) {
                        return HD__PATH;
                    }
                    break;
                case 't':
                    if (util::streq_l(":hos", name, 4)) {
                        return HD__HOST;
                    }
                    break;
            }
            break;
        case 6:
            switch (name[5]) {
                case 'e':
                    if (util::streq_l("cooki", name, 5)) {
                        return HD_COOKIE;
                    }
                    break;
                case 'r':
                    if (util::streq_l("serve", name, 5)) {
                        return HD_SERVER;
                    }
                    break;
                case 't':
                    if (util::streq_l("expec", name, 5)) {
                        return HD_EXPECT;
                    }
                    break;
            }
            break;
        case 7:
            switch (name[6]) {
                case 'c':
                    if (util::streq_l("alt-sv", name, 6)) {
                        return HD_ALT_SVC;
                    }
                    break;
                case 'd':
                    if (util::streq_l(":metho", name, 6)) {
                        return HD__METHOD;
                    }
                    break;
                case 'e':
                    if (util::streq_l(":schem", name, 6)) {
                        return HD__SCHEME;
                    }
                    if (util::streq_l("upgrad", name, 6)) {
                        return HD_UPGRADE;
                    }
                    break;
                case 'r':
                    if (util::streq_l("traile", name, 6)) {
                        return HD_TRAILER;
                    }
                    break;
                case 's':
                    if (util::streq_l(":statu", name, 6)) {
                        return HD__STATUS;
                    }
                    break;
            }
            break;
        case 8:
            switch (name[7]) {
                case 'n':
                    if (util::streq_l("locatio", name, 7)) {
                        return HD_LOCATION;
                    }
                    break;
            }
            break;
        case 9:
            switch (name[8]) {
                case 'd':
                    if (util::streq_l("forwarde", name, 8)) {
                        return HD_FORWARDED;
                    }
                    break;
                case 'l':
                    if (util::streq_l(":protoco", name, 8)) {
                        return HD__PROTOCOL;
                    }
                    break;
            }
            break;
        case 10:
            switch (name[9]) {
                case 'a':
                    if (util::streq_l("early-dat", name, 9)) {
                        return HD_EARLY_DATA;
                    }
                    break;
                case 'e':
                    if (util::streq_l("keep-aliv", name, 9)) {
                        return HD_KEEP_ALIVE;
                    }
                    break;
                case 'n':
                    if (util::streq_l("connectio", name, 9)) {
                        return HD_CONNECTION;
                    }
                    break;
                case 't':
                    if (util::streq_l("user-agen", name, 9)) {
                        return HD_USER_AGENT;
                    }
                    break;
                case 'y':
                    if (util::streq_l(":authorit", name, 9)) {
                        return HD__AUTHORITY;
                    }
                    break;
            }
            break;
        case 12:
            switch (name[11]) {
                case 'e':
                    if (util::streq_l("content-typ", name, 11)) {
                        return HD_CONTENT_TYPE;
                    }
                    break;
            }
            break;
        case 13:
            switch (name[12]) {
                case 'l':
                    if (util::streq_l("cache-contro", name, 12)) {
                        return HD_CACHE_CONTROL;
                    }
                    break;
            }
            break;
        case 14:
            switch (name[13]) {
                case 'h':
                    if (util::streq_l("content-lengt", name, 13)) {
                        return HD_CONTENT_LENGTH;
                    }
                    break;
                case 's':
                    if (util::streq_l("http2-setting", name, 13)) {
                        return HD_HTTP2_SETTINGS;
                    }
                    break;
            }
            break;
        case 15:
            switch (name[14]) {
                case 'e':
                    if (util::streq_l("accept-languag", name, 14)) {
                        return HD_ACCEPT_LANGUAGE;
                    }
                    break;
                case 'g':
                    if (util::streq_l("accept-encodin", name, 14)) {
                        return HD_ACCEPT_ENCODING;
                    }
                    break;
                case 'r':
                    if (util::streq_l("x-forwarded-fo", name, 14)) {
                        return HD_X_FORWARDED_FOR;
                    }
                    break;
            }
            break;
        case 16:
            switch (name[15]) {
                case 'n':
                    if (util::streq_l("proxy-connectio", name, 15)) {
                        return HD_PROXY_CONNECTION;
                    }
                    break;
            }
            break;
        case 17:
            switch (name[16]) {
                case 'e':
                    if (util::streq_l("if-modified-sinc", name, 16)) {
                        return HD_IF_MODIFIED_SINCE;
                    }
                    break;
                case 'g':
                    if (util::streq_l("transfer-encodin", name, 16)) {
                        return HD_TRANSFER_ENCODING;
                    }
                    break;
                case 'o':
                    if (util::streq_l("x-forwarded-prot", name, 16)) {
                        return HD_X_FORWARDED_PROTO;
                    }
                    break;
                case 'y':
                    if (util::streq_l("sec-websocket-ke", name, 16)) {
                        return HD_SEC_WEBSOCKET_KEY;
                    }
                    break;
            }
            break;
        case 20:
            switch (name[19]) {
                case 't':
                    if (util::streq_l("sec-websocket-accep", name, 19)) {
                        return HD_SEC_WEBSOCKET_ACCEPT;
                    }
                    break;
            }
            break;
    }
    return -1;
}

#ifdef _WIN32
#  include <ws2tcpip.h>
#  include <boost/date_time/posix_time/posix_time.hpp>
#else // !_WIN32

#include <netinet/tcp.h>
#include <arpa/inet.h>

#endif // !_WIN32

#ifndef _WIN32
namespace {
    int nghttp2_inet_pton(int af, const char *src, void *dst) noexcept {
        return inet_pton(af, src, dst);
    }
} // namespace
#else // _WIN32
namespace {
// inet_pton-wrapper for Windows
int nghttp2_inet_pton(int af, const char *src, void *dst) {
#  if _WIN32_WINNT >= 0x0600
  return InetPtonA(af, src, dst);
#  else
  // the function takes a 'char*', so we need to make a copy
  char addr[INET6_ADDRSTRLEN + 1];
  strncpy(addr, src, sizeof(addr));
  addr[sizeof(addr) - 1] = 0;

  int size = sizeof(struct in6_addr);

  if (WSAStringToAddress(addr, af, nullptr, (LPSOCKADDR)dst, &size) == 0)
    return 1;
  return 0;
#  endif
}
} // namespace
#endif // _WIN32

bool ipv6_numeric_addr(const char *host) noexcept {
    uint8_t dst[16];
    return nghttp2_inet_pton(AF_INET6, host, dst) == 1;
}