#include "luajit_cdata_pointer.h"

extern "C" {
#include <nghttp2/nghttp2.h>
}
#if defined(__clang__) || defined(__GNUC__)
#define LIKELY(x)    __builtin_expect(!!(x), 1)
#define UNLIKELY(x)    __builtin_expect(!!(x), 0)
#else
#define LIKELY(x)    (x)
#define UNLIKELY(x)   (x)
#endif

static int luajit_nghttp2_session_mem_recv(lua_State *L) {
    auto sz = lua_gettop(L);
    if (UNLIKELY(!(sz == 3 || sz == 2))) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "args number must is 2 or 3");
        return 2;
    }
    if (UNLIKELY(lua_type(L, 1) != 10)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, "first arg must is nghttp2_session*");
        return 2;
    }

    nghttp2_session *session = luajit::lua_get_from_cdata_unsafe<nghttp2_session *>(L, -1);
    size_t inlen = 0;
    const char *in;
    auto tt = lua_type(L, 2);
    if (tt == 10) {
        auto size = lua_gettop(L);
        if (size == 3) {
            inlen = lua_tointeger(L, 3);
            if (UNLIKELY(inlen == 0)) {
                lua_pushboolean(L, false);
                lua_pushstring(L, "three arg must is a integer");
                return 2;
            }
            in = luajit::lua_get_from_cdata_unsafe<const char *>(L, -1);
        } else {
            auto arr = luajit::lua_get_from_cdata_unsafe<char[]>(L, -1);
            inlen = arr.size();
            in = arr.data();
            if (UNLIKELY(in == nullptr || inlen == 0)) {
                lua_pushboolean(L, false);
                lua_pushstring(L, "second arg must is char[]");
                return 2;
            }
        }
    } else {
        in = lua_tolstring(L, -2, &inlen);
        if (UNLIKELY(in == nullptr)) {
            lua_pushboolean(L, false);
            lua_pushstring(L, "second arg must is string or const char*");
            return 2;
        }
    }
    auto ret = nghttp2_session_mem_recv(session, (const uint8_t *) in, inlen);
    lua_pushinteger(L, ret);
    return 1;
}


int luaopen_nghttp2(lua_State *L) {
    luajit::init_ffi_api(L);
    luaL_Reg fns[] = {
            {"recv",  luajit_nghttp2_session_mem_recv},
            {nullptr, nullptr}
    };
    luaL_newlib(L, fns);
    return 1;
}

namespace util{
    
template <typename CharT, typename InputIt, size_t N>
bool streq_l(const CharT (&a)[N], InputIt b, size_t blen) {
  return streq(a, a + (N - 1), b, b + blen);
}

template <typename CharT, size_t N, typename T>
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
int lookup_token(const uint8_t *name, size_t namelen) {
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
#endif // !_WIN32

#ifndef _WIN32
namespace {
int nghttp2_inet_pton(int af, const char *src, void *dst) {
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

bool ipv6_numeric_addr(const char* host){
    uint8_t dst[16];
    return nghttp2_inet_pton(AF_INET6, host, dst) == 1;
}