//
// Created by fesily on 2022/10/27.
//

#include <iostream>

#include <nghttp2/asio_http2_client.h>
#include <nghttp2/asio_http2.h>

#include <optional>
#include <variant>

#include "resty_nghttp2.h"
#include <list>

using boost::asio::ip::tcp;

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::client;

#ifndef ENABLE_HTTPS
#define ENABLE_HTTPS 1
#endif
struct ngx_lua_sema_t;
struct nghttp2_asio_ctx;

struct nghttp2_asio_client : std::enable_shared_from_this<nghttp2_asio_client> {

    nghttp2_asio_client(session &&session) : session(std::move(session)) {

    }

    enum class status : uint8_t {
        none,
        init,
        ready,
    };
#if ENABLE_HTTPS
    std::optional<boost::asio::ssl::context> tls_ctx;
#endif
    status status = status::none;
    session session;
    std::string uri;
    std::string scheme, host, service;
    ngx_lua_sema_t *ngx_connection_event;
    boost::system::error_code ec;
    ngx_lua_ffi_sema_post post_event_cb;
    nghttp2_asio_ctx *ctx;

    ~nghttp2_asio_client() {
        if (is_ready()) {
            session.shutdown();
        }
    }

    bool is_ready() {
        return status == status::ready;
    }

    void post_event(ngx_lua_sema_t *event) {
        post_event_cb(event, 1);
    }

    void post_connection_event() {
        if (ngx_connection_event)
            post_event_cb(ngx_connection_event, 1);
    }
};


struct nghttp2_asio_ctx {
    boost::asio::io_service io_service;
    boost::system::error_code ec;
    ngx_lua_ffi_sema_post post_event_cb = nullptr;
    std::list<std::shared_ptr<nghttp2_asio_client>> clients;
};

struct nghttp2_asio_submit {
    uint32_t error_code;

    std::string method, uri;
    priority_spec spec;
    header_map headers;
    std::optional<std::variant<std::string, generator_cb>> data;

    int status_code = 0;
    int64_t content_length = 0;
    std::vector<std::string> response_data;

    void *user_data;
    const request *req;
    std::shared_ptr<nghttp2_asio_client> client;
};

#define TRY \
    try     \
    {
#define DEFAULT_CATCH                                   \
    }                                                   \
    catch (std::exception & e)                          \
    {                                                   \
        std::cerr << "exception: " << e.what() << "\n"; \
    }


extern "C"
{
BOOST_SYMBOL_EXPORT nghttp2_asio_ctx *nghttp2_asio_init_ctx(ngx_lua_ffi_sema_post ptr) {
    if (!ptr)
        return nullptr;
    TRY
        auto ctx = new(std::nothrow) nghttp2_asio_ctx{
                .post_event_cb = ptr};
        return ctx;
    DEFAULT_CATCH
    return nullptr;
}

BOOST_SYMBOL_EXPORT void nghttp2_asio_release_ctx(nghttp2_asio_ctx *ctx) {
    if (!ctx) {
        return;
    }
    TRY
        ctx->io_service.stop();
        delete ctx;
    DEFAULT_CATCH
}

BOOST_SYMBOL_EXPORT int64_t nghttp2_asio_run_once(nghttp2_asio_ctx *ctx) {
    if (!ctx)
        return -1;
    TRY
        ctx->io_service.restart();
        return (int64_t) ctx->io_service.poll_one(ctx->ec);
    DEFAULT_CATCH
    return 0;
}

BOOST_SYMBOL_EXPORT int64_t nghttp2_asio_run(nghttp2_asio_ctx *ctx) {
    if (!ctx)
        return -1;
    TRY
        ctx->io_service.restart();
        return (int64_t) ctx->io_service.poll(ctx->ec);
    DEFAULT_CATCH
    return 0;
}

BOOST_SYMBOL_EXPORT int nghttp2_asio_error(nghttp2_asio_ctx *ctx, char *u_err, size_t errlen) {
    if (!ctx || ctx->io_service.stopped())
        return -1;
    if (ctx->ec) {
        auto ec = std::move(ctx->ec);
        return ec.message(u_err, errlen) != nullptr ? 0 : -1;
    }
    return 1;
}

BOOST_SYMBOL_EXPORT nghttp2_asio_client *
nghttp2_asio_client_new(nghttp2_asio_ctx *ctx, const char *c_uri, double read_timeout,
                        double connection_timeout, ngx_lua_sema_t *event) {
    TRY
        if (!ctx) return nullptr;

        boost::system::error_code &ec = ctx->ec;

        std::string uri(c_uri);
        std::string scheme, host, service;

        if (::host_service_from_uri(ec, scheme, host, service, uri)) {
            return nullptr;
        }
        std::shared_ptr<nghttp2_asio_client> client;
        if (scheme == "https") {
#if ENABLE_HTTPS
            boost::asio::ssl::context tls_ctx(boost::asio::ssl::context::sslv23);
            tls_ctx.set_default_verify_paths();
            // disabled to make development easier...
            // tls_ctx.set_verify_mode(boost::asio::ssl::verify_peer);
            configure_tls_context(ec, tls_ctx);

            client = std::shared_ptr<nghttp2_asio_client>(
                    new nghttp2_asio_client(session(ctx->io_service, tls_ctx, host, service,
                                                    boost::posix_time::milliseconds(
                                                            size_t(connection_timeout * 1000)))));
            client->tls_ctx = std::move(tls_ctx);
            client->uri = std::move(uri);
            client->scheme = std::move(scheme);
            client->host = std::move(host);
            client->service = std::move(service);
            client->post_event_cb = ctx->post_event_cb;
            client->ctx = ctx;
#else
            return nullptr;
#endif
        } else {
            client = std::shared_ptr<nghttp2_asio_client>(
                    new nghttp2_asio_client(session(ctx->io_service, host, service,
                                                    boost::posix_time::milliseconds(
                                                            size_t(connection_timeout * 1000)))));

            client->uri = std::move(uri);
            client->scheme = std::move(scheme);
            client->host = std::move(host);
            client->service = std::move(service);
            client->ngx_connection_event = event;
            client->post_event_cb = ctx->post_event_cb;
            client->ctx = ctx;
        }
        client->status = nghttp2_asio_client::status::init;
        auto &sess = client->session;
        sess.read_timeout(boost::posix_time::milliseconds(size_t(read_timeout * 1000)));
        sess.on_connect([client](auto &&d) {
            client->status = nghttp2_asio_client::status::ready;
            client->post_connection_event();
        });

        sess.on_error([client](const boost::system::error_code &ec) {
            client->ec = ec;
            client->post_connection_event();
        });

        auto ptr = client.get();
        ctx->clients.push_back(std::move(client));
        return ptr;

    DEFAULT_CATCH
    return nullptr;
}

BOOST_SYMBOL_EXPORT void nghttp2_asio_client_delete(nghttp2_asio_client *client) {
    auto ctx = client->ctx;
    // unlink
    client->session.on_connect(nullptr);
    client->session.on_error(nullptr);
    if (client->is_ready())
        client->session.shutdown();
    auto iter = std::find_if(ctx->clients.cbegin(), ctx->clients.cend(), [client](auto ptr) {
        return ptr.get() == client;
    });
    if (iter != ctx->clients.end()) {
        ctx->clients.erase(iter);
    }
}

BOOST_SYMBOL_EXPORT int nghttp2_asio_client_error(nghttp2_asio_client *client, char *u_err, size_t errlen) {
    if (!client)
        return -1;
    if (client->ec) {
        auto ec = std::move(client->ec);
        return ec.message(u_err, errlen) != nullptr ? 0 : -1;
    }
    return 1;
}

BOOST_SYMBOL_EXPORT bool nghttp2_asio_client_is_ready(nghttp2_asio_client *client) {
    return client && client->is_ready();
}

BOOST_SYMBOL_EXPORT nghttp2_asio_submit *
nghttp2_asio_submit_new(nghttp2_asio_client *client, const char *_method, const char *_uri, const char *data,
                        void *user_data) {
    if (!nghttp2_asio_client_is_ready(client) || !_method || !_uri)
        return nullptr;

    TRY
        auto req = new(std::nothrow) nghttp2_asio_submit{
                .method = _method,
                .uri = _uri,
                .user_data = user_data,
                .client = client->shared_from_this(),
        };
        if (data) {
            req->data.emplace(data);
        }
        return req;
    DEFAULT_CATCH
    return nullptr;
}

BOOST_SYMBOL_EXPORT void nghttp2_asio_submit_delete(nghttp2_asio_submit *submit) {
    if (submit) {
        if (submit->req) {
            submit->req->on_response(nullptr);
            submit->req->on_close(nullptr);
            submit->req->cancel(NGHTTP2_NO_ERROR);
        }
        delete submit;
    }
}

BOOST_SYMBOL_EXPORT int
nghttp2_asio_request_push_headers(nghttp2_asio_submit *req, const char *key, const char *value,
                                  bool sensitive) {
    if (!req || !key) {
        return -1;
    }
    TRY
        if (!value)
            value = "";
        req->headers.emplace(key, header_value{value, sensitive});
        return 0;
    DEFAULT_CATCH
    return -1;
}

BOOST_SYMBOL_EXPORT int
nghttp2_asio_request_set_body_iter(nghttp2_asio_submit *submitCtx, submit_request_data_cb cb) {
    if (!submitCtx) {
        return -1;
    }
    TRY
        submitCtx->data.emplace(cb);
        return 0;
    DEFAULT_CATCH
    return -1;
}

BOOST_SYMBOL_EXPORT int
nghttp2_asio_request_set_body(nghttp2_asio_submit *submitCtx, const char *data, size_t len) {
    if (!submitCtx) {
        return -1;
    }
    TRY
        submitCtx->data.emplace(std::string(data, len));
        return 0;
    DEFAULT_CATCH
    return -1;
}

BOOST_SYMBOL_EXPORT int
nghttp2_asio_client_submit(nghttp2_asio_client *client, nghttp2_asio_submit *submitCtx, bool need_headers,
                           ngx_lua_sema_t *sem) {
    if (!nghttp2_asio_client_is_ready(client) || !submitCtx)
        return -1;

    TRY
        auto &ec = client->ec;


        const request *req;

        if (!submitCtx->data.has_value())
            req = client->session.submit(ec, submitCtx->method, submitCtx->uri, submitCtx->headers,
                                         submitCtx->spec);
        else {

            req = std::visit([&](auto &&arg) -> const request * {
                                 return client->session.submit(ec, submitCtx->method, submitCtx->uri, arg, submitCtx->headers,
                                                               submitCtx->spec);
                             },
                             submitCtx->data.value());
        }
        if (!req) {
            return -1;
        }

        req->on_response([submitCtx, need_headers](const response &response) {
            submitCtx->status_code = response.status_code();
            submitCtx->content_length = response.content_length();
            if (need_headers) {
                submitCtx->headers = response.header();
            }
            response.on_data([submitCtx](const uint8_t *data, std::size_t len) {
                if (data) {
                    static_assert(sizeof(uint8_t) == sizeof(char));
                    submitCtx->response_data.emplace_back((const char *) data, len);
                }
            });
        });
        req->on_close([sem, submitCtx](uint32_t error_code) {
            submitCtx->req = nullptr;
            submitCtx->error_code = error_code;
            if (submitCtx->client)
                submitCtx->client->post_event(sem);
        });

        submitCtx->req = req;

        return 0;
    DEFAULT_CATCH
    return -1;
}

BOOST_SYMBOL_EXPORT int64_t nghttp2_asio_submit_error(nghttp2_asio_submit *submitCtx) {
    if (!submitCtx)
        return -1;
    if (submitCtx->error_code) {
        return submitCtx->error_code;
    }
    return -1;
}

BOOST_SYMBOL_EXPORT int
nghttp2_asio_response_code(nghttp2_asio_submit *submitCtx) {
    return submitCtx->status_code;
}

BOOST_SYMBOL_EXPORT size_t nghttp2_asio_response_header_length(nghttp2_asio_submit *submitCtx) {
    return submitCtx->headers.size();
}

BOOST_SYMBOL_EXPORT int64_t nghttp2_asio_response_content_length(nghttp2_asio_submit *submitCtx) {
    return submitCtx->content_length;
}

BOOST_SYMBOL_EXPORT size_t nghttp2_asio_response_body_length(nghttp2_asio_submit *submitCtx) {
    return submitCtx->response_data.size();
}

BOOST_SYMBOL_EXPORT int64_t
nghttp2_asio_response_content(nghttp2_asio_submit *submitCtx, char *output, int64_t len) {
    TRY
        if (len <= 0) return 0;
        auto origin_len = len;
        for (auto &body: submitCtx->response_data) {
            auto cpy_len = std::min(len, (int64_t) body.size());
            memcpy(output, body.c_str(), cpy_len);
            output = output + cpy_len;
            len -= cpy_len;
            if (len <= 0)
                break;
        }
        return origin_len - len;
    DEFAULT_CATCH
    return 0;
}

BOOST_SYMBOL_EXPORT const char *nghttp2_asio_response_body(nghttp2_asio_submit *submitCtx, int index) {
    if (index >= submitCtx->response_data.size())
        return nullptr;
    return submitCtx->response_data[index].c_str();
}

BOOST_SYMBOL_EXPORT int
nghttp2_asio_response_headers(nghttp2_asio_submit *submitCtx, const char **headers_key,
                              const char **headers_value, size_t len) {
    TRY
        len = std::min(len, submitCtx->headers.size());
        auto iter = submitCtx->headers.cbegin();
        for (size_t i = 0; i < len; ++i, iter++) {
            headers_key[i] = iter->first.c_str();
            headers_value[i] = iter->second.value.c_str();
        }
        return len;
    DEFAULT_CATCH
    return -1;
}
}