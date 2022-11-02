//
// Created by fesil on 2022/10/31.
//

#ifndef RESTY_NGHTTP2_RESTY_NGHTTP2_H
#define RESTY_NGHTTP2_RESTY_NGHTTP2_H

#include <stddef.h>

extern "C" {
struct ngx_lua_sema_t;
typedef int (*ngx_lua_ffi_sema_post)(ngx_lua_sema_t *, int);
typedef ssize_t (*submit_request_data_cb)(uint8_t *buf, size_t len,
                                          uint32_t *data_flags);

struct nghttp2_asio_ctx;
struct nghttp2_asio_client;
struct nghttp2_asio_submit;

nghttp2_asio_ctx *nghttp2_asio_init_ctx(ngx_lua_ffi_sema_post ptr);
void nghttp2_asio_release_ctx(nghttp2_asio_ctx *ctx);
int64_t nghttp2_asio_run_once(nghttp2_asio_ctx *ctx);
int64_t nghttp2_asio_run(nghttp2_asio_ctx *ctx);
int nghttp2_asio_error(nghttp2_asio_ctx *ctx, char *u_err, size_t errlen);

nghttp2_asio_client* nghttp2_asio_client_new(nghttp2_asio_ctx *ctx, const char *c_uri, double read_timeout,
                                             double connection_timeout, ngx_lua_sema_t* event);
void nghttp2_asio_client_delete(nghttp2_asio_client* client);
int nghttp2_asio_client_error(nghttp2_asio_client *client, char *u_err, size_t errlen);
bool nghttp2_asio_client_is_ready(nghttp2_asio_client *client);
int
nghttp2_asio_client_submit(nghttp2_asio_client *client, nghttp2_asio_submit *submitCtx, bool need_headers,
                           ngx_lua_sema_t *sem);
nghttp2_asio_submit *
nghttp2_asio_submit_new(nghttp2_asio_client *client, const char *_method, const char *_uri, const char *data,
                        void *user_data);
void nghttp2_asio_submit_delete(nghttp2_asio_submit* submit);
int
nghttp2_asio_submit_error(nghttp2_asio_submit *submitCtx, char *u_err, size_t errlen);

int
nghttp2_asio_request_push_headers(nghttp2_asio_submit *req, const char *key, const char *value,
                                  bool sensitive);
int
nghttp2_asio_request_set_body_iter(nghttp2_asio_submit *submitCtx, submit_request_data_cb cb);
int
nghttp2_asio_request_set_body(nghttp2_asio_submit *submitCtx, const char *data, size_t len);

int nghttp2_asio_response_code(nghttp2_asio_submit *submitCtx);
size_t nghttp2_asio_response_header_length(nghttp2_asio_submit *submitCtx);
int64_t
nghttp2_asio_response_content_length(nghttp2_asio_submit *submitCtx);
size_t nghttp2_asio_response_body_length(nghttp2_asio_submit *submitCtx);

int64_t
nghttp2_asio_response_content(nghttp2_asio_submit *submitCtx, char *output, int64_t len);

const char *
nghttp2_asio_response_body(nghttp2_asio_submit *submitCtx, int index);

int
nghttp2_asio_response_headers(nghttp2_asio_submit *submitCtx, const char **headers_key,
                              const char **headers_value, size_t len);
};

#endif //RESTY_NGHTTP2_RESTY_NGHTTP2_H
