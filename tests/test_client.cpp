//
// Created by fesil on 2022/11/1.
//
#include <catch.hpp>
#include <resty_nghttp2.h>
#include <future>
#include <iostream>

struct ngx_lua_sema_t {
    virtual void poll() = 0;

    virtual  ~ngx_lua_sema_t() {}
};

struct ngx_lua_sema_msg : ngx_lua_sema_t {
    const char *msg;

    void poll() override {
        if (msg)
            std::cout << "event:" << msg << std::endl;
    }
};

struct ngx_lua_sema_cb : ngx_lua_sema_t {
    std::function<void(void)> cb;

    void poll() override {
        if (cb)
            cb();
    }
};

struct ngx_lua_sema_merge : ngx_lua_sema_t {
    std::vector<ngx_lua_sema_t> sems;

    void poll() override {
        for (auto &sem: sems)
            sem.poll();
    }
};


int cb(ngx_lua_sema_t *t, int n) {

    t->poll();
    return 0;
}

TEST_CASE("echo server") {
    auto stop = false;
    auto ctx = nghttp2_asio_init_ctx(cb);
    REQUIRE(ctx != nullptr);

    ngx_lua_sema_cb conn_event;
    auto client = nghttp2_asio_client_new(ctx, "http://localhost:8002", 10, 10,
                                          &conn_event);
    REQUIRE(client != nullptr);
    ngx_lua_sema_cb respone_event;
    conn_event.cb = [&]() {
        if (!nghttp2_asio_client_is_ready(client)) {
            char msg[2048];
            REQUIRE(nghttp2_asio_client_error(client, msg, 2048) == -1);
        }

        auto submit = nghttp2_asio_submit_new(client, "GET", "http://localhost", nullptr, nullptr);
        REQUIRE(submit != nullptr);

        nghttp2_asio_client_submit(client, submit, true, &respone_event);
        respone_event.cb = [=, &stop]() {
            REQUIRE(nghttp2_asio_response_code(submit) == 200);
            auto body_length = nghttp2_asio_response_body_length(submit);
            REQUIRE(body_length == 1);

            auto content_length = nghttp2_asio_response_content_length(submit);
            REQUIRE(content_length == 388);
            char msg[1024];
            auto len = nghttp2_asio_response_content(submit, msg, 1024);
            REQUIRE(len == 388);
            REQUIRE(std::string_view(nghttp2_asio_response_body(submit, 0)) == std::string_view(msg, len));


            stop = true;
            nghttp2_asio_submit_delete(submit);
        };
    };
    while (!stop)
        nghttp2_asio_run(ctx);
    nghttp2_asio_client_delete(client);
    nghttp2_asio_release_ctx(ctx);
}

TEST_CASE("before connection delete") {
    auto ctx = nghttp2_asio_init_ctx(cb);
    REQUIRE(ctx != nullptr);
    ngx_lua_sema_cb conn_event;
    auto client = nghttp2_asio_client_new(ctx, "http://localhost:8002", 10, 10,
                                          &conn_event);
    REQUIRE(client != nullptr);
    nghttp2_asio_client_delete(client);
    nghttp2_asio_release_ctx(ctx);
}

TEST_CASE("after connection delete") {
    auto stop = false;
    auto ctx = nghttp2_asio_init_ctx(cb);
    REQUIRE(ctx != nullptr);
    ngx_lua_sema_cb conn_event;
    auto client = nghttp2_asio_client_new(ctx, "http://localhost:8002", 10, 10,
                                          &conn_event);
    REQUIRE(client != nullptr);
    conn_event.cb = [&] {
        stop = true;
    };
    while (!stop)
        nghttp2_asio_run(ctx);
    nghttp2_asio_client_delete(client);
    nghttp2_asio_release_ctx(ctx);
}

TEST_CASE("first delete ctx") {
    auto stop = false;
    auto ctx = nghttp2_asio_init_ctx(cb);
    REQUIRE(ctx != nullptr);
    ngx_lua_sema_cb conn_event;
    auto client = nghttp2_asio_client_new(ctx, "http://localhost:8002", 10, 10,
                                          &conn_event);
    REQUIRE(client != nullptr);
    conn_event.cb = [&] {
        stop = true;
    };
    while (!stop)
        nghttp2_asio_run(ctx);
    nghttp2_asio_release_ctx(ctx);
    nghttp2_asio_client_delete(client);
}

TEST_CASE("memory") {
    auto stop = false;
    auto ctx = nghttp2_asio_init_ctx(cb);
    REQUIRE(ctx != nullptr);
    ngx_lua_sema_cb conn_event;
    auto client = nghttp2_asio_client_new(ctx, "http://localhost:8002", 10, 10,
                                          &conn_event);
    REQUIRE(client != nullptr);
    nghttp2_asio_submit *submit;
    ngx_lua_sema_msg respone_event;
    respone_event.msg = "123";
    conn_event.cb = [&] {
        submit = nghttp2_asio_submit_new(client, "GET", "http://localhost", nullptr, nullptr);
        REQUIRE(submit != nullptr);

        nghttp2_asio_client_submit(client, submit, true, &respone_event);

        nghttp2_asio_client_delete(client);
        stop = true;
    };
    while (!stop)
        nghttp2_asio_run(ctx);
    nghttp2_asio_submit_delete(submit);
    nghttp2_asio_release_ctx(ctx);
}
