//
// Created by fesil on 2022/11/1.
//
#include <catch.hpp>
#include <resty_nghttp2.h>
#include <future>
#include <iostream>

struct ngx_lua_sema_t {
    const char *msg;
    std::promise<void> promise;
};

int cb(ngx_lua_sema_t *t, int n) {
    std::cout << "event:" << t->msg << std::endl;
    t->promise.set_value();
    return 0;
}

TEST_CASE("echo server") {
    auto ctx = nghttp2_asio_init_ctx(cb);
    REQUIRE(ctx != nullptr);

    ngx_lua_sema_t conn_event{
            "connection"
    };
    auto client = nghttp2_asio_client_new(ctx, "http://localhost:8002", 10, 10,
                                          &conn_event);
    REQUIRE(client != nullptr);
    bool stop = false;
    std::thread thread([&]() {
        while (!stop) {
            auto size = nghttp2_asio_run(ctx);
            if (size == -1) {
                break;
            }
            using namespace std::chrono_literals;
            std::this_thread::sleep_for(10ms);
        }
    });
    conn_event.promise.get_future().get();
    if (!nghttp2_asio_client_is_ready(client)) {
        char msg[2048];
        REQUIRE(nghttp2_asio_client_error(client, msg, 2048) == -1);
    }

    ngx_lua_sema_t respone_event{
            "submit response"
    };
    auto submit = nghttp2_asio_submit_new(client, "GET", "http://localhost", nullptr, nullptr);
    REQUIRE(submit != nullptr);

    nghttp2_asio_client_submit(client, submit, true, &respone_event);
    respone_event.promise.get_future().get();
    REQUIRE(nghttp2_asio_response_code(submit) == 200);
    auto body_length = nghttp2_asio_response_body_length(submit);
    REQUIRE(body_length == 1);

    auto content_length = nghttp2_asio_response_content_length(submit);
    REQUIRE(content_length == 388);
    char msg[1024];
    char msg1[1024];
    auto len = nghttp2_asio_response_content(submit, msg, 1024);
    REQUIRE(len == 388);
    REQUIRE(std::string_view(nghttp2_asio_response_body(submit, 0)) == std::string_view(msg, len));

    stop = true;
    thread.join();

    nghttp2_asio_submit_delete(submit);
    nghttp2_asio_client_delete(client);
    nghttp2_asio_release_ctx(ctx);
}