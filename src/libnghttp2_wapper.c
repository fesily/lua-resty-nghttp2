#include <nghttp2/nghttp2.h>
typedef struct nghttp2_Ctx
{
    nghttp2_session *session;
    nghttp2_Stream* streams;
} nghttp2_Ctx;
typedef struct nghttp2_Stream
{
    int id;
} nghttp2_Stream;
int on_begin_headers_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, void *user_data)
{
    if (frame->hd.type != NGHTTP2_PUSH_PROMISE)
    {
        return 0;
    }

    //  auto sess = static_cast<session_impl *>(user_data);
    // sess->create_push_stream(frame->push_promise.promised_stream_id);

    return 0;
}
int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen, uint8_t flags,
                       void *user_data)
{
    auto sess = static_cast<session_impl *>(user_data);
    stream *strm;

    switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:
    {
        strm = sess->find_stream(frame->hd.stream_id);
        if (!strm)
        {
            return 0;
        }

        // ignore trailers
        if (frame->headers.cat == NGHTTP2_HCAT_HEADERS &&
            !strm->expect_final_response())
        {
            return 0;
        }

        auto token = http2::lookup_token(name, namelen);

        auto &res = strm->response().impl();
        if (token == http2::HD__STATUS)
        {
            res.status_code(util::parse_uint(value, valuelen));
        }
        else
        {
            if (res.header_buffer_size() + namelen + valuelen > 64_k)
            {
                nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                          frame->hd.stream_id, NGHTTP2_INTERNAL_ERROR);
                break;
            }
            res.update_header_buffer_size(namelen + valuelen);

            if (token == http2::HD_CONTENT_LENGTH)
            {
                res.content_length(util::parse_uint(value, valuelen));
            }

            res.header().emplace(
                std::string(name, name + namelen),
                header_value{std::string(value, value + valuelen),
                             (flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0});
        }
        break;
    }
    case NGHTTP2_PUSH_PROMISE:
    {
        strm = sess->find_stream(frame->push_promise.promised_stream_id);
        if (!strm)
        {
            return 0;
        }

        auto &req = strm->request().impl();
        auto &uri = req.uri();

        switch (http2::lookup_token(name, namelen))
        {
        case http2::HD__METHOD:
            req.method(std::string(value, value + valuelen));
            break;
        case http2::HD__SCHEME:
            uri.scheme.assign(value, value + valuelen);
            break;
        case http2::HD__PATH:
            split_path(uri, value, value + valuelen);
            break;
        case http2::HD__AUTHORITY:
            uri.host.assign(value, value + valuelen);
            break;
        case http2::HD_HOST:
            if (uri.host.empty())
            {
                uri.host.assign(value, value + valuelen);
            }
        // fall through
        default:
            if (req.header_buffer_size() + namelen + valuelen > 64_k)
            {
                nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                          frame->hd.stream_id, NGHTTP2_INTERNAL_ERROR);
                break;
            }
            req.update_header_buffer_size(namelen + valuelen);

            req.header().emplace(
                std::string(name, name + namelen),
                header_value{std::string(value, value + valuelen),
                             (flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0});
        }

        break;
    }
    default:
        return 0;
    }

    return 0;
}
int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame,
                           void *user_data)
{
    auto sess = static_cast<session_impl *>(user_data);
    auto strm = sess->find_stream(frame->hd.stream_id);

    switch (frame->hd.type)
    {
    case NGHTTP2_DATA:
    {
        if (!strm)
        {
            return 0;
        }
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
            strm->response().impl().call_on_data(nullptr, 0);
        }
        break;
    }
    case NGHTTP2_HEADERS:
    {
        if (!strm)
        {
            return 0;
        }

        // ignore trailers
        if (frame->headers.cat == NGHTTP2_HCAT_HEADERS &&
            !strm->expect_final_response())
        {
            return 0;
        }

        if (strm->expect_final_response())
        {
            // wait for final response
            return 0;
        }

        auto &req = strm->request().impl();
        req.call_on_response(strm->response());
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
            strm->response().impl().call_on_data(nullptr, 0);
        }
        break;
    }
    case NGHTTP2_PUSH_PROMISE:
    {
        if (!strm)
        {
            return 0;
        }

        auto push_strm = sess->find_stream(frame->push_promise.promised_stream_id);
        if (!push_strm)
        {
            return 0;
        }

        strm->request().impl().call_on_push(push_strm->request());

        break;
    }
    }
    return 0;
}
int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id, const uint8_t *data,
                                size_t len, void *user_data)
{
    auto sess = static_cast<session_impl *>(user_data);
    auto strm = sess->find_stream(stream_id);
    if (!strm)
    {
        return 0;
    }

    auto &res = strm->response().impl();
    res.call_on_data(data, len);

    return 0;
}
int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code, void *user_data)
{
    auto sess = static_cast<session_impl *>(user_data);
    auto strm = sess->pop_stream(stream_id);
    if (!strm)
    {
        return 0;
    }

    strm->request().impl().call_on_close(error_code);

    return 0;
}


int setup_session(nghttp2_Ctx *ctx)
{
    if (!ctx)
        return NGHTTP2_ERR_INVALID_ARGUMENT;

    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_on_begin_headers_callback(
        callbacks, on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                     on_header_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                         on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, on_stream_close_callback);

    int rv = nghttp2_session_client_new(&ctx->session, callbacks, ctx);
    if (rv != 0)
    {
        nghttp2_session_callbacks_del(callbacks);
        return rv;
    }

    const uint32_t window_size = 256 * 1024 * 1024;

    nghttp2_settings_entry iv[] = {
        {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
         // typically client is just a *sink* and just process data as
         // much as possible.  Use large window size by default.
         {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, window_size}}};
    nghttp2_submit_settings(ctx->session, NGHTTP2_FLAG_NONE, iv, sizeof(iv) / sizeof(nghttp2_settings_entry));
    // increase connection window size up to window_size
    nghttp2_session_set_local_window_size(ctx->session, NGHTTP2_FLAG_NONE, 0,
                                          window_size);
    nghttp2_session_callbacks_del(callbacks);
    return 0;
}