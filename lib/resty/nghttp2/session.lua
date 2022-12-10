local lib = require('resty.nghttp2.libnghttp2')
local libresty_nghttp2 = require 'resty.nghttp2.libresty_nghttp2'
local ffi = require('ffi')
local bit = require 'bit'
local tab_nkeys = require 'table.nkeys'
local create_options = require('resty.nghttp2.options')
local create_stream = require('resty.nghttp2.stream')
local semaphore = require 'ngx.semaphore'
local http2 = require 'resty.nghttp2.http2'
local ffi_cast = ffi.cast
local ffi_string = ffi.string
local uint16_t = ffi.typeof("uint16_t")
local ptr_t = ffi.typeof("void*")
local unescape_uri = ngx.unescape_uri
local band = bit.band
local logger = require 'resty.nghttp2.logger'

---@class nghttp2.session
local _M = {}
local _mt = {
    __index = _M
}
---@type table<number, nghttp2.session>
local session_registry = setmetatable({}, { __mode = "kv" })

local function user_data_key(user_data)
    return tonumber(ffi_cast(uint16_t, user_data))
end

local void_ptr_t = ffi.typeof "void*"
--- int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
function libresty_nghttp2.on_data_chunk_recv(session, flags, stream_id, data, user_data)
    user_data = ffi_cast(void_ptr_t, user_data)
    logger.debug("nghttp2_on_data_chunk_recv_callback")
    session = session_registry[user_data_key(user_data)]
    if not session then
        return lib.NGHTTP2_ERR_CALLBACK_FAILURE
    end
    return session:on_data_chunk_recv(flags, stream_id, data)
end

function libresty_nghttp2.on_stream_close(session, stream_id, error_code, user_data)
    user_data = ffi_cast(void_ptr_t, user_data)
    logger.debug("nghttp2_on_stream_close_callback")
    session = session_registry[user_data_key(user_data)]
    if not session then
        return lib.NGHTTP2_ERR_CALLBACK_FAILURE
    end
    return session:on_stream_close(stream_id, error_code)
end

local const_nghttp2_frame_ptr_t = ffi.typeof "const nghttp2_frame*"
function libresty_nghttp2.on_begin_headers(session, frame, user_data)
    frame = ffi_cast(const_nghttp2_frame_ptr_t, frame)
    user_data = ffi_cast(void_ptr_t, user_data)

    logger.debug("nghttp2_on_begin_headers_callback")
    session = session_registry[user_data_key(user_data)]
    if not session then
        return lib.NGHTTP2_ERR_CALLBACK_FAILURE
    end
    return session:on_begin_headers(frame)
end

function libresty_nghttp2.on_frame_recv(session, frame, user_data)
    frame = ffi_cast(const_nghttp2_frame_ptr_t, frame)
    user_data = ffi_cast(void_ptr_t, user_data)

    logger.debug("nghttp2_on_frame_recv_callback")
    session = session_registry[user_data_key(user_data)]
    if not session then
        return lib.NGHTTP2_ERR_CALLBACK_FAILURE
    end
    return session:on_frame_recv(frame)
end

function libresty_nghttp2.on_header(session, frame, name, value, flags, user_data)
    frame = ffi_cast(const_nghttp2_frame_ptr_t, frame)
    user_data = ffi_cast(void_ptr_t, user_data)

    logger.debug("nghttp2_on_header_callback")
    session = session_registry[user_data_key(user_data)]
    if not session then
        return lib.NGHTTP2_ERR_CALLBACK_FAILURE
    end
    return session:on_header(frame, name, value, flags)
end

-- Make a C callbacks structure using the functions in a table.
-- Will fail if a callback is defined but is not a function.
-- Ignores keys that are not callbacks.
local nghttp2_session_callbacks = ffi.new "nghttp2_session_callbacks*[1]"
local function create_callbacks()
    local error_code = lib.nghttp2_session_callbacks_new(nghttp2_session_callbacks)
    if error_code ~= 0 then
        return nil, lib.nghttp2_strerror(error_code)
    end
    local cb = nghttp2_session_callbacks[0]
    ffi.gc(cb, lib.nghttp2_session_callbacks_del)
    libresty_nghttp2.init_callbacks(cb)
    return cb
end

local nghttp2_session = ffi.new "nghttp2_session*[1]"
local user_data_count = 0

local window_size = 256 * 1024 * 1024
local default_submit_settings
local default_submit_settings_size = 2
do
    default_submit_settings = ffi.new("nghttp2_settings_entry[2]", {
        { lib.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
        { lib.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, window_size }
    })
end

function _M:handle_ping()
    if (self.stopped or tab_nkeys(self.streams) ~= 0) then return end

    lib.nghttp2_submit_ping(self.session, lib.NGHTTP2_FLAG_NONE, nil)

    self:signal_write();
end

function _M.new(opt)
    local options, err
    if opt then
        options, err = create_options(opt)
        if not options then
            return nil, err
        end
    end

    local cb, err = create_callbacks()
    if not cb then
        return nil, err
    end
    local rv
    if options then
        rv = lib.nghttp2_session_client_new2(nghttp2_session, cb, ffi_cast(ptr_t, user_data_count), options)
    else
        rv = lib.nghttp2_session_client_new(nghttp2_session, cb, ffi_cast(ptr_t, user_data_count))
    end
    if rv ~= 0 then
        return nil, lib.nghttp2_strerror(rv)
    end
    local session = nghttp2_session[0]
    ffi.gc(session, lib.nghttp2_session_del)
    ---@class nghttp2.session
    local sess = setmetatable({
        session = session,
        ---@type nghttp2.stream[]
        streams = {},
        stopped = false,
        tcpsock = ngx.socket.tcp(),
        write_sem = semaphore.new(),
        on_error = opt.on_error,
        native_id = user_data_count,
        uri = opt.uri,
        host = opt.host,
        releaser = nil,
    }, _mt)
    local releaser = newproxy(true)
    getmetatable(releaser).__gc = function()
        for i, stream in pairs(sess.streams) do
            stream.request:call_on_close("session closed")
        end
    end
    sess.releaser = releaser

    session_registry[user_data_count] = sess
    user_data_count = user_data_count + 1
    if user_data_count > 65535 then
        user_data_count = 0
    end
    lib.nghttp2_session_set_local_window_size(session, lib.NGHTTP2_FLAG_NONE, 0, window_size)
    lib.nghttp2_submit_settings(session, lib.NGHTTP2_FLAG_NONE, default_submit_settings,
        default_submit_settings_size)

    return sess
end

function _M:create_stream(stream_id)
    local strm = create_stream(stream_id, self);
    self.streams[stream_id] = strm
    self:stop_ping()
    return strm
end

function _M:find_stream(stream_id)
    return self.streams[stream_id]
end

function _M:pop_stream(stream_id)
    logger.debug("pop_stream:", stream_id)
    local strm = self.streams[stream_id]
    self.streams[stream_id] = nil
    if tab_nkeys(self.streams) == 0 then
        logger.debug("no streams")
        self:start_ping()
    end
    return strm
end

local ping_timer_master

---@param self nghttp2.session
local function stop(self)
    if (self.stopped) then
        return
    end
    self.stopped = true
    if ping_timer_master then
        ping_timer_master[self] = nil
    end
    self.tcpsock:close()
end

local function handle_all_ping(p)
    if p then
        for k, v in pairs(ping_timer_master) do
            logger.debug("close all streams when exiting")
            ---@cast k nghttp2.session
            k:shutdown()
        end
        ping_timer_master = nil
    else
        for k, v in pairs(ping_timer_master) do
            if v then
                ---@cast k nghttp2.session
                k:handle_ping()
            end
        end
    end
end

function _M:start_ping()
    if not ping_timer_master then
        local ok, err = ngx.timer.every(3, handle_all_ping)
        if not ok then
            logger.error("create timer failed:", err)
            return
        end
        ping_timer_master = setmetatable({}, { __mode = "kv" })
    end
    ping_timer_master[self] = true
end

function _M:stop_ping()
    ping_timer_master[self] = false
end

---@param dst nghttp2.uri_ref
---@param value string
local function split_path(dst, value, first, last)
    local path_last = value:find("?", 1, true)
    local query_first;
    if (not path_last) then
        query_first = last
        path_last = last
    else
        path_last = first + (path_last - 1)
        query_first = path_last + 1
    end

    local raw_path = ffi_string(first, path_last - first);
    dst.path = unescape_uri(raw_path);
    dst.raw_path = raw_path;
    dst.raw_query = ffi.string(query_first, last - query_first);
end

function _M:on_begin_headers(frame)
    if frame.hd.type ~= lib.NGHTTP2_PUSH_PROMISE then
        return 0
    end
    local stream_id = frame.push_promise.promised_stream_id
    logger.debug("create push stream: ", stream_id)
    self:create_stream(stream_id)
    return 0
end

local const_char_ptr_t = ffi.typeof "const char*"
function _M:on_header(frame, name, value, flags)
    local t = frame.hd.type
    if t == lib.NGHTTP2_HEADERS then
        local strm = self:find_stream(frame.hd.stream_id)
        if not strm then
            return 0
        end
        if frame.headers.cat == lib.NGHTTP2_HCAT_HEADERS and not strm:expect_final_response() then
            return 0
        end
        -- no read headers
        if not strm.response.headers then
            return 0
        end
        local namelen = #name
        local valuelen = #value
        local token = http2.lookup_token(name, namelen);

        local res = strm.response
        if token == http2.HD__STATUS then
            res.status_code = tonumber(value);
        else
            if res.header_buffer_size + namelen + valuelen > 64 * 1024 then
                lib.nghttp2_submit_rst_stream(self.session, lib.NGHTTP2_FLAG_NONE,
                    frame.hd.stream_id, lib.NGHTTP2_INTERNAL_ERROR);
                return 0
            end
            res:update_header_buffer_size(namelen + valuelen);

            if token == http2.HD_CONTENT_LENGTH then
                res.content_length = tonumber(value)
            end

            res.headers[ffi_string(name, namelen)] = { value = value,
                sensitive = band(flags, lib.NGHTTP2_NV_FLAG_NO_INDEX) ~= 0 }
        end
    else if t == lib.NGHTTP2_PUSH_PROMISE then
            local strm = self:find_stream(frame.push_promise.promised_stream_id);
            if not strm then
                return 0
            end

            local req = strm.request
            local uri = req.uri;

            local namelen = #name
            local valuelen = #value

            local case = http2.lookup_token(name, namelen)

            if case == http2.HD__METHOD then
                req.method = value;
            elseif case == http2.HD__SCHEME then
                uri.scheme = value;
            elseif case == http2.HD__PATH then
                local ptr = ffi_cast(const_char_ptr_t, value)
                split_path(uri, value, ptr, ptr + valuelen);
            elseif case == http2.HD__AUTHORITY then
                uri.host = value
            elseif case == http2.HD_HOST then
                if not uri.host then
                    uri.host = value
                end
            else
                if (req.header_buffer_size + namelen + valuelen > 64 * 1024) then
                    lib.nghttp2_submit_rst_stream(self.session, lib.NGHTTP2_FLAG_NONE,
                        frame.hd.stream_id, lib.NGHTTP2_INTERNAL_ERROR)
                else
                    req:update_header_buffer_size(namelen + valuelen)

                    req.headers = req.headers or {}
                    req.headers[name] = {
                        value = value,
                        sensitive = band(flags, lib.NGHTTP2_NV_FLAG_NO_INDEX) ~= 0
                    }
                end

            end
            return 0
        end
    end
    return 0
end

function _M:on_frame_recv(frame)
    local strm = self:find_stream(frame.hd.stream_id);
    if not strm then
        return 0
    end
    local t = frame.hd.type
    if t == lib.NGHTTP2_DATA then
        if band(frame.hd.flags, lib.NGHTTP2_FLAG_END_STREAM) ~= 0 then
            strm.response:call_on_data();
        end
    elseif t == lib.NGHTTP2_HEADERS then
        if frame.headers.cat == lib.NGHTTP2_HCAT_HEADERS and
            not strm:expect_final_response() then
            return 0;
        end

        if strm:expect_final_response() then
            -- wait for final response
            return 0
        end

        local req = strm.request
        req:call_on_response(strm.response);
        if band(frame.hd.flags, lib.NGHTTP2_FLAG_END_STREAM) ~= 0 then
            strm.response:call_on_data();
        end
    elseif t == lib.NGHTTP2_PUSH_PROMISE then
        local push_strm = self:find_stream(frame.push_promise.promised_stream_id);
        if not push_strm then
            return 0
        end

        strm.request:call_on_push(push_strm.request);
    end
    return 0
end

function _M:on_data_chunk_recv(flags, stream_id, data)
    local strm = self:find_stream(stream_id);
    if not strm then
        return 0
    end

    local res = strm.response
    res:call_on_data(data);

    return 0
end

function _M:on_stream_close(stream_id, error_code)
    local strm = self:pop_stream(stream_id);
    if not strm then
        return 0
    end

    local err
    if error_code ~= 0 then
        err = ffi_string(lib.nghttp2_http2_strerror(error_code))
    end

    strm.request:call_on_close(err)

    return 0
end

function _M:resume(strm)
    if (self.stopped) then
        return
    end
    lib.nghttp2_session_resume_data(self.session, strm.stream_id);
    self:signal_write();
end

function _M:should_stop()
    return lib.nghttp2_session_want_read(self.session) == 0 and
        lib.nghttp2_session_want_write(self.session) == 0
end

---@param self nghttp2.session
local function write_thread(self)
    logger.debug("enter write_thread:", tostring(self.session))
    self.sem_write_thead_exit = semaphore.new()
    while not self.stopped do
        local data, err = libresty_nghttp2.mem_send(self.session)
        if err then
            self:call_error_cb(err)
            stop(self)
            goto EXIT
        end
        if not data then
            if self:should_stop() then
                stop(self)
                goto EXIT
            end
            self.wait_write = true
            self.write_sem:wait(1)
        else
            local bytes, err = self.tcpsock:send(data)
            if not bytes then
                self:call_error_cb("tcpsock send:" .. err)
                stop(self)
                goto EXIT
            end
        end
    end
    ::EXIT::
    logger.debug("exit write_thread")
    self.sem_write_thead_exit:post()
end

function _M:signal_write()
    if (self.stopped) then
        return
    end

    if self.wait_write then
        logger.debug("self.write_sem")
        self.write_sem:post()
        self.wait_write = false
    end
end

---@param self nghttp2.session
local function do_read(self)
    self.sem_read_thead_exit = semaphore.new()
    logger.debug("enter do_read")
    while not self.stopped do
        local data, err = self.tcpsock:receiveany(10 * 1024)
        if not data then
            if not self:should_stop() then
                self:call_error_cb("tcpsock receiveany:" .. err)
            end
            stop(self)
            goto EXIT
        end
        local rv, err = libresty_nghttp2.mem_recv(self.session, data)
        if not rv then
            self:call_error_cb(err)
            stop(self)
            goto EXIT
        end
        self:signal_write()
        if self:should_stop() then
            stop(self)
            goto EXIT
        end
    end
    ::EXIT::
    logger.debug("exit do_read")
    self.sem_read_thead_exit:post()
end

function _M:on_connection()
    local th1 = ngx.thread.spawn(write_thread, self)
    local th2 = ngx.thread.spawn(do_read, self)
    self:start_ping()
    logger.debug("on_connection")
    return th1, th2
end

function _M:call_error_cb(error)
    if self.on_error then
        self:on_error(error)
    end
end

local nghttp2_nv_t = ffi.typeof("nghttp2_nv[?]")
local nghttp2_data_provider = ffi.new("nghttp2_data_provider")
nghttp2_data_provider.read_callback = libresty_nghttp2.resty_nghttp2_data_provider_read_callback
nghttp2_data_provider.source.ptr = ffi.cast("ssize_t (*)(int32_t stream_id, uint8_t *buf, size_t length,uint32_t *data_flags,void *user_data)"
    , function(stream_id, buf, length, data_flags, user_data)
    local session = session_registry[user_data_key(user_data)]
    if not session then
        return lib.NGHTTP2_ERR_CALLBACK_FAILURE
    end
    local strm = session:find_stream(stream_id)
    if not strm then
        return lib.NGHTTP2_ERR_CALLBACK_FAILURE
    end
    return strm.request:call_on_read(buf, length, data_flags)
end)
ffi.cdef [[
typedef struct nghttp2_data_string_source {
    const char *data;
    size_t data_len;
    size_t left;
}nghttp2_data_string_source;
]]
local nghttp2_data_string_source_t = ffi.typeof("nghttp2_data_string_source")
local nghttp2_data_string_provider = ffi.new(ffi.typeof(nghttp2_data_provider))
nghttp2_data_string_provider.read_callback = libresty_nghttp2.resty_nghttp2_data_provider_string_generator

local nghttp2_priority_spec_t = ffi.typeof "nghttp2_priority_spec"

local function createa_headers_nv(nvs, i, headers)
    local i = i or 0
    for k, v in pairs(headers) do
        if type(v) == 'table' then
            http2.make_nv_ls(nvs[i], k, v.value, v.sensitive)
        else
            http2.make_nv_ls(nvs[i], k, v)
        end
        i = i + 1
    end
    return i
end

function _M:request_allowed()
    return lib.nghttp2_session_check_request_allowed(self.session) ~= 0
end

function _M:submit(scheme, host, path, method, headers, data_or_cb, prio)
    if self.stopped then
        return nil, "stopped"
    end
    prio = prio and nghttp2_priority_spec_t(prio) or nil
    local strm = create_stream(0, self)
    local req = strm.request

    local nvs = nghttp2_nv_t(4 + tab_nkeys(headers))
    http2.make_nv_ls(nvs[0], ":method", method)
    http2.make_nv_ls(nvs[1], ":scheme", scheme)
    http2.make_nv_ls(nvs[2], ":path", path)
    http2.make_nv_ls(nvs[3], ":authority", host)
    local i = createa_headers_nv(nvs, 4, headers)
    req.method = method
    req.uri.scheme = scheme
    req.uri.path = path
    req.uri.host = host
    req.headers = headers

    local prd
    if data_or_cb then
        if type(data_or_cb) == "function" then
            prd = nghttp2_data_provider
            req.generator_cb = data_or_cb
        else
            data_or_cb = tostring(data_or_cb)
            local nghttp2_data_string_source = nghttp2_data_string_source_t()
            nghttp2_data_string_provider.source.ptr = nghttp2_data_string_source
            nghttp2_data_string_source.data = data_or_cb
            nghttp2_data_string_source.data_len = #data_or_cb
            nghttp2_data_string_source.left = #data_or_cb
            req.body = { nghttp2_data_string_source, data_or_cb }
            prd = nghttp2_data_string_provider
        end
    end


    local stream_id = lib.nghttp2_submit_request(self.session, prio, nvs, i, prd, nil)
    if stream_id < 0 then
        return nil, lib.nghttp2_strerror(stream_id)
    end
    logger.info("submit stream:", stream_id)
    strm.stream_id = stream_id
    self.streams[stream_id] = strm
    self:signal_write()
    self:stop_ping()
    return strm
end

function _M:cancel(strm, error_code)
    if (self.stopped) then
        return;
    end

    lib.nghttp2_submit_rst_stream(self.session, lib.NGHTTP2_FLAG_NONE, strm.stream_id,
        error_code);
    self:signal_write();
end

function _M:write_trailer(strm, headers)
    assert(type(headers) == "table")
    local nvs = nghttp2_nv_t(tab_nkeys(headers))
    local i = createa_headers_nv(nvs, 0, headers)
    local rv = lib.nghttp2_submit_trailer(self.session, strm.stream_id, nvs, i)
    if rv ~= 0 then
        logger.error(lib.nghttp2_strerror(rv))
        return -1;
    end
    self:signal_write();
end

function _M:shutdown()
    if self.stopped then
        return
    end
    if not self.session then
        return
    end
    lib.nghttp2_session_terminate_session(self.session, lib.NGHTTP2_NO_ERROR)
    self:signal_write()
    self.sem_write_thead_exit:wait(1)
    self.sem_read_thead_exit:wait(1)
end

return _M
