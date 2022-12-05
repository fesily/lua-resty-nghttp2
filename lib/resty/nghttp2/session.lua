local lib = require('resty.nghttp2.libnghttp2')
local ffi = require('ffi')
local bit = require 'bit'
local timer = require "resty.timer"
local tab_nkeys = require 'table.nkeys'
local create_options = require('resty.nghttp2.options')
local create_stream = require('resty.nghttp2.stream')
local semaphore = require 'ngx.semaphore'
local http2 = require 'resty.nghttp2.http2'
local url_parser = require 'resty.nghttp2.url_parser'

local ffi_cast = ffi.cast
local ffi_string = ffi.string
local uint16_t = ffi.typeof("uint16_t")
local ptr_t = ffi.typeof("void*")
local unescape_uri = ngx.unescape_uri
local band = bit.band

---@class nghttp2.session
local _M = {}
local _mt = {
    __index = _M
}
---@type table<number, nghttp2.session>
local session_registry = {}
local function user_data_key(user_data)
    return tonumber(ffi_cast(uint16_t, user_data))
end

local global_callbacks = {
    --[[
        typedef int (*nghttp2_on_begin_headers_callback)(nghttp2_session *session,
                                                 const nghttp2_frame *frame,
                                                 void *user_data)
    ]]
    on_begin_headers = ffi.cast("nghttp2_on_begin_headers_callback",
        function(session, frame, user_data)
            session = session_registry[user_data_key(user_data)]
            if not session then
                return lib.NGHTTP2_ERR_CALLBACK_FAILURE
            end
            return session:on_begin_headers(frame)
        end);
    --[[
            typedef int (*nghttp2_on_header_callback)(nghttp2_session *session,
                                          const nghttp2_frame *frame,
                                          const uint8_t *name, size_t namelen,
                                          const uint8_t *value, size_t valuelen,
                                          uint8_t flags, void *user_data);
        ]]
    on_header = ffi.cast("nghttp2_on_header_callback",
        function(session, frame, name, namelen, value, valuelen, flags, user_data)
            session = session_registry[user_data_key(user_data)]
            if not session then
                return lib.NGHTTP2_ERR_CALLBACK_FAILURE
            end
            return session:on_header(frame, name, namelen, value, valuelen, flags)
        end);

    on_frame_recv = ffi.cast("nghttp2_on_frame_recv_callback",
        function(session, frame, user_data)
            session = session_registry[user_data_key(user_data)]
            if not session then
                return lib.NGHTTP2_ERR_CALLBACK_FAILURE
            end
            return session:on_frame_recv(frame)
        end);
    on_data_chunk_recv = ffi.cast("nghttp2_on_data_chunk_recv_callback",
        function(session, flags, stream_id, data, len, user_data)
            session = session_registry[user_data_key(user_data)]
            if not session then
                return lib.NGHTTP2_ERR_CALLBACK_FAILURE
            end
            return session:on_data_chunk_recv(flags, stream_id, data, len)
        end);
    --[[
        int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code, void *user_data)
    ]]
    on_stream_close = ffi.cast("nghttp2_on_stream_close_callback",
        function(session, stream_id, error_code, user_data)
            session = session_registry[user_data_key(user_data)]
            if not session then
                return lib.NGHTTP2_ERR_CALLBACK_FAILURE
            end
            return session:on_stream_close(stream_id, error_code)
        end)
}

local function session_callbacks_del(callbacks)
    lib.nghttp2_session_callbacks_del(callbacks[0])
end

-- Make a C callbacks structure using the functions in a table.
-- Will fail if a callback is defined but is not a function.
-- Ignores keys that are not callbacks.
local nghttp2_session_callbacks_t = ffi.typeof "nghttp2_session_callbacks*[1]"
local function create_callbacks()
    local cb = nghttp2_session_callbacks_t()
    local error_code = lib.nghttp2_session_callbacks_new(cb)
    if error_code ~= 0 then
        return nil, lib.nghttp2_strerror(error_code)
    end
    ffi.gc(cb, session_callbacks_del)
    for name, func in pairs(global_callbacks) do
        local set_callback = "nghttp2_session_callbacks_set_" .. name .. "_callback"
        lib[set_callback](cb[0], func)
    end
    return cb
end

local nghttp2_session_t = ffi.typeof "nghttp2_session*[1]"
local user_data_count = 0

local window_size = 256 * 1024 * 1024
local default_submit_settings
do
    default_submit_settings = ffi.new("nghttp2_settings_entry[2]", {
        { lib.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
        { lib.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, window_size }
    })
end

function _M:handle_ping()
    if (self.stopped or tab_nkeys(self.streams) ~= 0) then return end

    lib.nghttp2_submit_ping(self.handler[0], lib.NGHTTP2_FLAG_NONE, nil)

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
    local session = nghttp2_session_t()
    local rv
    if options then
        rv = lib.nghttp2_session_client_new2(session, cb[0], ffi_cast(ptr_t, user_data_count), options[0])
    else
        rv = lib.nghttp2_session_client_new(session, cb[0], ffi_cast(ptr_t, user_data_count))
    end
    if rv ~= 0 then
        return nil, lib.nghttp2_strerror(rv)
    end
    user_data_count = user_data_count + 1
    if user_data_count > 65535 then
        user_data_count = 0
    end
    lib.nghttp2_session_set_local_window_size(session[0], lib.NGHTTP2_FLAG_NONE, 0, window_size)
    lib.nghttp2_submit_settings(session[0], lib.NGHTTP2_FLAG_NONE, default_submit_settings,
        ffi.sizeof(default_submit_settings))
    ---@class nghttp2.session
    return setmetatable({ handler = session,
        ---@type nghttp2.stream[]
        streams = {},
        stopped = false,
        tcpsock = ngx.socket.tcp(),
        write_sem = semaphore.new(),
        on_error = opt.on_error,
    }, _mt)
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
    local strm = self.streams[stream_id]
    self.streams[stream_id] = nil
    if tab_nkeys(self.streams) == 0 then
        self:start_ping()
    end
    return strm
end

function _M:start_ping()
    if not self.ping_timer then
        self.ping_timer = timer.new({
            interval = 15,
            recurring = true,
            immediate = false,
            detached = false,
            expire = _M.handle_ping,
        }, self)
    end
end

function _M:stop_ping()
    if self.ping_timer then
        self.ping_timer:cancel()
        self.ping_timer = nil
    end
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
    self:create_stream(frame.push_promise.promised_stream_id)
    return 0
end

function _M:on_header(frame, name, namelen, value, valuelen, flags)
    local t = frame.hd.type
    if t == lib.NGHTTP2_HEADERS then
        local strm = self:find_stream(frame.hd.stream_id)
        if not strm then
            return 0
        end
        if frame.headers.cat == lib.NGHTTP2_HCAT_HEADERS and not strm:expect_final_response() then
            return 0
        end
        local token = http2.lookup_token(name, namelen);

        local res = strm.response
        if token == http2.HD__STATUS then
            res:status_code(tonumber(ffi_string(value, valuelen)));
        else
            if res.header_buffer_size + namelen + valuelen > 64 * 1024 then
                lib.nghttp2_submit_rst_stream(self, lib.NGHTTP2_FLAG_NONE,
                    frame.hd.stream_id, lib.NGHTTP2_INTERNAL_ERROR);
                return 0
            end
            res:update_header_buffer_size(namelen + valuelen);

            if token == http2.HD_CONTENT_LENGTH then
                res.content_length = tonumber(ffi_string(value, valuelen))
            end

            res.headers[ffi_string(name, namelen)] = { value = ffi_string(value, valuelen),
                sensitive = band(flags, lib.NGHTTP2_NV_FLAG_NO_INDEX) ~= 0 }
        end
    else if t == lib.NGHTTP2_PUSH_PROMISE then
            local strm = self:find_stream(frame.push_promise.promised_stream_id);
            if not strm then
                return 0
            end

            local req = strm.request
            local uri = req.uri;

            local name_s = ffi_string(name, namelen)
            local value_s = ffi_string(value, valuelen)
            local case = http2.lookup_token(name, namelen)

            if case == http2.HD__METHOD then
                req.method = value_s;
            elseif case == http2.HD__SCHEME then
                uri.scheme = value_s;
            elseif case == http2.HD__PATH then
                split_path(uri, value_s, value, value + valuelen);
            elseif case == http2.HD__AUTHORITY then
                uri.host = value_s
            elseif case == http2.HD_HOST then
                if not uri.host then
                    uri.host = value_s
                end
            else
                if (req.header_buffer_size + namelen + valuelen > 64 * 1024) then
                    lib.nghttp2_submit_rst_stream(self, lib.NGHTTP2_FLAG_NONE,
                        frame.hd.stream_id, lib.NGHTTP2_INTERNAL_ERROR)
                else
                    req:update_header_buffer_size(namelen + valuelen)

                    req.headers[name_s] = {
                        value = value_s,
                        sensitive = band(flags, lib.NGHTTP2_NV_FLAG_NO_INDEX) ~= 0
                    }
                end

            end
            return 0
        end
    end
end

function _M:on_frame_recv(frame)
    local strm = self:find_stream(frame.push_promise.promised_stream_id);
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

function _M:on_data_chunk_recv(flags, stream_id, data, len)
    local strm = self:find_stream(stream_id);
    if not strm then
        return 0
    end

    local res = strm.response
    res:call_on_data(data, len);

    return 0
end

function _M:on_stream_close(stream_id, error_code)
    local strm = self:pop_stream(stream_id);
    if not strm then
        return 0
    end

    strm.request:call_on_close(error_code)

    return 0
end

function _M:resume(strm)
    if (self.stopped) then
        return
    end
    lib.nghttp2_session_resume_data(self.handler[0], strm.stream_id);
    self:signal_write();
end

---@param self nghttp2.session
local function stop(self)
    if (self.stopped) then
        return
    end
    self.stopped = true
    self:stop_ping()
    self.tcpsock:close()
end

function _M:should_stop()
    return not lib.nghttp2_session_want_read(self.handler[0]) and
        not lib.nghttp2_session_want_write(self.handler[0])
end

local data_t = ffi.typeof "const uint8_t*[1]"

---@param self nghttp2.session
local function write_thread(self)
    local data = data_t()
    while not self.stopped do
        local n = lib.nghttp2_session_mem_send(self.handler[0], data)
        if n < 0 then
            self:call_error_cb(lib.nghttp2_strerror(n))
            stop(self)
            return
        end
        if n == 0 then
            if self:should_stop() then
                stop(self)
                return
            end
            self.write_sem:wait()
        else
            local ok, err = self.tcpsock:send(ffi_string(data[0], n))
            if not ok then
                self:call_error_cb(err)
                stop(self)
                return
            end
        end
    end
end

function _M:signal_write()
    if (self.stopped) then
        return
    end

    self.write_sem:post()
end

function _M:do_read()
    while not self.stopped do
        local data, err = self.tcpsock:receiveany(10 * 1024)
        if not data then
            if not self:should_stop() then
                self:call_error_cb(err)
            end
            stop(self)
            return
        end
        local rv = lib.nghttp2_session_mem_recv(self.handler[0], data, #data)
        if rv ~= #data then
            self:call_error_cb(rv < 0 and lib.nghttp2_strerror(rv) or "General protocol error")
            stop(self)
            return
        end
        self:signal_write()
        if self:should_stop() then
            stop(self)
            return
        end
    end
end

function _M:connection(host, port, opts)
    local ok, err = self.tcpsock:connect(host, port, opts)
    if not ok then
        return nil, err
    end
    self.writing = ngx.thread.spawn(write_thread, self)
    self.reader = ngx.thread.spawn(_M.do_read, self)
    self:start_ping()
end

function _M:call_error_cb(error)
    if self.on_error then
        self:on_error(error)
    end
end

local UF_SCHEMA = bit.lshift(1, url_parser.UF_SCHEMA)
local UF_HOST = bit.lshift(1, url_parser.UF_HOST)
local HF_PORT = bit.lshift(1, url_parser.UF_PORT)
local UF_QUERY = bit.lshift(1, url_parser.UF_QUERY)

local nghttp2_nv_t = ffi.typeof("nghttp2_nv[?]")
local nghttp2_data_provider = ffi.new("nghttp2_data_provider")
nghttp2_data_provider.read_callback = function(session, stream_id, buf, length, data_flags, source, user_data)
    local session = session_registry[user_data_key(user_data)]
    if not session then
        return lib.NGHTTP2_ERR_CALLBACK_FAILURE
    end
    local strm = session:find_stream(stream_id)
    if not strm then
        return lib.NGHTTP2_ERR_CALLBACK_FAILURE
    end
    return strm.request:call_on_read(buf, length, data_flags)
end

function _M:submit(method, uri, cb, headers, prio)
    if self.stopped then
        return nil, "stopped"
    end
    local u1, err = url_parser.http_parser_parse_url(uri);
    if not u1 then
        return nil, err
    end
    local u = u1[0]
    if band(u.field_set, UF_SCHEMA) == 0 and band(u.field_set, UF_HOST) == 0 then
        return nil, "invalid uri"
    end
    local strm = create_stream(0, self)
    local req = strm.request
    local uref = req.uri
    uref.scheme = http2.copy_url_component(u, url_parser.UF_SCHEMA, uri);
    uref.host = http2.copy_url_component(u, url_parser.UF_HOST, uri);
    uref.raw_path = http2.copy_url_component(u, url_parser.UF_PATH, uri);
    uref.raw_query = http2.copy_url_component(u, url_parser.UF_QUERY, uri);

    if url_parser.ipv6_numeric_addr(uref.host) then
        uref.host = "[" .. uref.host .. "]"
    end

    if band(u.field_set, HF_PORT) ~= 0 then
        uref.host = uref.host .. ":" .. u.port
    end

    if not uref.raw_path or #uref.raw_path == 0 then
        uref.raw_path = "/"
    end

    uref.path = unescape_uri(uref.raw_path)

    local path = uref.raw_path

    if band(u.field_set, UF_QUERY) ~= 0 then
        path = path .. "?" .. uref.raw_query
    end

    local nvs = nghttp2_nv_t(4 + tab_nkeys(headers))
    http2.make_nv_ls(nvs[0], ":method", method)
    http2.make_nv_ls(nvs[1], ":scheme", uref.scheme)
    http2.make_nv_ls(nvs[2], ":path", path)
    http2.make_nv_ls(nvs[3], ":authority", uref.host)
    local i = 4
    for k, v in pairs(headers) do
        http2.make_nv_ls(nvs[i], k, v.value, v.sensitive)
        i = i + 1
    end
    req.headers = headers

    local prd
    if cb then
        req.generator_cb = cb
        prd = nghttp2_data_provider
    end

    local stream_id = lib.nghttp2_submit_request(self.handler[0], prio, nvs, prd, nil)
    if stream_id < 0 then
        return nil, lib.nghttp2_strerror(stream_id)
    end
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

    lib.nghttp2_submit_rst_stream(self.handler[0], lib.NGHTTP2_FLAG_NONE, strm.stream_id,
        error_code);
    self:signal_write();
end

function _M:write_trailer(strm, headers)
    assert(type(headers) == "table")
    local nghttp2_nvs = nghttp2_nv_t(tab_nkeys(headers))
    local i = 0
    for k, v in pairs(headers) do
        http2.make_nv_ls(nghttp2_nvs[i], k, v.value, v.sensitive)
        i = i + 1
    end
    local rv = lib.nghttp2_submit_trailer(self.handler[0], strm.stream_id, nghttp2_nvs, i)
    if (rv ~= 0) then
        ngx.log(ngx.ERR, lib.nghttp2_strerror(rv))
        return -1;
    end
    self:signal_write();
end

function _M:shutdown()
    if self.stopped then
        return
    end
    if not self.handler then
        return
    end
    lib.nghttp2_session_terminate_session(self.handler[0], lib.NGHTTP2_NO_ERROR)
    self:signal_write()
    ngx.thread.wait(self.reader, self.writing)
end

return _M
