local lib = require('resty.nghttp2.libnghttp2')
local ffi = require('ffi')
local option_t = ffi.typeof "nghttp2_option*[1]"

---@class nghttp2.options
---@field no_auto_window_update boolean
---@field peer_max_concurrent_streams integer
---@field no_recv_client_magic boolean
---@field no_http_messaging boolean
---@field max_reserved_remote_streams integer
---@field user_recv_extension_type integer
---@field builtin_recv_extension_type integer
---@field no_auto_ping_ack boolean
---@field set_no_auto_ping_ack integer
---@field max_send_header_block_length integer
---@field max_deflate_dynamic_table_size integer
---@field no_closed_streams boolean
---@field max_outbound_ack integer
---@field max_settings integer
---@field server_fallback_rfc7540_priorities integer
---@field no_rfc9113_leading_and_trailing_ws_validation boolean

-- Makes a C options structure from table keys.
local opt_ptr = option_t()
---@param options nghttp2.options
local function create_options(options)
    local error_code = lib.nghttp2_option_new(opt_ptr)
    if error_code ~= 0 then
        return nil, lib.nghttp2_strerror(error_code)
    end
    local opt = opt_ptr[0]
    ffi.gc(opt, lib.nghttp2_option_del)
    if options.no_auto_window_update then
        lib.nghttp2_option_set_no_auto_window_update(opt, options.no_auto_window_update)
    end
    if options.peer_max_concurrent_streams then
        lib.nghttp2_option_set_peer_max_concurrent_streams(opt, tonumber(options.peer_max_concurrent_streams))
    end
    if options.no_recv_client_magic then
        lib.nghttp2_option_set_no_recv_client_magic(opt, options.no_recv_client_magic)
    end
    if options.no_http_messaging then

        lib.nghttp2_option_set_no_http_messaging(opt, options.no_http_messaging)
    end
    if options.max_reserved_remote_streams then
        lib.nghttp2_option_set_max_reserved_remote_streams(opt, tonumber(options.max_reserved_remote_streams))
    end
    if (options.user_recv_extension_type) then
        lib.nghttp2_option_set_user_recv_extension_type(opt, tonumber(options.user_recv_extension_type))
    end
    if (options.builtin_recv_extension_type) then
        lib.nghttp2_option_set_builtin_recv_extension_type(opt, tonumber(options.builtin_recv_extension_type))
    end
    if (options.no_auto_ping_ack) then
        lib.nghttp2_option_set_no_auto_ping_ack(opt, options.set_no_auto_ping_ack)
    end
    if (options.max_send_header_block_length) then
        lib.nghttp2_option_set_max_send_header_block_length(opt, tonumber(options.max_send_header_block_length))
    end
    if (options.max_deflate_dynamic_table_size) then
        lib.nghttp2_option_set_max_deflate_dynamic_table_size(opt,
            tonumber(options.max_deflate_dynamic_table_size))
    end
    if (options.no_closed_streams) then
        lib.nghttp2_option_set_no_closed_streams(opt, tonumber(options.no_closed_streams))
    end
    if (options.max_outbound_ack) then
        lib.nghttp2_option_set_max_outbound_ack(opt, tonumber(options.max_outbound_ack))
    end
    if (options.max_settings) then
        lib.nghttp2_option_set_max_settings(opt, tonumber(options.max_settings))
    end
    if (options.server_fallback_rfc7540_priorities) then
        lib.nghttp2_option_set_server_fallback_rfc7540_priorities(opt,
            tonumber(options.server_fallback_rfc7540_priorities))
    end
    if (options.no_rfc9113_leading_and_trailing_ws_validation) then
        lib.nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(opt,
            tonumber(options.no_rfc9113_leading_and_trailing_ws_validation))
    end
    return opt
end

return create_options
