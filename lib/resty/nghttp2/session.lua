local getenv = os.getenv
local tonumber = tonumber
local handlers = require "dev.handlers"
local log = require("apisix.core.log")
local semaphore = require "ngx.semaphore"
local pack = require "dev.pack"
local protocol = require "dev.protocol"

local timer = require "resty.timer"

local table_clear = require("table.clear")
local table_insert = table.insert
local table_isempty = require("table.isempty")
local table_isarray = require("table.isarray")
local table_unpack = table.unpack
local table_pack = table.pack
local table_remove = table.remove
local ngx_now = ngx.now
local xpcall, tostring, select = xpcall, tostring, select
local exiting = ngx.worker.exiting

local default_option = {
    timeout = 5
}

---@alias rpc_status
---| "'connected'"
---| "'disconnect'"

---@class RpcClient
---@field stop boolean
---@field sock tcpsock
---@field lastTime number
---@field request_id integer
---@field option {timeout:number}
---@field sendSemaphore ngx.semaphore
---@field send_deque {head:RpcNetHead,body:any}[]
---@field requests table<string,ngx.semaphore>
---@field handle_request_deque any[]
---@field is_init boolean|nil
---@field changed_status fun(status:rpc_status)
---@field semaphore_pool ngx.semaphore[]
local _M = {
    _VERSION = "0.1.0"
}
---@module "dev.handlers"
_M.handlers = nil
---@param self RpcClient
local function init(self)
    self.stop = false
    self.send_deque = {}
    self.requests = {}
    self.option = self.option or default_option
    self.lastTime = ngx_now()
    self.request_id = 0
    self.sendSemaphore = self.sendSemaphore or semaphore.new()
    self.sock = nil
    self.handlers = self.handlers or handlers.new()
    self.handle_request_deque = {}
    self.semaphore_pool = {}
end

---@generic T
---@param obj? T
---@return T|RpcClient
function _M.new(obj)
    obj = obj or {}
    init(obj)
    return setmetatable(obj, {
        __index = _M
    })
end

local function pack_result(ok, ...)
    if not ok then
        return
    end
    local nparam = select('#', ...)
    if nparam == 0 then
        return nil
    elseif nparam == 1 then
        return select(1, ...)
    end
    return table_pack(...)
end

function _M:run_once_recv_msg()
    local head, body = pack.read(self.reader)
    if not head then
        self.stop = true
        return false
    end
    if head.Type == protocol.HBRequestType then

        self.lastTime = ngx_now()
        head.Type = protocol.HBResponseType
        pack.write(self.sock, head)

    elseif head.Type == protocol.HBResponseType then

        self.lastTime = ngx_now()
        -- Nothing to do here

    elseif head.Type == protocol.RequestType then

        table_insert(self.handle_request_deque, { head, body })

    elseif head.Type == protocol.ResponseType then

        self.lastTime = ngx_now()
        local key = tostring(head.Seq)
        local sm = self.requests[key]
        if sm then
            self.requests[key] = body
            sm:post()
        else
            log.info("can't find request:", head.ServiceMethod, head.Seq)
        end
    else
        log.error("can't find rpc head type:", head.Type)
    end
    return true
end

function _M:handle_requests()
    local v = table_remove(self.handle_request_deque, 1)
    if v then
        repeat
            local head = v[1]
            local body = v[2]
            local result = pack_result(xpcall(self.handlers.call, function(msg)
                head.Error = msg
            end, self.handlers, head.ServiceMethod, body))
            -- unused field
            head.ServiceMethod = nil
            head.Type = protocol.ResponseType
            if not pack.write(self.sock, head, result) then
                break
            end
            v = table_remove(self.handle_request_deque, 1)
        until v == nil
    end
end

---@param self RpcClient
local function recver(self)
    local count = 0
    while self.is_init do
        if not self:run_once_recv_msg() then
            return
        end
        count = count + 1
        self:handle_requests()
    end
    return count
end

function _M:run_once_send_msg()
    local v = table_remove(self.send_deque, 1)
    if v == nil then
        self.sendSemaphore:wait(1)
        return not self.stop
    end
    return pack.write(self.sock, v.head, v.body)
end

---@param self RpcClient
local function sender(self)
    local count = 0
    while self.is_init do
        if not self:run_once_send_msg() then
            return
        end
        count = count + 1
        if exiting() then
            self.is_init = true
            return count
        end
    end
    return count
end

---@param self RpcClient
local function post_message(self, head, body)
    if not self.is_init then
        log.debug("sock is not init when sending message", head.ServiceMethod)
        return true
    end

    local needPost = table_isempty(self.send_deque)
    table_insert(self.send_deque, {
        head = head,
        body = body
    })

    if needPost then
        self.sendSemaphore:post()
    end
    return true
end

---@return RpcNetHead
function _M:create_head(methodName)
    self.request_id = self.request_id + 1
    ---@type RpcNetHead
    return {
        ServiceMethod = methodName,
        Seq = self.request_id,
        Type = protocol.RequestType
    }
end

---@param methodName string
---@param obj any
---@return boolean
function _M:post_message(methodName, obj)
    return post_message(self, self:create_head(methodName), obj)
end

function _M:run_one()
    self:run_once_send_msg()
    self:run_once_recv_msg()
end

local function create_recver(self)
    xpcall(recver, function()
        self.is_init = false
    end, self)
end

function _M:run()
    local recver = ngx.thread.spawn(create_recver, self)
    pcall(sender, self)
    ngx.thread.wait(recver)
    self:handle_requests()
end

---@param self RpcClient
local function heart(self)
    post_message(self, {
        Type = protocol.HBRequestType
    }, nil)
end

function _M:start_once(host, port)
    self.sock = ngx.socket.tcp()
    local ok, err = self.sock:connect(host, port)
    if not ok then
        return nil, err
    end
    if self.stopped then
        return true
    end

    self.reader = pack.create_reader(self.sock)
    local heart_timer, err = timer.new({
        interval = 3, -- expiry interval in seconds
        recurring = true, -- recurring or single timer
        immediate = false, -- immediateinitial interval will be 0
        detached = false, -- run detached, or be garbagecollectible
        expire = function()
            heart(self)
        end -- callback on timer expiry
    })
    if not heart_timer then log.alert(err) return end
    -- send first packaget
    local node_id = tonumber(getenv("XWAF_AGENT_NODE_ID"))
    if not node_id then
        log.warn("NO XWAF_AGENT_NODE_ID used default 1")
        node_id = 1
    end
    if not pack.write_hello(self.sock, node_id) then
        return
    end
    self.is_init = true
    self.changed_status('connected')

    self:run()
    heart_timer:cancel()

    self.changed_status('disconnect')
    self.is_init = false
end

function _M:clear()
    init(self)
end

---comment
---@param self RpcClient
---@param head RpcNetHead
---@param ... any
---@return ...
local function call_service(self, head, ...)
    local body
    local nparam = select("#", ...)
    if nparam > 0 then
        if nparam == 1 then
            body = select(1, ...)
        else
            body = table_pack(...)
        end
    end

    if not post_message(self, head, body) then
        log.info("send message failed!")
        return nil
    end
    local sm = table_remove(self.semaphore_pool)
    if not sm then
        sm = semaphore.new()
    end

    local seq_key = tostring(head.Seq)
    self.requests[seq_key] = sm
    local ok, err = sm:wait(self.option.timeout)

    table_insert(self.semaphore_pool, sm)
    local data = self.requests[seq_key]
    self.requests[seq_key] = nil
    if err ~= nil then
        log.warn(head.ServiceMethod, "wait rpc response err:", err)
        return nil
    end
    assert(ok)
    if type(data) == "table" and table_isarray(data) then -- type is array ?
        return table_unpack(data)
    else
        return data
    end
end

---create service proxy from obj
---@generic T
---@param name string
---@param obj T
---@return T
function _M:register_service(name, obj)
    local rpc_client = self
    table_clear(obj)
    obj.name = name
    return setmetatable(obj, {
        __index = function(obj, cmd)
            obj[cmd] = function(...)
                local head = rpc_client:create_head(obj.name .. "." .. cmd)
                return call_service(rpc_client, head, ...)
            end
            return obj[cmd]
        end
    })
end

---unregister_service infact is unsupported
---@param _ any
function _M:unregister_service(_)
end

function _M:register_single_handler(name, obj, key, func)
    self.handlers:register(name, obj, key, func)
end

function _M:register_handler(name, obj)
    self.handlers:register_handler(name, obj)
end

function _M:unregister_handler(name)
    self.handlers:unregister_handler(name)
end

return _M
