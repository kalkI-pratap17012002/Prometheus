-- request_logger.lua
-- log_by_lua phase: publish the raw request envelope to the waf:requests
-- Redis stream. Runs AFTER the response, fail-open and non-blocking.
--
-- IMPORTANT: log_by_lua_file forbids cosockets (ngx.socket.tcp / resty.redis).
-- All request data is collected in the log phase, then the actual Redis XADD
-- is deferred into a ngx.timer.at(0) callback where cosockets are allowed.

local cjson      = require "cjson.safe"
local redis      = require "resty.redis"
local sha256     = require "resty.sha256"
local resty_str  = require "resty.string"

local REDIS_HOST    = os.getenv("REDIS_HOST")   or "redis"
local REDIS_PORT    = tonumber(os.getenv("REDIS_PORT") or "6379")
local REQ_STREAM    = os.getenv("REDIS_STREAM") or "waf:requests"
local STREAM_MAXLEN = 100000

local BODY_LIMIT     = 65536
local SOCKET_TIMEOUT = 50

local log = ngx.log
local WARN, ERR = ngx.WARN, ngx.ERR

local function now_ms()
    return math.floor(ngx.now() * 1000)
end

local function client_ip()
    local xff = ngx.var.http_x_forwarded_for
    if xff and xff ~= "" then
        local first = xff:match("([^,%s]+)")
        if first then return first end
    end
    return ngx.var.remote_addr or "0.0.0.0"
end

local function collect_headers()
    local h = ngx.req.get_headers(100, true)
    if not h then return {} end
    local out = {}
    for k, v in pairs(h) do
        if type(v) == "table" then
            out[k] = table.concat(v, ",")
        else
            out[k] = tostring(v)
        end
    end
    return out
end

local function collect_body()
    -- access_by_lua already triggered ngx.req.read_body via lua_need_request_body.
    -- Do NOT call read_body() here; it is not safe in the log phase.
    local body = ngx.req.get_body_data()
    if not body then
        if ngx.req.get_body_file() then
            return "", true
        end
        return "", false
    end
    if #body > BODY_LIMIT then
        return body:sub(1, BODY_LIMIT), true
    end
    return body, false
end

local function sha256_hex(s)
    local h = sha256:new()
    if not h then return ngx.md5(s) end
    h:update(s)
    return resty_str.to_hex(h:final())
end

local function run()
    -- Collect everything while still in the request context (log phase).
    -- No socket I/O here — only safe variable reads.
    local ts_ms     = now_ms()
    local method    = ngx.req.get_method()
    local uri       = ngx.var.request_uri or ngx.var.uri or "/"
    local path_only = ngx.var.uri or "/"
    local query     = ngx.var.args or ""
    local ip        = client_ip()
    local headers   = collect_headers()
    local body, truncated = collect_body()
    local status_str = tostring(ngx.status)

    local req_hash     = sha256_hex(method .. "|" .. uri .. "|" .. ip .. "|" .. (body or ""))
    local headers_json = cjson.encode(headers) or "{}"

    -- Defer the Redis write to a timer so cosockets are available.
    local ok, err = ngx.timer.at(0, function(premature)
        if premature then return end
        local r = redis:new()
        r:set_timeouts(SOCKET_TIMEOUT, SOCKET_TIMEOUT, SOCKET_TIMEOUT)
        local rok, cerr = r:connect(REDIS_HOST, REDIS_PORT)
        if not rok then
            log(WARN, "request_logger: redis unavailable: ", tostring(cerr))
            return
        end
        local args = {
            REQ_STREAM, "MAXLEN", "~", STREAM_MAXLEN, "*",
            "ts_ms",        tostring(ts_ms),
            "method",       method,
            "uri",          uri,
            "path",         path_only,
            "query",        query,
            "client_ip",    ip,
            "headers_json", headers_json,
            "body",         body or "",
            "truncated",    truncated and "1" or "0",
            "request_hash", req_hash,
            "status",       status_str,
        }
        local _, xerr = r:xadd(unpack(args))
        if xerr then log(WARN, "request_logger: xadd waf:requests failed: ", xerr) end
        local kok = r:set_keepalive(10000, 50)
        if not kok then pcall(function() r:close() end) end
    end)
    if not ok then
        log(ERR, "request_logger: ngx.timer.at failed: ", tostring(err))
    end
end

local ok, err = pcall(run)
if not ok then
    log(ERR, "request_logger: unhandled error (fail-open): ", err)
end
