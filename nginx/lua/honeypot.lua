-- honeypot.lua
-- Decoy endpoints (/admin, /wp-login.php, /.env, …). Anyone hitting these
-- on a legitimate app would be a misconfiguration; in practice it is a
-- scanner or an automated exploit pass. We:
--   1. Log the full hit to Redis stream waf:honeypot.
--   2. Add the source IP to ip_rules (BLOCK, 24h TTL) via /ip-rules.
--   3. Return a *convincing* fake response — never 403, because a 403
--      tells the scanner the path is a trap.

local cjson      = require "cjson.safe"
local redis      = require "resty.redis"
local http       = require "util_http"

local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT") or "6379")
local STREAM     = "waf:honeypot"
local STREAM_MAXLEN = 50000

local ML_HOST = os.getenv("ML_ENGINE_HOST") or "ml_engine"
local ML_PORT = tonumber(os.getenv("ML_ENGINE_PORT") or "8000")

local log  = ngx.log
local WARN = ngx.WARN

local function client_ip()
    local xff = ngx.var.http_x_forwarded_for
    if xff and xff ~= "" then
        local first = xff:match("([^,%s]+)")
        if first then return first end
    end
    return ngx.var.remote_addr or "0.0.0.0"
end

local function publish_stream(ip, path, method, ua)
    local r = redis:new()
    r:set_timeouts(50, 50, 50)
    local ok, err = r:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        log(WARN, "honeypot: redis connect failed: ", err)
        return
    end
    local _, xerr = r:xadd(STREAM, "MAXLEN", "~", STREAM_MAXLEN, "*",
        "ts_ms",      tostring(math.floor(ngx.now() * 1000)),
        "client_ip",  ip,
        "path",       path,
        "method",     method,
        "user_agent", ua or "",
        "uri",        ngx.var.request_uri or path
    )
    if xerr then log(WARN, "honeypot: xadd failed: ", xerr) end
    local kok = r:set_keepalive(10000, 50)
    if not kok then pcall(function() r:close() end) end
end

local function add_block_rule(ip)
    local payload = cjson.encode({
        ip_cidr          = ip .. "/32",
        action           = "BLOCK",
        reason           = "honeypot",
        expires_in_hours = 24,
    }) or "{}"
    local code, body = http.post_json(ML_HOST, ML_PORT, "/ip-rules", payload, 100)
    if code ~= 201 and code ~= 200 then
        log(WARN, "honeypot: /ip-rules add failed (", tostring(code), "): ", tostring(body))
    end
end

-- ---------------------------------------------------------------------------
-- Fake response bodies. Goal: look like a real misconfigured asset so the
-- scanner moves on with a "hit" in its log. Avoid signalling that this is a
-- WAF — no X-WAF headers, no obvious decoy markers.
-- ---------------------------------------------------------------------------

local FAKE_WP_LOGIN = [[<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Log In &lsaquo; WordPress</title>
<link rel='stylesheet' id='login-css' href='/wp-admin/css/login.min.css?ver=6.4.2' type='text/css' media='all' />
</head>
<body class="login no-js login-action-login wp-core-ui locale-en-us">
<div id="login">
  <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
  <form name="loginform" id="loginform" action="/wp-login.php" method="post">
    <p><label for="user_login">Username or Email Address</label>
       <input type="text" name="log" id="user_login" autocomplete="username" class="input" size="20" /></p>
    <p><label for="user_pass">Password</label>
       <input type="password" name="pwd" id="user_pass" autocomplete="current-password" class="input" size="20" /></p>
    <p class="submit">
       <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
    </p>
  </form>
</div>
</body>
</html>
]]

local FAKE_404 = [[<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
]]

local function respond_fake(path)
    if path == "/wp-login.php" then
        ngx.status = 200
        ngx.header["Content-Type"] = "text/html; charset=UTF-8"
        ngx.header["Server"]       = "Apache"  -- look like a typical wp host
        ngx.say(FAKE_WP_LOGIN)
    else
        ngx.status = 404
        ngx.header["Content-Type"] = "text/html"
        ngx.say(FAKE_404)
    end
    return ngx.exit(ngx.status)
end

-- ---------------------------------------------------------------------------
-- main
-- ---------------------------------------------------------------------------

local function run()
    local ip     = client_ip()
    local path   = ngx.var.uri or "/"
    local method = ngx.req.get_method()
    local ua     = ngx.var.http_user_agent or ""

    publish_stream(ip, path, method, ua)

    -- Fire-and-forget so we don't block the fake response on a slow upstream.
    -- Capture add_block_rule in closure to avoid nil reference in timer
    local block_fn = add_block_rule
    local captured_ip = ip
    ngx.timer.at(0, function() block_fn(captured_ip) end)

    respond_fake(path)
end

local ok, err = pcall(run)
if not ok then
    log(WARN, "honeypot: unhandled error, falling back to fake 404: ", err)
    ngx.status = 404
    ngx.header["Content-Type"] = "text/html"
    ngx.say("<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center></body></html>")
    return ngx.exit(404)
end
