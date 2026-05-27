-- util_http.lua
-- Hand-rolled HTTP/1.1 client over ngx.socket.tcp. OpenResty doesn't bundle
-- lua-resty-http, and this is the only HTTP egress shape we need (small JSON
-- bodies, in-band, tight timeouts). Returns (status_code, body) or (nil, err).

local _M = {}

local DEFAULT_TIMEOUT = 100  -- ms

local function read_response(sock)
    local status_line, lerr = sock:receive("*l")
    if not status_line then return nil, "recv status: " .. tostring(lerr) end
    local code = tonumber(status_line:match("HTTP/%d%.%d%s+(%d+)"))

    local content_length
    while true do
        local line, herr = sock:receive("*l")
        if not line then return nil, "recv header: " .. tostring(herr) end
        if line == "" then break end
        local cl = line:lower():match("^content%-length:%s*(%d+)")
        if cl then content_length = tonumber(cl) end
    end

    local body, berr
    if content_length and content_length > 0 then
        body, berr = sock:receive(content_length)
    else
        body, berr = sock:receive("*a")
    end
    if not body then return nil, "recv body: " .. tostring(berr) end

    return code, body
end

local function send_request(host, port, req, timeout_ms)
    local sock = ngx.socket.tcp()
    local t = timeout_ms or DEFAULT_TIMEOUT
    sock:settimeouts(t, t, t)

    local ok, err = sock:connect(host, port)
    if not ok then return nil, "connect: " .. tostring(err) end

    local _, serr = sock:send(req)
    if serr then sock:close(); return nil, "send: " .. tostring(serr) end

    local code, body = read_response(sock)
    sock:close()
    return code, body
end

function _M.post_json(host, port, path, payload, timeout_ms)
    payload = payload or ""
    local req = table.concat({
        "POST " .. path .. " HTTP/1.1",
        "Host: " .. host .. ":" .. port,
        "User-Agent: ml-waf-lua/1",
        "Content-Type: application/json",
        "Content-Length: " .. #payload,
        "Connection: close",
        "",
        payload,
    }, "\r\n")
    return send_request(host, port, req, timeout_ms)
end

function _M.get(host, port, path, timeout_ms)
    local req = table.concat({
        "GET " .. path .. " HTTP/1.1",
        "Host: " .. host .. ":" .. port,
        "User-Agent: ml-waf-lua/1",
        "Accept: application/json",
        "Connection: close",
        "",
        "",
    }, "\r\n")
    return send_request(host, port, req, timeout_ms)
end

-- URL-encode a value for query strings. Plain bytes only — sufficient for
-- IP addresses and short identifiers; do not feed it arbitrary unicode.
function _M.urlencode(s)
    if not s then return "" end
    return (s:gsub("([^%w%-_.~])", function(c)
        return string.format("%%%02X", c:byte())
    end))
end

return _M
