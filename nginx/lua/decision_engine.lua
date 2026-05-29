-- decision_engine.lua
-- Phase 4: combined WAF decision pipeline.
--   1. Look up the client IP against ip_rules via FastAPI /ip-check.
--   2. Read ModSecurity's aggregate anomaly score from X-Modsec-Score
--      (injected by modsec_custom_rules.conf, rule 9000901).
--   3. Call ml_engine /score for the ML verdict.
--   4. Combine modsec_score + ml_score via the priority ladder.
--   5. Log the full decision asynchronously via /log-request.
--   6. Block (403 JSON), log-through, or pass.

local cjson      = require "cjson.safe"
local sha256     = require "resty.sha256"
local resty_str  = require "resty.string"
local http       = require "util_http"

local ML_HOST     = os.getenv("ML_ENGINE_HOST") or "ml_engine"
local ML_PORT     = tonumber(os.getenv("ML_ENGINE_PORT") or "8000")
local BODY_LIMIT  = 65536
local ML_TIMEOUT  = 400  -- ml /score budget
local IP_TIMEOUT  = 200  -- ip-check is cached, should be fast
local LOG_TIMEOUT = 200  -- log-request returns immediately on FastAPI side

local log  = ngx.log
local WARN = ngx.WARN
local ERR  = ngx.ERR

-- ---------------------------------------------------------------------------
-- helpers
-- ---------------------------------------------------------------------------

local function client_ip()
    local xff = ngx.var.http_x_forwarded_for
    if xff and xff ~= "" then
        local first = xff:match("([^,%s]+)")
        if first then return first end
    end
    return ngx.var.remote_addr or "0.0.0.0"
end

local function collect_headers()
    local h = ngx.req.get_headers(100, true) or {}
    local out = {}
    for k, v in pairs(h) do
        out[k] = (type(v) == "table") and table.concat(v, ",") or tostring(v)
    end
    return out
end

local function collect_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        if ngx.req.get_body_file() then return "", true end
        return "", false
    end
    if #body > BODY_LIMIT then return body:sub(1, BODY_LIMIT), true end
    return body, false
end

local function sha256_hex(s)
    local h = sha256:new()
    if not h then return ngx.md5(s) end
    h:update(s)
    return resty_str.to_hex(h:final())
end

-- has_attack_pattern: quick regex check used as a metric tag (not a decision).
local ATTACK_RE = [[(?i)(?:\b(?:union|select|drop|delete|insert|update)\b|<script|onerror\s*=|javascript:|\.\./|;\s*cat\s+/etc)]]
local function looks_attacky(s)
    if not s or s == "" then return false end
    return ngx.re.find(s, ATTACK_RE, "jo") ~= nil
end

-- ---------------------------------------------------------------------------
-- block/respond helpers
-- ---------------------------------------------------------------------------

local function respond_blocked(req_hash, reason, score)
    ngx.status = 403
    ngx.header["Content-Type"]   = "application/json"
    ngx.header["X-WAF-Decision"] = "BLOCK"
    if score then ngx.header["X-WAF-Score"] = tostring(score) end
    ngx.say(cjson.encode({
        error = "Request blocked",
        ref   = req_hash:sub(1, 8),
        reason = reason,
    }) or '{"error":"Request blocked"}')
    return ngx.exit(403)
end

-- ---------------------------------------------------------------------------
-- IP lookup, ML call, async log
-- ---------------------------------------------------------------------------

local function ip_check(ip)
    local code, body = http.get(ML_HOST, ML_PORT,
        "/ip-check?ip=" .. http.urlencode(ip), IP_TIMEOUT)
    if code ~= 200 or not body then
        return nil, "ip-check unreachable: " .. tostring(body)
    end
    local data = cjson.decode(body)
    if not data then return nil, "ip-check parse failed" end
    return data
end

local function ml_score(payload)
    local code, body = http.post_json(ML_HOST, ML_PORT, "/score", payload, ML_TIMEOUT)
    if code ~= 200 or not body then
        return nil, "ml /score failed: " .. tostring(body)
    end
    local data = cjson.decode(body)
    if not data then return nil, "ml /score parse failed" end
    return data
end

local function async_log(payload)
    local code, body = http.post_json(ML_HOST, ML_PORT, "/log-request", payload, LOG_TIMEOUT)
    if code ~= 200 then
        log(WARN, "decision_engine: log-request failed: ", tostring(body))
    end
end

-- ---------------------------------------------------------------------------
-- combined decision ladder
-- ---------------------------------------------------------------------------

local function combine(modsec_score, ml_score_val)
    if modsec_score >= 10 then
        return "BLOCK", string.format("modsec_score=%.1f >= 10 (critical)", modsec_score)
    end
    if modsec_score >= 5 and ml_score_val >= 0.5 then
        return "BLOCK", string.format("modsec=%.1f & ml=%.2f", modsec_score, ml_score_val)
    end
    if ml_score_val >= 0.8 then
        return "BLOCK", string.format("ml=%.2f >= 0.8", ml_score_val)
    end
    if ml_score_val >= 0.5 or modsec_score >= 3 then
        return "LOG", string.format("ml=%.2f modsec=%.1f", ml_score_val, modsec_score)
    end
    return "ALLOW", "below thresholds"
end

-- ---------------------------------------------------------------------------
-- main
-- ---------------------------------------------------------------------------

local function run()
    local method  = ngx.req.get_method()
    local uri     = ngx.var.request_uri or ngx.var.uri or "/"
    local ip      = client_ip()
    local headers = collect_headers()
    local body, truncated = collect_body()

    local req_hash = sha256_hex(method .. "|" .. uri .. "|" .. ip .. "|" .. (body or ""))

    -- (a) IP allow/block shortcut
    local ipinfo, ip_err = ip_check(ip)
    if ipinfo then
        if ipinfo.action == "BLOCK" then
            -- fire-and-forget log; the actual ML call is skipped
            -- Capture all needed functions and variables in closure
            local encoder = cjson
            local a_log = async_log
            ngx.timer.at(0, function()
                local payload = {
                    client_ip          = ip,
                    method             = method,
                    uri                = uri,
                    status_code        = 403,
                    modsec_score       = 0,
                    ml_score           = 0,
                    decision           = "BLOCK",
                    request_hash       = req_hash,
                    inference_ms       = 0,
                    has_attack_pattern = looks_attacky(uri .. " " .. (body or "")),
                    uri_length         = #uri,
                }
                a_log(encoder.encode(payload) or "{}")
            end)
            return respond_blocked(req_hash, "ip_rule:" .. (ipinfo.reason or ""), 0)
        elseif ipinfo.action == "ALLOW" then
            -- Explicit allowlist: skip ML, pass straight through.
            ngx.req.set_header("X-WAF-Decision", "ALLOW")
            ngx.req.set_header("X-WAF-IP-Rule",  ipinfo.reason or "allowlist")
            return
        end
    else
        log(WARN, "decision_engine: ", ip_err)
    end

    -- (b) ModSec score from header (set by rule 9000901)
    local modsec_score = tonumber(headers["x-modsec-score"]) or 0

    -- (c) ML score
    local ml_payload = cjson.encode({
        method    = method,
        uri       = uri,
        headers   = headers,
        body      = body or "",
        client_ip = ip,
    }) or "{}"

    local ml_score_val, inference_ms = 0.0, 0.0
    local ml_resp, ml_err = ml_score(ml_payload)
    if ml_resp then
        ml_score_val = tonumber(ml_resp.score) or 0
        inference_ms = tonumber(ml_resp.inference_ms) or 0
    else
        log(WARN, "decision_engine: ", ml_err)
        -- Fail safe (not fail open) for BLOCK paths: if ml is down we still
        -- honour a high modsec_score below. We DO NOT escalate to BLOCK on
        -- our own; ModSec is in enforcement mode and will have already
        -- blocked anything it considers critical.
    end

    -- (d) combine
    local decision, reason = combine(modsec_score, ml_score_val)

    -- (e) async log
    -- Capture all needed functions and variables in closure
    local encoder = cjson
    local a_log = async_log
    ngx.timer.at(0, function()
        local payload = {
            client_ip          = ip,
            method             = method,
            uri                = uri,
            status_code        = (decision == "BLOCK") and 403 or nil,
            modsec_score       = modsec_score,
            ml_score           = ml_score_val,
            decision           = decision,
            request_hash       = req_hash,
            inference_ms       = inference_ms,
            has_attack_pattern = looks_attacky(uri .. " " .. (body or "")),
            uri_length         = #uri,
        }
        a_log(encoder.encode(payload) or "{}")
    end)

    if decision == "BLOCK" then
        return respond_blocked(req_hash, reason, ml_score_val)
    end

    -- pass through, tagging the upstream-bound headers
    ngx.req.set_header("X-WAF-Decision", decision)
    ngx.req.set_header("X-WAF-Score",    tostring(ml_score_val))
    if decision == "LOG" then
        ngx.req.set_header("X-WAF-Reason", reason)
    end
end

local ok, err = pcall(run)
if not ok then
    -- Catastrophic Lua error: log and fail-OPEN for LOG/ALLOW class traffic.
    -- A blanket fail-closed would amplify any decision-engine bug into a
    -- site outage. Real attacks are still caught by ModSec (enforcement on).
    log(ERR, "decision_engine: unhandled error (fail-open): ", err)
end
