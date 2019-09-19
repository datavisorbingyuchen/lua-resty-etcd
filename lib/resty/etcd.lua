-- https://github.com/ledgetech/lua-resty-http
local http          = require("resty.http")
local typeof        = require("typeof")
local cjson         = require("cjson.safe")
local encode_args   = ngx.encode_args
local setmetatable  = setmetatable
local clear_tab     = require "table.clear"
local tab_nkeys     = require "table.nkeys"
local split         = require "ngx.re" .split
local concat_tab    = table.concat
local tostring      = tostring
local select        = select
local ipairs        = ipairs
local type          = type


local _M = {
    decode_json = cjson.decode,
    encode_json = cjson.encode,
}
local mt = { __index = _M }


local ngx_log = ngx.log
local ngx_ERR = ngx.ERR
local function log_error(...)
    return ngx_log(ngx_ERR, ...)
end


local normalize
do
    local items = {}
    local function concat(sep, ...)
        local argc = select('#', ...)
        clear_tab(items)
        local len = 0

        for i = 1, argc do
            local v = select(i, ...)
            if v ~= nil then
                len = len + 1
                items[len] = tostring(v)
            end
        end

        return concat_tab(items, sep);
    end


    local segs = {}
    function normalize(...)
        local path = concat('/', ...)
        local names = {}
        local err

        segs, err = split(path, [[/]], "jo", nil, nil, segs)
        if not segs then
            return nil, err
        end

        local len = 0
        for _, seg in ipairs(segs) do
            if seg == '..' then
                if len > 0 then
                    len = len - 1
                end

            elseif seg == '' or seg == '/' and names[len] == '/' then
                -- do nothing

            elseif seg ~= '.' then
                len = len + 1
                names[len] = seg
            end
        end

        return '/' .. concat_tab(names, '/', 1, len);
    end
end
_M.normalize = normalize


function _M.new(opts)
    if opts == nil then
        opts = {}

    elseif not typeof.table(opts) then
        return nil, 'opts must be table'
    end

    local timeout = opts.timeout or 5000    -- 5 sec
    local http_host = opts.host or "http://127.0.0.1:2379"
    local ttl = opts.ttl or -1
    local prefix = opts.prefix or "/v2/keys"

    if not typeof.uint(timeout) then
        return nil, 'opts.timeout must be unsigned integer'
    end

    if not typeof.string(http_host) then
        return nil, 'opts.host must be string'
    end

    if not typeof.int(ttl) then
        return nil, 'opts.ttl must be integer'
    end

    if not typeof.string(prefix) then
        return nil, 'opts.prefix must be string'
    end

    return setmetatable({
            timeout = timeout,
            ttl = ttl,
            endpoints = {
                full_prefix = http_host .. normalize(prefix),
                http_host = http_host,
                prefix = prefix,
                version = '/version',
                stats_leader = '/v2/stats/leader',
                stats_self = '/v2/stats/self',
                stats_store = '/v2/stats/store',
                keys = '/v2/keys',
            }
        },
        mt)
end

local content_type = {
    ["Content-Type"] = "application/x-www-form-urlencoded",
}


local function _request(self, method, key, body, query)
    key = normalize(key)
    if key == '/' then
        return nil, "key should not be a slash"
    end

    local opts = {}

    local req_body = nil
    if body and tab_nkeys(body) > 0 then
        req_body = encode_args(body)
    end

    local uri = self.endpoints.http_host .. key
    if query and tab_nkeys(query) > 0 then
        uri = uri .. '?' .. encode_args(query)
    end

    local http_cli, err = http.new()
    if err then
        return nil, err
    end

    http_cli:set_timeout(self.timeout)

    local res, err = http_cli:request_uri(uri, {
        method = method,
        body = req_body,
        headers = content_type,
    })

    if err then
        return nil, err
    end

    if res.status >= 500 then
        return nil, "invalid response code: " .. res.status
    end

    local res_body, err = self.decode_json(res.body)
    if err then
        return nil, "invalid response body: " .. res.body
    end
    return res_body, nil
end

-- /version
function _M.version(self)
    return _request(self, 'GET', self.endpoints.version)
end

-- /stats
function _M.stats_leader(self)
    return _request(self, 'GET', self.endpoints.stats_leader)
end

function _M.stats_self(self)
    return _request(self, 'GET', self.endpoints.stats_self)
end

function _M.stats_store(self)
    return _request(self, 'GET', self.endpoints.stats_store)
end

function _M.get(self, key, recursive)
    local query = {}
    if recursive ~= nil then
        query["recursive"] = tostring(recursive)
    end
    return _request(self, 'GET', self.endpoints.prefix .. key, nil, query)
end

function _M.wait(self, key, waitIndex, recursive)
    local query = {}
    if recursive ~= nil then
        query["recursive"] = tostring(recursive)
    end
    query["waitIndex"] = waitIndex
    query["wait"] = "true"

    return _request(self, 'GET', self.endpoints.prefix .. key, nil, query)
end

function _M.set(self, key, val, ttl)
    return _request(self, 'PUT', self.endpoints.prefix .. key, {value = val, ttl = ttl})
end

function _M.refresh(self, key, ttl)
    return _request(self, 'PUT', self.endpoints.prefix .. key, {refresh = "true", ttl = ttl})
end

return _M
