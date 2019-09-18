-- https://github.com/ledgetech/lua-resty-http
local http          = require("resty.http")
local typeof        = require("typeof")
local encode_args   = ngx.encode_args
local clear_tab     = require "table.clear"
local tab_nkeys     = require "table.nkeys"
local split         = require "ngx.re" .split
local concat_tab    = table.concat
local tostring      = tostring
local select        = select
local ipairs        = ipairs


local _M = {}


local content_type = {
    ["Content-Type"] = "application/x-www-form-urlencoded",
}

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


local ngx_log = ngx.log
local ngx_ERR = ngx.ERR
local ngx_INFO = ngx.INFO
local function log_error(...)
    return ngx_log(ngx_ERR, ...)
end
_M.log_error = log_error


local function log_info( ... )
    return ngx_log(ngx_INFO, ...)
end
_M.log_info = log_info


local function request_uri(self, method, uri, opts, timeout)
    local body
    if opts and opts.body and tab_nkeys(opts.body) > 0 then
        body = self.encode_json(opts.body) --encode_args(opts.body)
    end

    if opts and opts.query and tab_nkeys(opts.query) > 0 then
        uri = uri .. '?' .. encode_args(opts.query)
    end

    local http_cli, err = http.new()
    if err then
        return nil, err
    end

    if timeout then
        http_cli:set_timeout(timeout * 1000)
    end

    log_info('uri:', uri, ' body:', body)

    local res
    res, err = http_cli:request_uri(uri, {
        method = method,
        body = body,
        headers = content_type,
    })

    if err then
        return nil, err
    end

    log_info('res body:', res.body, 'status:', res.status)

    if res.status >= 500 then
        return nil, "invalid response code: " .. res.status
    end

    if not typeof.string(res.body) then
        return res
    end

    res.body = self.decode_json(res.body)
    return res
end

_M.request_uri = request_uri


local function request_chunk(self, method, host, port, path, opts, timeout)
    local body
    if opts and opts.body and tab_nkeys(opts.body) > 0 then
        body = self.encode_json(opts.body) --encode_args(opts.body)
    end

    local query
    if opts and opts.query and tab_nkeys(opts.query) > 0 then
        query = encode_args(opts.query)
    end

    local http_cli, err = http.new()
    if err then
        return nil, err
    end

    local ok, _
    if timeout then
        _, err = http_cli:set_timeout(timeout * 1000)
        if err then
            return nil, err
        end
    end

    ok, err = http_cli:connect(host, port)
    if not ok then
        return nil, err
    end

    local res
    res, err = http_cli:request({
        method = method,
        path   = path,
        body   = body,
        query  = query,
    })
    log_info("http request method: ", method, " path: ", path,
             " body: ", body, " query: ", query)

    if not res then
        return nil, err
    end

    return function()
        return res.body_reader()
    end
end
_M.request_chunk = request_chunk


return _M
