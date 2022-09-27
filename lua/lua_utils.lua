local _M = {}

function _M.new(self)
    return self
end

function _M.get_clientip(self)
    local client_ip = ngx.req.get_headers()["X-Real-IP"]
    if client_ip == nil then
        client_ip = ngx.req.get_headers()["x_forwarded_for"]
    end

    if client_ip == nil then
        client_ip = ngx.var.remote_addr
    end
    return client_ip
end

return _M
