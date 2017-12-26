local redis = require "resty.redis"

local config = {
	host = "127.0.0.1",
    port = 6379,
    password = "password"
}

local _M = {}

--获取redis连接
function _M.new(self)
    local red = redis:new()
    red:set_timeout(1000) -- one second timeout
    local res = red:connect(config['host'], config['port'])
    if not res then
        return nil
    end
    if config['password'] ~= nil then
		res = red:auth(config['password'])
	    if not res then
	        return nil
	    end
    end
    red.close = close
    return red
end
--归还连接到连接池 以备复用
function close(self)
    self:set_keepalive(120000, 50)
end

return _M