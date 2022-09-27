local redis = require "resty.redis"

local config = {
    host = "172.24.32.7" or "127.0.0.1",
    port = 6379 or 6379,
    password = "e0rAZ%LP" or "adongta123",
    database = 12 or 0
}

local rds = nil
local _M = {}

-- 获取redis连接
function _M.new(self)
    -- if rds ~= nil then
    --     return rds
    -- end
    
    -- 连接
    local red = redis:new()
    red:set_timeout(1000) -- one second timeout
    local res = red:connect(config['host'], config['port'])
    if not res then
        return nil
    end
    -- 鉴权
    if config['password'] ~= nil then
        res = red:auth(config['password'])
        if not res then
            return nil
        end
    end

    -- select db
    red:select(config['database'])

    red.close = close
    rds = red
    return rds
end
-- 归还连接到连接池 以备复用
function close(self)
    self:set_keepalive(120000, 50)
end

return _M
