---@summary: ip 限流 - 计数器算法
---@author: jerry.D 2017-12-26
---@since: v1
---@modified: jerry.D 2022-08-27
-- package.path = '/usr/local/data/trt_svncodes/lua-ratelimiter/?.lua;' .. package.path

-- local ttl_timespan_s = 60 -- 封禁时长
-- local ip_check_timespan_s = 60 -- 检查步长
-- local access_threshold_count = 5 -- 访问频率计数阈值

local ttl_timespan_s = 86400 -- 封禁时长
local ip_check_timespan_s = 86400 -- 检查步长
local access_threshold_count = 200 -- 访问频率计数阈值



local error_status = 403

local key_prefix_isdeny = "ngx:globalipfreq:isdeny:"
local key_prefix_stime = "ngx:globalipfreq:stime:"
local key_prefix_count = "ngx:globalipfreq:count:"

local _M = {}

function _M.new(self)
    return self
end

function _M.check_ip_freq(self)
    local utils = require "lua_utils"
    local client_ip = utils.get_clientip()

    local rds_key = client_ip

    -- 连接redis
    local redis = require "redispool"
    local rds = redis.new()
    -- 如果连接失败、redis丢失服务等 按无限制操作
    if not rds then
        return 1
    end
    -- 查询ip是否在封禁段内，若在则返回http错误码
    -- 封禁时间段内不再对ip时间和计数做处理
    local is_deny, err = rds:get(key_prefix_isdeny .. rds_key)
    if tonumber(is_deny) == 1 then
        ngx.log(ngx.ERR, "globalipfreq_deny ", "ip: " .. rds_key .. " : deny timespan : " .. ttl_timespan_s)
        rds:close()
        return error_status
    end

    local start_time, err = rds:get(key_prefix_stime .. rds_key)
    if start_time == nil or start_time == ngx.null then
        start_time = 0
    end
    local count, err = rds:get(key_prefix_count .. rds_key)
    -- 如果ip记录时间大于指定时间间隔或者记录时间不存在,则初始化记录时间、计数
    -- 如果IP访问的时间间隔小于约定的时间间隔，则ip计数正常加1，且如果ip计数大于约定阈值，则设置ip的封禁key为1,即将此IP拉黑 ,同时设置封禁IP的数据过期时间
    if start_time == 0 or count == nil or (os.time() - start_time) >= ip_check_timespan_s then
        res, err = rds:set(key_prefix_stime .. rds_key, os.time())
        rds:expire(key_prefix_stime .. rds_key, ttl_timespan_s)
        res, err = rds:set(key_prefix_count .. rds_key, 1)
        rds:expire(key_prefix_count .. rds_key, ttl_timespan_s)
        rds:close()
        return 1
    else
        res_cnt, err = rds:incr(key_prefix_count .. rds_key)
        if res_cnt >= access_threshold_count then
            res, err = rds:set(key_prefix_isdeny .. rds_key, 1)
            res, err = rds:expire(key_prefix_isdeny .. rds_key, ttl_timespan_s)
            ngx.log(ngx.ERR, "globalipfreq_deny ", "ip: " .. rds_key .. " : deny timespan : " .. ttl_timespan_s)
            rds:close()
            return error_status
        end
        rds:close()
    end
end

return _M
