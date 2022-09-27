-----@author
package.path = '/opt/verynginx/openresty/mylua/?.lua;;' .. package.path

local ipuid_deny_timespan_s = 86400 -- 封禁时长
local ipuid_check_timespan_s = 86400 -- 检查步长
local access_threshold_count = 25 -- 指定访问频率计数最大值
local error_status = 403

local key_prefix_ipuidfreq_isdeny = "ngx:ipuidfreq:isdeny:"
local key_prefix_ipuidfreq_count = "ngx:ipuidfreq:count:"
local key_prefix_ipuidfreq_stime = "ngx:ipuidfreq:stime:"

local _M = {}

function _M.new(self)
    return self
end

function _M.check_ip_uid_freq(self)
    local utils = require "lua_utils"
    local client_ip = utils.get_clientip()
    -- 针对某些接口做限流
    local uri = ngx.var.uri
    ngx.log(ngx.ERR, "xxxxxxx", "-------" .. ngx.header.mxuid .. "----" .. ngx.header.mxnid)
    if not string.find(uri, "/api/doctor/") then
        return 1
    end
    -- 获取用户id
    local uid = ngx.var.arg_uid
    local rds_key = client_ip
    if uid then
        rds_key = rds_key .. "_" .. uid
    end
    -- 连接redis
    local redis = require "redispool"
    local rds = redis.new()
    -- 如果连接失败、redis丢失服务等 按无限制操作
    if not rds then
        return 1
    end
    -- 查询ip是否在封禁段内，若在则返回403错误代码
    -- 因封禁时间会大于ip记录时间，故此处不对ip时间key和计数key做处理
    local is_deny, err = rds:get(key_prefix_ipuidfreq_isdeny .. rds_key)
    if tonumber(is_deny) == 1 then
        ngx.log(ngx.ERR, "ipuidfreq_deny ", "ip: " .. rds_key .. " : deny timespan : " .. ipuid_deny_timespan_s)
        rds:close()
        return error_status
    end

    local start_time, err = rds:get(key_prefix_ipuidfreq_stime .. rds_key)
    local ip_count, err = rds:get(key_prefix_ipuidfreq_count .. rds_key)
    -- 如果ip记录时间大于指定时间间隔或者记录时间不存在,则重置记录时间、基数归1
    -- 如果IP访问的时间间隔小于约定的时间间隔，则ip计数正常+1，且如果ip计数大于约定阈值，则设置ip的封禁key为1,即将此IP拉黑
    -- 同时设置封禁IP的数据过期时间
    if start_time == ngx.null or (os.time() - start_time) >= ipuid_check_timespan_s then
        res, err = rds:set(key_prefix_ipuidfreq_stime .. rds_key, os.time())
        res, err = rds:set(key_prefix_ipuidfreq_count .. rds_key, 1)
        rds:close()
        return 1
    else
        if ip_count == ngx.null then
            rds:set(key_prefix_ipuidfreq_count .. rds_key, 1)
        else
            ip_count = ip_count + 1
            res, err = rds:incr(key_prefix_ipuidfreq_count .. rds_key)
            if ip_count >= access_threshold_count then
                res, err = rds:set(key_prefix_ipuidfreq_isdeny .. rds_key, 1)
                res, err = rds:expire(key_prefix_ipuidfreq_isdeny .. rds_key, ipuid_deny_timespan_s)
                ngx.log(ngx.ERR, "ipuidfreq_deny ", "ip: " .. rds_key .. " : deny timespan : " .. ipuid_deny_timespan_s)
                rds:close()
                return error_status
            end
        end
        rds:close()
    end
end

return _M
