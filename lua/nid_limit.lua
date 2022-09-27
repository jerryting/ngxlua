package.path = '/usr/local/openresty-1.13.6.1/mylua/?.lua;;' .. package.path

local ttl_timespan_s = 86400 -- 封禁时长
local nid_check_timespan_s = 86400 -- 检查步长
local access_threshold_count = 25 -- 访问频率计数阈值
local error_status = 403

local key_prefix_isdeny = "ngx:nidfreq:isdeny:"
local key_prefix_stime = "ngx:nidfreq:stime:"
local key_prefix_count = "ngx:nidfreq:count:"
local key_prefix_nid = "ngx:nid:"

local _M = {}

function _M.new(self)
    return self
end

function _M.check_nid_freq(self)
    -- 只针对指定接口做限流
    local uri = ngx.var.uri
    if not string.find(uri, "/api/doctor/") then
        return 1
    end

    local headers = ngx.req.get_headers()
    local uid = tonumber(headers["mxuid"])
    local nid = tonumber(headers["mxnid"])
    if not uid then
        uid = 0
    end
    if not nid then
        nid = 0
    end

    if nid <= 0 and uid <= 0 then
        return error_status
    elseif uid > 0 then
        return 1
    end

    local rds_key = nid
    -- if not nid then
    -- 	return error_status
    -- end
    -- 连接redis
    local redis = require "redispool"
    local rds = redis.new()
    -- 如果连接失败、redis丢失服务等 按无限制操作
    if not rds then
        return 1
    end
    -- nid有效性验证 非法用户直接拒绝访问
    local niddata, err = rds:get(key_prefix_nid .. nid)
    if niddata == ngx.null then
        return error_status
    end
    -- 查询是否在封禁段内，若在则返回错误码
    -- 因封禁时间会大于记录时间，故此处不对时间key和计数key做处理
    local is_deny, err = rds:get(key_prefix_isdeny .. rds_key)
    if tonumber(is_deny) == 1 then
        ngx.log(ngx.ERR, "nidfreq_deny ", "ip: " .. rds_key .. " : deny timespan : " .. ttl_timespan_s)
        rds:close()
        return error_status
    end

    local start_time, err = rds:get(key_prefix_stime .. rds_key)
    local count, err = rds:get(key_prefix_count .. rds_key)
    -- 如果记录时间大于指定时间间隔或者记录时间不存在,则重置记录时间、计数归1
    -- 如果访问的时间间隔小于约定的时间间隔，则计数正常+1，且如果计数大于约定阈值，则设置封禁标识为1,即将此ID拉黑
    -- 同时设置封禁的数据过期时间
    if start_time == ngx.null or (os.time() - start_time) >= nid_check_timespan_s then
        res, err = rds:set(key_prefix_stime .. rds_key, os.time())
        rds:expire(key_prefix_stime .. rds_key, ttl_timespan_s)
        res, err = rds:set(key_prefix_count .. rds_key, 1)
        rds:expire(key_prefix_count .. rds_key, ttl_timespan_s)
        rds:close()
        return 1
    else
        if count == ngx.null then
            rds:set(key_prefix_count .. rds_key, 1)
            rds:expire(key_prefix_count .. rds_key, ttl_timespan_s)
        else
            count = count + 1
            res, err = rds:incr(key_prefix_count .. rds_key)
            ngx.log(ngx.ERR, "inc.....", "" .. nid)
            if count >= access_threshold_count then
                res, err = rds:set(key_prefix_isdeny .. rds_key, 1)
                res, err = rds:expire(key_prefix_isdeny .. rds_key, ttl_timespan_s)
                ngx.log(ngx.ERR, "nidfreq_deny ", "ip: " .. rds_key .. " : deny timespan : " .. ttl_timespan_s)
                rds:close()
                return error_status
            end
        end
        rds:close()
    end
end

return _M
