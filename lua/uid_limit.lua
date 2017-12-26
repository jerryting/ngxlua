package.path  = '/usr/local/openresty-1.13.6.1/mylua/?.lua;;' .. package.path

local ttl_timespan_s = 86400  			--封禁时长
local uid_check_timespan_s = 86400    	--检查步长
local access_threshold_count = 25 		--访问频率计数阈值
local error_status = 403

local key_prefix_isdeny = "uidfreq_isdeny_"
local key_prefix_stime = "uidfreq_stime_"
local key_prefix_count = "uidfreq_count_"
local key_prefix_uid = "UID_"

local _M = {}

function _M.new(self)
	return self
end

function _M.check_uid_freq(self)
	--只针对指定接口做限流,其他接口放行
	local uri = ngx.var.uri
	if not string.find(uri,"/api/detail/") then
		return 1
	end
	--获取用户id
	local uid = ngx.var.arg_uid
	local rds_key = uid
	if not uid then
		return error_status
	end
	--连接redis
	local redis = require "redispool"
	local rds = redis.new()
	--如果连接失败、redis丢失服务等 按无限制操作
	if not rds then
		return 1
	end
	--UID有效性验证 非法用户直接拒绝访问
	local uiddata,err = rds:get(key_prefix_uid..uid)
	if uiddata == ngx.null then
		return error_status
	end
	--查询是否在封禁段内，若在则返回错误码
	--因封禁时间会大于记录时间，故此处不对时间key和计数key做处理
	local is_deny , err = rds:get(key_prefix_isdeny..rds_key)
	if tonumber(is_deny) == 1 then
		ngx.log(ngx.ERR,"uidfreq_deny ","ip: "..rds_key.." : deny timespan : "..ttl_timespan_s)
		rds:close()
		return error_status
	end

	local start_time , err = rds:get(key_prefix_stime..rds_key)
	local count , err = rds:get(key_prefix_count..rds_key)
	--如果记录时间大于指定时间间隔或者记录时间不存在,则重置记录时间、计数归1
	--如果访问的时间间隔小于约定的时间间隔，则计数正常+1，且如果计数大于约定阈值，则设置封禁标识为1,即将此ID拉黑
	--同时设置封禁的数据过期时间
	if start_time == ngx.null or (os.time() - start_time) >= uid_check_timespan_s then
		res , err = rds:set(key_prefix_stime..rds_key , os.time())
		rds:expire(key_prefix_stime..rds_key,ttl_timespan_s)
		res , err = rds:set(key_prefix_count..rds_key , 1)
		rds:expire(key_prefix_count..rds_key,ttl_timespan_s)
		rds:close()
		return 1
	else
		if count == ngx.null then
			rds:set(key_prefix_count..rds_key , 1)
			rds:expire(key_prefix_count..rds_key,ttl_timespan_s)
		else
			count = count + 1
			res , err = rds:incr(key_prefix_count..rds_key)
			ngx.log(ngx.ERR,"inc.....",""..uid)
			if count >= access_threshold_count then
				res , err = rds:set(key_prefix_isdeny..rds_key,1)
				res , err = rds:expire(key_prefix_isdeny..rds_key,ttl_timespan_s)
				ngx.log(ngx.ERR,"uidfreq_deny ","ip: "..rds_key.." : deny timespan : "..ttl_timespan_s)
				rds:close()
				return error_status
			end
		end
		rds:close()
	end
end

return _M