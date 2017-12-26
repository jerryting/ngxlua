> 主要目的是防止爬虫、恶意访问等，爬虫本身基本防不住，所以尽量让爬虫爬取时对服务器产生压力控制在带宽和服务器性能允许的范围，并且做一个动态黑名单的规则，比如永久或一段时间内拉黑某个ip、某个用户id，禁止其再访问服务器，即保证后端服务器不受影响，也保证正常用户不受影响。

> web服务器使用openresty，用它主要是出于nginx_lua模块灵活和便捷，当然使用原生nginx也可以，在安装的时候带上lua支持模块，另外 春哥的openresty里 有个限流分流的模块 [lua-resty-limit-traffic](https://github.com/openresty/lua-resty-limit-traffic) 如果想做限流分流，服务降级，灰度等等 这个模块确实也是可以用的，但是如果涉及到用户级别的缓存，比如用户ID有效性，宕机缓存失效等，所以改用redis 做缓存，没有用官方提供的模块。

> 运行环境：centos + openresty + lua + redis (安装略)

> openresty/nginx配置：

```
对访问本机x-service的所有请求，请求到达时执行access_limit.lua脚本，进行限流检查
location /x-service {
            lua_code_cache on; #代码缓存，如果nginx -s reload 失效，最好执行以下 stop 再启动
            access_by_lua_file /usr/local/openresty-1.13.6.1/mylua/access_limit.lua; # 限流脚本入口
            proxy_pass http://server_ups/x-service-web;
            proxy_set_header  X-Real-IP  $remote_addr;
            proxy_set_header  Host       $http_host;
        }
```

> ***lua_utils.lua*** 提供获取客户端ip公共方法

```
local _M = {}

function _M.new(self)
	return self
end
--获取客户端IP
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
```
> ***redispool.lua*** 提供redis连接池

```
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
    self:set_keepalive(120000, 50) --50个连接，每个120秒保活
end

return _M
```
> ***ip_limit.lua*** 全局IP限制：例如单IP对本机该服务的所有访问次数达到200次，则拉黑该IP，封禁24小时，24小时候自动解封
(如果你觉得代理ip一抓一大把，那这个脚本确实没啥大用，你可以考虑限制ua、固定访问header等)

```
package.path  = '/usr/local/openresty-1.13.6.1/mylua/?.lua;;' .. package.path

local ttl_timespan_s = 86400  			--封禁时长
local ip_check_timespan_s = 86400    	--检查步长
local access_threshold_count = 200 		--访问频率计数阈值
local error_status = 403

local key_prefix_isdeny = "globalipfreq_isdeny_"
local key_prefix_stime = "globalipfreq_stime_"
local key_prefix_count = "globalipfreq_count_"

local _M = {}

function _M.new(self)
	return self
end

function _M.check_ip_freq(self)
	local utils = require "lua_utils"
	local client_ip = utils.get_clientip()

	local rds_key = client_ip

	--获取redis连接
	local redis = require "redispool"
	local rds = redis.new()
	--如果连接失败、redis丢失服务等 按无限制操作
	if not rds then
		return 1
	end
	--查询ip是否在封禁段内，若在则返回http错误码
	--封禁时间段内不再对ip时间和计数做处理
	local is_deny , err = rds:get(key_prefix_isdeny..rds_key)
	if tonumber(is_deny) == 1 then
		ngx.log(ngx.ERR,"globalipfreq_deny ","ip: "..rds_key.." : deny timespan : "..ttl_timespan_s)
		rds:close()
		return error_status
	end

	local start_time , err = rds:get(key_prefix_stime..rds_key)
	local count , err = rds:get(key_prefix_count..rds_key)
	--如果ip记录时间大于指定时间间隔或者记录时间不存在,则初始化记录时间、计数
	--如果IP访问的时间间隔小于约定的时间间隔，则ip计数正常加1，且如果ip计数大于约定阈值，则设置ip的封禁key为1,即将此IP拉黑 ,同时设置封禁IP的数据过期时间
	if start_time == ngx.null or (os.time() - start_time) >= ip_check_timespan_s then
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
			if count >= access_threshold_count then
				res , err = rds:set(key_prefix_isdeny..rds_key,1)
				res , err = rds:expire(key_prefix_isdeny..rds_key,ttl_timespan_s)
				ngx.log(ngx.ERR,"globalipfreq_deny ","ip: "..rds_key.." : deny timespan : "..ttl_timespan_s)
				rds:close()
				return error_status
			end
		end
		rds:close()
	end
end

return _M
```
> ***uid_limit.lua*** 对用户ID限制: 针对业务接口比如/api/detail/接口的限制，比如一天内 同一个UID只能访问25次，超过25次立即封禁，限制服务24h，24h后自动解封
(如果多个规则组合判断，能判断到确实是一个爬虫或者恶意访问就直接永久封禁，当然规则要兼顾很多地方，我这里采用一刀切的方式，后面有时间再慢慢补充，让整个规则更符合业务需要)

```
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
	local uiddata,err = rds:get(key_prefix_uid..uid) --用户的ID需要提前预热到redis，批量操作+ 动态增加的方式
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
```
> ***access_limit.lua*** 入口

```
package.path  = '/usr/local/openresty-1.13.6.1/mylua/?.lua;;' .. package.path
--白名单IP ,放入redis也可以，如果图方便直接写也可以，毕竟白单不会太多
local ipTable = "11.25.17.18"

local utils = require "lua_utils"
local clientip = utils.get_clientip()

local uidLimit = require "uid_limit"
local uidL = uidLimit:new()

local ipLimit = require "ip_limit"
local iplimit = ipLimit:new()

if not string.find(ipTable,clientip) then --白单过滤
	--单IP单uid固定接口 组合限制
	--当某一uid被限流时尽量不影响该IP内的其他用户
	local ok1 = uidL.check_uid_freq()
	if ok1 and ok1 ~= 1 then
		ngx.exit(ok1)
	end
	--单IP全局限流检查
	local ok = iplimit.check_ip_freq()
	if ok and ok ~= 1 then
		ngx.exit(ok)
	end
end
```
Enjoy!!!
