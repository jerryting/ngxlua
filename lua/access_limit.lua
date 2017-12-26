package.path  = '/usr/local/openresty-1.13.6.1/mylua/?.lua;;' .. package.path
--白名单IP
local ipTable = "111.205.187.18"

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