---本地emmylua(vscode)插件调试使用
---emmylua new Debugger
-- package.cpath = package.cpath .. ';/Users/jerry/.vscode/extensions/tangzx.emmylua-0.5.10/debugger/emmy/mac/x64/?.dylib'
-- local dbg = require('emmy_core')
-- dbg.tcpConnect('localhost', 9966)
---emmylua new Debugger

-- 每次脚本执行都会重复放path 避免使用
-- package.path = '/usr/local/data/trt_svncodes/lua-ratelimiter/?.lua;;' .. package.path

-- 白名单IP
local ipTable = "103.85.172.190,"
-- 工具
local utils = require "lua_utils"
local clientip = utils.get_clientip()

-- 按uid(header设定)
local uidLimit = require "uid_limit"
local uidL = uidLimit:new()
-- 全局ip
local ipLimit = require "ip_limit"
local iplimit = ipLimit:new()
-- 匿名用户(header设定)
local nidLimit = require "nid_limit"
local nidL = nidLimit:new()

if not string.find(ipTable, clientip) then -- 白单过滤
    -- 单IP单uid固定接口 组合限制
    -- 当某一uid被限流时尽量不影响该IP内的其他用户

    -- local ok1 = uidL.check_uid_freq()
    -- if ok1 and ok1 ~= 1 then
    --     ngx.exit(ok1)
    -- end

    -- 游客nid限流 (仿uid限流)
    -- local ok2 = nidL.check_nid_freq()
    -- if ok2 and ok2 ~= 1 then
    -- 	ngx.exit(ok2)
    -- end

    -- local headers = ngx.req.get_headers()
    -- local uid = headers["mxuid"]
    -- local nid = headers["mxnid"]
    -- if uid then
    -- 	ngx.log(ngx.ERR,"number ","uid: "..tonumber(uid))
    -- end

    -- if nid then
    -- 	ngx.log(ngx.ERR,"number "," nid: "..tonumber(nid))
    -- end
    -- 单IP全局限流检查
    -- ngx.log(ngx.ERR, package.path)

    local ok = iplimit.check_ip_freq()
    if ok and ok ~= 1 then
        -- 按httpcode返回
        -- ngx.exit(ok)

        -- 按内容返回
        ngx.header["Content-type"] = 'text/html'
        ngx.say('<html><br><br><br><br><br><center>' .. ok .. ' u r robot !?' .. '</center></html>')
    end
end
