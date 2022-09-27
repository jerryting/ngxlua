---emmylua new Debugger
-- package.cpath = package.cpath .. ';C:/Users/win/.vscode/extensions/tangzx.emmylua-0.5.3/debugger/emmy/windows/x86/?.dll'
package.cpath = package.cpath .. ';/Users/jerry/.vscode/extensions/tangzx.emmylua-0.5.10/debugger/emmy/mac/x64/?.dylib'
local dbg = require('emmy_core')
dbg.tcpConnect('localhost', 9966)
---emmylua new Debugger

ngx.log(ngx.ERR, 'sdfsfsfsdfsf')
-- local uri = ngx.var.uri
local a = "hello world"
ngx.exit(1)

print(a)
