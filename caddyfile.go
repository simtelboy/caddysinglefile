package forwardproxy

import (
	"encoding/base64" // 用于Base64编码
	"log"

	//"log"     // 用于日志记录
	"strconv" // 用于字符串到整数的转换
	"strings" // 用于字符串操作
	"time"

	caddy "github.com/caddyserver/caddy/v2"                     // Caddy服务器的模块
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"     // Caddyfile配置解析模块
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile" // HTTP Caddyfile配置解析模块
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"         // Caddy HTTP模块
)

// init函数在包初始化时调用，用于注册forward_proxy指令
func init() {
	httpcaddyfile.RegisterHandlerDirective("forward_proxy", parseCaddyfile)
}

// parseCaddyfile函数用于解析Caddyfile中的forward_proxy指令
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var fp Handler                            // 声明Handler变量
	err := fp.UnmarshalCaddyfile(h.Dispenser) // 解析Caddyfile
	return &fp, err                           // 返回Handler实例和错误
}

// EncodeAuthCredentials base64-encode credentials
// EncodeAuthCredentials函数用于Base64编码认证凭据
func EncodeAuthCredentials(user, pass string) (result []byte) {
	raw := []byte(user + ":" + pass)                               // 拼接用户名和密码
	result = make([]byte, base64.StdEncoding.EncodedLen(len(raw))) //创建结果切片
	base64.StdEncoding.Encode(result, raw)                         //编码
	return
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
// 用于将Caddyfile的token反序化到Handle结构体
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		//如果没有下一个toKen,则返回错误
		return d.ArgErr()
	}

	//获取剩余的参数
	args := d.RemainingArgs()
	if len(args) > 0 {
		//如果没有参数，则返回错误
		return d.ArgErr()
	}

	//-----------hotyi------------------------

	if h.userManager == nil {
		h.userManager = h.GetUserUserManager()
	}

	// 初始化全局 UserConfig
	if h.globalUserConfig == nil {
		h.globalUserConfig = GetUserConfig()
	}

	//globalUserConfig.mu.Lock()
	//defer globalUserConfig.mu.Unlock()
	//-----------------------------------------

	//循环处理所有的block
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		//获取子指令
		subdirective := d.Val()
		//获取子指令的参数
		args := d.RemainingArgs()
		switch subdirective {
		//处理basic_auth子指令
		case "basic_auth":

			//-----------hotyi-----------------------
			var username, password string
			var expiry time.Time
			var err error

			if len(args) < 2 {
				return d.ArgErr()
			}

			username = args[0]
			password = args[1]

			if len(username) == 0 {
				return d.Err("empty usernames are not allowed")
			}
			// TODO: Evaluate policy of allowing empty passwords.
			//检查用户名中是否含有非法字符
			if strings.Contains(username, ":") {
				return d.Err("character ':' in usernames is not allowed")
			}

			h.globalUserConfig.mu.Lock()

			//限制ip登录数
			if len(args) > 2 {
				ipLimit, err := strconv.Atoi(args[2])
				if err == nil {
					h.globalUserConfig.userIPLimits[username] = ipLimit
				}
			}

			//限制时间
			if len(args) > 3 {
				expiry, err = time.Parse(time.RFC3339, args[3])
				if err != nil {
					return d.Err("invalid expiry date format")
				}
				h.globalUserConfig.userExpiry[username] = expiry
			}
			h.globalUserConfig.mu.Unlock()

			//编码认证凭据并添加到列表
			if h.AuthCredentials == nil {
				h.AuthCredentials = [][]byte{}
			}
			h.AuthCredentials = append(h.AuthCredentials, EncodeAuthCredentials(username, password))
			//--------------------------------------------------
		//处理hosts子指令
		case "hosts":
			//验证参数数量并设置Hosts字段
			if len(args) == 0 {
				return d.ArgErr()
			}
			if len(h.Hosts) != 0 {
				return d.Err("hosts subdirective specified twice") //hosts 子指令指定两次
			}
			h.Hosts = caddyhttp.MatchHost(args)
		//处理ports子指令
		case "ports":
			//验证参数数量并设置AllowedPorts字段
			if len(args) == 0 {
				return d.ArgErr()
			}
			if len(h.AllowedPorts) != 0 {
				return d.Err("ports subdirective specified twice")
			}
			h.AllowedPorts = make([]int, len(args))
			for i, p := range args {
				//转换端口号并验证范围
				intPort, err := strconv.Atoi(p)
				if intPort <= 0 || intPort > 65535 || err != nil {
					return d.Errf("ports are expected to be space-separated and in 0-65535 range, but got: %s", p)
				}
				h.AllowedPorts[i] = intPort
			}
		//处理hide_ip子指令
		case "hide_ip":
			//设置HideIP字段
			if len(args) != 0 {
				return d.ArgErr()
			}
			h.HideIP = true
			//处理hide_via子指令
		case "hide_via":
			//设置Hidevia字段
			if len(args) != 0 {
				return d.ArgErr()
			}
			h.HideVia = true
			//处理probe_resistance子指令
		case "probe_resistance":
			//设置probe_resistance字段
			if len(args) > 1 {
				return d.ArgErr()
			}
			if len(args) == 1 {
				//警告大写字母
				lowercaseArg := strings.ToLower(args[0])
				if lowercaseArg != args[0] {
					log.Println("[WARNING] Secret domain appears to have uppercase letters in it, which are not visitable")
				}
				h.ProbeResistance = &ProbeResistance{Domain: args[0]}
			} else {
				h.ProbeResistance = &ProbeResistance{}
			}
			//处理serve_pac子指令
		case "serve_pac":
			// 设置PACPath字段
			if len(args) > 1 {
				return d.ArgErr()
			}
			if len(h.PACPath) != 0 {
				return d.Err("serve_pac subdirective specified twice")
			}
			if len(args) == 1 {
				h.PACPath = args[0]
				if !strings.HasPrefix(h.PACPath, "/") {
					h.PACPath = "/" + h.PACPath
				}
			} else {
				h.PACPath = "/proxy.pac"
			}
			// 处理dial_timeout子指令
		case "dial_timeout":
			// 设置DialTimeout字段
			if len(args) != 1 {
				return d.ArgErr()
			}
			timeout, err := caddy.ParseDuration(args[0])
			if err != nil {
				return d.ArgErr()
			}
			if timeout < 0 {
				return d.Err("dial_timeout cannot be negative.")
			}
			h.DialTimeout = caddy.Duration(timeout)
			// 处理upstream子指令
		case "upstream":
			// 设置Upstream字段
			if len(args) != 1 {
				return d.ArgErr()
			}
			if h.Upstream != "" {
				return d.Err("upstream directive specified more than once")
			}
			h.Upstream = args[0]
			// 处理acl子指令
		case "acl":
			// 循环处理ACL规则
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				aclDirective := d.Val()
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				var ruleSubjects []string
				var err error
				aclAllow := false
				switch aclDirective {
				case "allow":
					ruleSubjects = args
					aclAllow = true
				case "allow_file":
					if len(args) != 1 {
						return d.Err("allowfile accepts a single filename argument")
					}
					ruleSubjects, err = readLinesFromFile(args[0])
					if err != nil {
						return err
					}
					aclAllow = true
				case "deny":
					ruleSubjects = args
				case "deny_file":
					if len(args) != 1 {
						return d.Err("denyfile accepts a single filename argument")
					}
					ruleSubjects, err = readLinesFromFile(args[0])
					if err != nil {
						return err
					}
				default:
					return d.Err("expected acl directive: allow/allowfile/deny/denyfile." +
						"got: " + aclDirective)
				}
				ar := ACLRule{Subjects: ruleSubjects, Allow: aclAllow}
				h.ACL = append(h.ACL, ar)
			}
		default:
			return d.ArgErr()
		}
	}
	//globalUserConfig.mu.Unlock()
	return nil
}
