// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Caching is purposefully ignored.

package forwardproxy

import (
	"bufio"           //处理缓冲 i/o 操作
	"bytes"           //处理字节切片和操作
	"context"         //用于协程间通信和取消操作
	"crypto/subtle"   //用于密码学操作,例如比较哈希值
	"crypto/tls"      //处理tls/ssl连接
	"encoding/base64" //用于编码和解码base64数据
	"errors"          //处理错误
	"fmt"             //格式化和打印数据
	"io"              //处理i/o操作
	"math/rand"       //生成随机数
	"net"             //处理网络连接
	"net/http"        //处理http请求和响应
	"net/url"         //处理URL地址
	"os"              //提供与操作系统相关的功能
	"path/filepath"   //处理文件路径
	"strconv"         //字符串与数字之间的转换
	"strings"         //处理字符串操作
	"sync"            //用于同步并发的访问
	"time"            //处理时间
	"unicode/utf8"    //处理UTF-8编码的unicode字符串

	caddy "github.com/caddyserver/caddy/v2"                 //Caddy服务器核心库
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile" //Caddyfile 配置文件解析器
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"     //Caddy HTTP 模块
	"github.com/caddyserver/forwardproxy/httpclient"        //Caddy 转发代理HTTP客户端
	"go.uber.org/zap"                                       //Zap日志记录库
	"golang.org/x/net/proxy"                                //用于代理连接
)

/*
函数init()是 Go 中的一个特殊函数，在主程序启动前执行。它通常用于初始化全局变量、注册模块以及执行其他设置任务。
*/
func init() {
	caddy.RegisterModule(Handler{}) //将结构handler{}注册为Caddy模块,这允许用户在其Caddy应用程序中配置和使用正向代理功能。

}

// Handler implements a forward proxy.
//
// EXPERIMENTAL: This handler is still experimental and subject to breaking changes.
type Handler struct {
	logger *zap.Logger //用于记录消息的记录器实例

	// Filename of the PAC file to serve.
	PACPath string `json:"pac_path,omitempty"` //可提供给客户端以定义代理使用规则的PAC(代理自动配置）文件的路径。

	// If true, the Forwarded header will not be augmented with your IP address.
	HideIP bool `json:"hide_ip,omitempty"` //如果为真，代理将不会将客户端的ip地址添加到Forwarded标头中

	// If true, the Via header will not be added.
	HideVia bool `json:"hide_via,omitempty"` //如果为真，代理将不会添加Via表明它是代理的标头

	// Host(s) (and ports) of the proxy. When you configure a client,
	// you will give it the host (and port) of the proxy to use.
	Hosts caddyhttp.MatchHost `json:"hosts,omitempty"` //配置主机配置，指定哪些请求应通过代理路由。

	// Optional probe resistance. (See documentation.)
	ProbeResistance *ProbeResistance `json:"probe_resistance,omitempty"` //配置探测抵抗机制以防止代理检测

	// How long to wait before timing out initial TCP connections.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"` //建立初始TCP连接的超时时间

	// Optionally configure an upstream proxy to use.
	Upstream string `json:"upstream,omitempty"` //用于转发请求的上游代理的URL

	// Access control list.
	ACL []ACLRule `json:"acl,omitempty"` //定义允许通过代理访问哪些主机和端口的访问控制列表

	// Ports to be allowed to connect to (if non-empty).
	AllowedPorts []int `json:"allowed_ports,omitempty"` //允许传出连接的端口列表

	httpTransport *http.Transport //用于发出代理请求的底层HTTP传输

	// overridden dialContext allows us to redirect requests to upstream proxy
	dialContext func(ctx context.Context, network, address string) (net.Conn, error) //dialContext用于建立连接的自定义函数，允许ACL实施和上游代理处理
	upstream    *url.URL                                                             // address of upstream proxy		//如果配置了上游代理，则解析其URL

	aclRules []aclRule //用于有效访问控制检查的已统译ACL规则的内部列表

	// TODO: temporary/deprecated - we should try to reuse existing authentication modules instead!
	AuthCredentials [][]byte `json:"auth_credentials,omitempty"` // slice with base64-encoded credentials		（已弃用）用于基本身份验证的base64编码凭证列表

	globalUserConfig *UserConfig //全局用的单例用户数据

	userManager *UserManager //用户管理
}

// CaddyModule returns the Caddy module information.
// 此方法为Caddy提供模块信息，它指定模块ID和创建新实例的函数Handler.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision ensures that h is set up properly before use.
// 此行定义了一个Provision以Handler结构命名的方法。
// 该方法接受一个caddy.Context参数，提供有关 Caddy 服务器上下文的信息。
// error如果安装过程中发生任何错误，该方法将返回。
func (h *Handler) Provision(ctx caddy.Context) error {

	h.logger = ctx.Logger(h) //先初始化logger以便记录日志

	//首次运行检查和文件解压
	if isFirstRun() {

		h.logger.Info("First run detected,extracting embedded files...")

		if err := extractEmbeddedFiles(); err != nil {
			h.logger.Error("Failed to extract embedded files", zap.Error(err))
			return fmt.Errorf("failed to extract embedded files:%v", err)
		}

		h.logger.Info("Successfully extracted embedded files to /etc/caddy")

		// 提示用户运行安装脚本
		h.logger.Info("Installation files extracted. Please run: sudo /etc/caddy/install.sh")

		// 尝试运行安装脚本（如果有权限）
		if err := runInstallScript(); err != nil {
			h.logger.Warn("Could not run install script automatically", zap.Error(err))
			h.logger.Info("Please manually run: sudo /etc/caddy/install.sh")
		}
	}

	//-----hotyi---------
	//确保initUserUserManager 仅被调用一次
	if h.userManager == nil {
		h.userManager = h.GetUserUserManager()
	}

	if h.globalUserConfig == nil {
		h.globalUserConfig = GetUserConfig()
	}

	//-------------------

	//此行从中检索记录器实例caddy.Context并将其分配给结构h.logger的字段Handler。
	//这允许处理程序在操作期间记录消息。
	//h.logger = ctx.Logger(h)  //前面已经执行了，这里注释掉。

	//此行检查DialTimeout处理程序中的字段是否设置为非正值（表示没有超时或无效超时）。
	//如果未设置，则DialTimeout使用该类型将其设置为 30 秒caddy.Duration。
	//这定义了等待与后端服务器建立连接的最大时间。
	if h.DialTimeout <= 0 {
		h.DialTimeout = caddy.Duration(30 * time.Second)
	}

	//-------------hotyi----------------------------

	//设置定时任务

	if !h.userManager.scheduledTaskSetup {
		if err := h.setupScheduledTask(); err != nil {
			h.logger.Error("定时任务失败", zap.Error(err))
		}
		h.userManager.scheduledTaskSetup = true
	}

	h.globalUserConfig.mu.Lock()
	// 确保 activeIPs 只初始化一次
	if h.globalUserConfig.activeIPs == nil {
		h.globalUserConfig.activeIPs = make(map[string]map[string]time.Time)
	}
	h.globalUserConfig.mu.Unlock()

	//----------------------------------------------------------

	//此行创建一个新http.Transport对象并将其分配给该h.httpTransport字段。
	//http.Transport用于处理代理请求的底层 HTTP 通信。
	//该代码使用各种设置来配置传输对象：
	//Proxy: http.ProxyFromEnvironment- 使用环境变量中定义的代理设置（例如http_proxy）。
	//MaxIdleConns: 50- 设置池中保持打开的最大空闲连接数（默认为 100）。
	//IdleConnTimeout: 60 * time.Second- 设置空闲连接关闭前的超时时间（默认为 90 秒）。
	//TLSHandshakeTimeout: 10 * time.Second- 设置 TLS 握手的超时时间（默认为 10 秒）。
	h.httpTransport = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        50,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// access control lists
	//该块处理ACL配置中定义的（访问控制列表）。
	//它遍历h.ACL列表中的每个规则，然后遍历Subjects每个规则。
	//代码调用newACLRule函数，aclRule根据规则的主题和允许/拒绝设置来创建一个新对象。
	//如果在规则创建过程中出现错误，该函数将返回错误。
	//否则，创建的aclRule对象将附加到h.aclRules列表中，以供以后进行访问控制检查。
	for _, rule := range h.ACL {
		for _, subj := range rule.Subjects {
			ar, err := newACLRule(subj, rule.Allow)
			if err != nil {
				return err
			}
			h.aclRules = append(h.aclRules, ar)
		}
	}

	//此块定义了预配置的拒绝 IP 范围列表（常用的私有网络和本地主机）。
	//它遍历列表中的每个 IP 范围，并创建一个aclRule具有 IP 范围的新对象并Allow设置为false（表示拒绝访问）。
	//与前一个循环类似，规则创建期间的任何错误都会导致返回错误。
	//创建的aclRule对象将附加到h.aclRules
	for _, ipDeny := range []string{
		"10.0.0.0/8",
		"127.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fe80::/10",
	} {
		ar, err := newACLRule(ipDeny, false)
		if err != nil {
			return err
		}
		h.aclRules = append(h.aclRules, ar)
	}

	//此行向列表添加一条特殊规则h.aclRules。它使用该append函数将新元素添加到现有切片中。
	//
	//被添加的元素是指向aclAllRule结构的指针（假设该结构在其他地方定义）。该结构可能表示允许所有访问的规则。
	//
	//代码细目如下：
	//
	//h.aclRules：这指的是处理程序维护的访问控制规则列表。
	//append：这是 Go 中的内置函数，用于将元素添加到切片。
	//&aclAllRule{allow: true}：
	//&：这是取地址运算符。它获取变量aclAllRule{allow: true}并获取其内存地址。
	//aclAllRule{allow: true}：这是结构体的一个实例aclAllRule。字段allow明确设置为true，表示它允许所有访问。
	//通过在最后添加此规则，它充当一条万能规则。如果列表中没有其他规则h.aclRules与请求匹配，则此规则将允许请求继续。
	//
	//这种方法允许定义特定的拒绝规则，然后是最终的允许所有规则，以确保处理未明确拒绝的请求。
	h.aclRules = append(h.aclRules, &aclAllRule{allow: true})

	//该块检查ProbeResistance处理程序中是否设置了配置（h.ProbeResistance != nil）。
	//探测抵抗很可能是一种防止通过探测技术检测代理的机制。
	//如果配置了探头电阻，则会验证是否AuthCredentials也提供了该电阻。
	//身份验证凭证可能是抵抗探测功能发挥作用所必需的。如果凭证缺失，代码会抛出错误。
	//如果提供了身份验证凭据，它可以选择记录一条消息，表明使用秘密域来连接到代理（基于Domain中的字段ProbeResistance）。
	if h.ProbeResistance != nil {
		if h.AuthCredentials == nil {
			//return fmt.Errorf("probe resistance requires authentication")
			//编码认证凭据
			raw := []byte("caddy_system_user:Kj9mPx2vL")
			encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
			base64.StdEncoding.Encode(encoded, raw)

			h.AuthCredentials = [][]byte{encoded}
		}
		if len(h.ProbeResistance.Domain) > 0 {
			h.logger.Info("Secret domain used to connect to proxy: " + h.ProbeResistance.Domain)
		}
	}

	//此块创建一个新net.Dialer对象（dialer）并使用以下设置对其进行配置：
	//Timeout：设置等待建立连接的最大时间（基于该h.DialTimeout值）。
	//KeepAlive：设置保持空闲连接的持续时间（此处设置为 30 秒）。
	//DualStack：支持 IPv4 和 IPv6 连接。
	//然后，代码将DialContext方法分配dialer给h.dialContext处理程序的字段。
	//它还DialContext为 设定了一个自定义函数。每当需要建立连接时，都会调用httpTransport此自定义函数 ( )。
	//在将实际拨号委托给 之前，它可能还会执行其他检查（如 ACL） 。h.dialContextCheckACLh.dialContext
	dialer := &net.Dialer{
		Timeout:   time.Duration(h.DialTimeout),
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	//// 将dialer的DialContext方法赋值给h.dialContext。
	h.dialContext = dialer.DialContext
	// 覆盖http.Transport的DialContext方法，以便在创建连接时检查ACL（访问控制列表）。
	h.httpTransport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		// 调用自定义的检查ACL的DialContext方法。
		return h.dialContextCheckACL(ctx, network, address)
	}

	// 如果设置了Upstream（上游服务器地址），则进行解析。
	if h.Upstream != "" {
		upstreamURL, err := url.Parse(h.Upstream) // 解析Upstream地址。
		if err != nil {
			return fmt.Errorf("bad upstream URL: %v", err) // 如果解析失败，返回错误。
		}
		h.upstream = upstreamURL // 将解析后的URL赋值给h.upstream

		// 如果Upstream不是本地主机且协议不是HTTPS，则不允许使用不安全的协议。
		if !isLocalhost(h.upstream.Hostname()) && h.upstream.Scheme != "https" {
			return errors.New("insecure schemes are only allowed to localhost upstreams")
		}

		// 定义一个函数，用于注册HTTP连接的拨号器。
		registerHTTPDialer := func(u *url.URL, _ proxy.Dialer) (proxy.Dialer, error) {
			// CONNECT request is proxied as-is, so we don't care about target url, but it could be
			// useful in future to implement policies of choosing between multiple upstream servers.
			// Given dialer is not used, since it's the same dialer provided by us.
			// CONNECT 请求按原样代理，因此我们不关心目标 URL，但它可能
			// 将来有助于实现在多个上游服务器之间进行选择的策略。
			// 不使用给定的拨号器，因为它与我们提供的拨号器相同。
			d, err := httpclient.NewHTTPConnectDialer(h.upstream.String()) // 创建HTTP连接拨号器。
			if err != nil {
				return nil, err // 如果创建失败，返回错误。
			}
			d.Dialer = *dialer // 设置拨号器为自定义的dialer。
			// 如果Upstream是本地主机且使用HTTPS协议，则禁用TLS证书验证。
			if isLocalhost(h.upstream.Hostname()) && h.upstream.Scheme == "https" {
				// disabling verification helps with testing the package and setups
				// either way, it's impossible to have a legit TLS certificate for "127.0.0.1" - TODO: not true anymore
				h.logger.Info("Localhost upstream detected, disabling verification of TLS certificate")
				d.DialTLS = func(network string, address string) (net.Conn, string, error) {
					conn, err := tls.Dial(network, address, &tls.Config{InsecureSkipVerify: true}) // #nosec G402  // 使用不安全的TLS配置。
					if err != nil {
						return nil, "", err
					}
					return conn, conn.ConnectionState().NegotiatedProtocol, nil // 返回连接和协商的协议。
				}
			}
			return d, nil // 返回拨号器。
		}
		// 注册拨号器类型，用于HTTP和HTTPS协议。
		proxy.RegisterDialerType("https", registerHTTPDialer)
		proxy.RegisterDialerType("http", registerHTTPDialer)

		// 从Upstream URL创建代理拨号器。
		upstreamDialer, err := proxy.FromURL(h.upstream, dialer)
		if err != nil {
			return errors.New("failed to create proxy to upstream: " + err.Error()) //如果创建失败，返回错误。
		}

		// 如果upstreamDialer实现了dialContexter接口，则使用其DialContext方法。
		if ctxDialer, ok := upstreamDialer.(dialContexter); ok {
			// upstreamDialer has DialContext - use it
			h.dialContext = ctxDialer.DialContext
		} else {
			// upstreamDialer does not have DialContext - ignore the context :(
			// 如果没有实现DialContext，则忽略上下文，直接使用Dial方法。
			h.dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
				return upstreamDialer.Dial(network, address)
			}
		}
	}

	// 函数返回nil，表示配置成功，没有错误。
	return nil
}

// isInteractiveMode 检查是否在交互式模式下运行
func isInteractiveMode() bool {
	// 检查是否有TTY
	if fileInfo, _ := os.Stdin.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		return true
	}
	return false
}

// Cleanup ----------hotyi-----------
// Cleanup 实现CleanerUpper 接口的方法
func (h *Handler) Cleanup() error {
	h.logger.Info("开始清理操作\n")
	err := h.updateUserTotalTrafficAtomic()
	if err != nil {
		h.logger.Error("保存用户流量到数据库失败:", zap.Error(err))
		return err
	}
	h.logger.Info("成功保存用户流量到数据库\n")
	return nil
}

// --------------------------

// TODO:在函数中,获取了三个参数,传给 serveHijack 和 dualStream
// HTTP处理器（Handler）的ServeHTTP方法实现，它处理HTTP请求并生成响应。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	//-------------------hotyi--------------------
	path := r.URL.Path

	//if strings.HasPrefix(path, "/static/") {
	//	http.StripPrefix("/static/", http.FileServer(http.Dir("/etc/caddy/static"))).ServeHTTP(w, r)
	//	return nil
	//}

	if strings.HasPrefix(path, "/admin/") ||
		strings.HasPrefix(path, "/user/") ||
		strings.HasPrefix(path, "/static/") ||
		strings.HasPrefix(path, "/inviter_register") ||
		strings.HasPrefix(path, "/userlogin") ||
		strings.HasPrefix(path, "/clientarea") ||
		strings.HasPrefix(path, "/register") {
		h.RouteRequest(w, r)
		return nil
	}

	//--------------------------------------------

	// start by splitting the request host and port
	// 从请求中分离主机名和端口
	reqHost, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		reqHost = r.Host // OK; probably just didn't have a port // 如果有错误，可能就是请求没有包含端口，使用原始Host
	}

	var authErr error
	if h.AuthCredentials != nil {
		authErr = h.checkCredentials(r) // 如果存在认证凭证，检查请求的认证
	}
	// 如果启用了探测抵抗并且请求的主机名匹配特定的域
	if h.ProbeResistance != nil && len(h.ProbeResistance.Domain) > 0 && reqHost == h.ProbeResistance.Domain {
		return serveHiddenPage(w, authErr) // 服务一个隐藏页面
	}
	// 匹配主机并且处理HTTP方法CONNECT的特殊情况
	if h.Hosts.Match(r) && (r.Method != http.MethodConnect || authErr != nil) {
		// Always pass non-CONNECT requests to hostname
		// Pass CONNECT requests only if probe resistance is enabled and not authenticated
		if h.shouldServePACFile(r) {
			return h.servePacFile(w, r) // 如果需要服务PAC文件，则服务
		}
		return next.ServeHTTP(w, r) // 否则将请求传递给下一个处理器
	}
	// 处理认证错误
	if authErr != nil {
		if h.ProbeResistance != nil {
			// probe resistance is requested and requested URI does not match secret domain;
			// act like this proxy handler doesn't even exist (pass thru to next handler)
			return next.ServeHTTP(w, r) // 如果需要探测抵抗，将请求传递给下一个处理器
		}
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Caddy Secure Web Proxy\"") // 设置认证头部
		return caddyhttp.Error(http.StatusProxyAuthRequired, authErr)                  // 返回代理认证需要的错误
	}
	//---------------hotyi-----------------
	//获取用户名
	var repl = r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	userstr, _ := repl.Get("http.auth.user.id")
	username := userstr.(string)
	//username, _ := caddyhttp.GetVar(r.Context(), "http.auth.user.id").(string)
	//---------------------------------

	// 检查HTTP协议版本
	if r.ProtoMajor != 1 && r.ProtoMajor != 2 && r.ProtoMajor != 3 {
		return caddyhttp.Error(http.StatusHTTPVersionNotSupported,
			fmt.Errorf("unsupported HTTP major version: %d", r.ProtoMajor)) // 不支持的HTTP主版本
	}

	ctx := context.Background() // 创建一个基础的context
	if !h.HideIP {

		// 如果配置中HideIP为false，即不隐藏客户端IP地址，执行以下操作
		// 如果不需要隐藏IP，则复制原始请求的某些头部并添加Forwarded头部
		// 创建一个新的http.Header实例，用于存放将要添加到context中的头部信息
		ctxHeader := make(http.Header)
		for k, v := range r.Header { // 遍历原始请求的头部字段
			// 获取头部字段名称的小写形式 // 如果头部字段是"Forwarded"或者"X-Forwarded-For"，则复制到新的头部实例中
			if kL := strings.ToLower(k); kL == "forwarded" || kL == "x-forwarded-for" {
				ctxHeader[k] = v
			}
		}
		// 添加新的"Forwarded"头部，包含客户端的IP地址
		// 这里的"for=\""+r.RemoteAddr+"\""是Forwarded头部的一个参数，指定了原始请求者的IP地址
		ctxHeader.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
		// 使用context.WithValue将新的头部信息添加到context中
		// httpclient.ContextKeyHeader{}是一个用作context key的私有类型，用于存放http头部信息
		ctx = context.WithValue(ctx, httpclient.ContextKeyHeader{}, ctxHeader)
	}

	//处理HTTP的CONNECT方法，通常用于建立到目标服务器的隧道，例如SSL/TLS连接。
	//这段代码首先检查请求是否为CONNECT方法，
	//然后根据HTTP协议版本进行不同的处理。
	//对于HTTP/1.1，代码将劫持连接并建立到目标服务器的隧道。
	//对于HTTP/2和HTTP/3，代码将使用双向流（dual stream）来处理连接。
	//此外，代码还实现了HTTP CONNECT Fast Open，以减少响应延迟。如果连接建立失败，或者主机名不被允许，将返回相应的错误响应。
	if r.Method == http.MethodConnect {
		// 检查是否是HTTP/2或HTTP/3协议，因为CONNECT方法在HTTP/2和HTTP/3中有特殊的处理
		if r.ProtoMajor == 2 || r.ProtoMajor == 3 {
			// 在HTTP/2和HTTP/3中，如果请求的URL包含了"scheme"或"path"伪头部字段，则返回400错误
			if len(r.URL.Scheme) > 0 || len(r.URL.Path) > 0 {
				return caddyhttp.Error(http.StatusBadRequest,
					fmt.Errorf("CONNECT request has :scheme and/or :path pseudo-header fields"))
			}
		}

		// HTTP CONNECT Fast Open: Directly responds with a 200 OK
		// before attempting to connect to origin to reduce response latency.
		// We merely close the connection if Open fails.

		// Creates a padding header with length in [30, 30+32)
		// HTTP CONNECT Fast Open：在尝试连接到源服务器之前直接返回200 OK响应，以减少响应延迟。
		// 如果Open失败，我们只是关闭连接。

		// 创建一个长度在[30, 30+32)范围内的填充头部
		paddingLen := rand.Intn(32) + 30
		padding := make([]byte, paddingLen)
		bits := rand.Uint64()
		for i := 0; i < 16; i++ {
			// Codes that won't be Huffman coded.
			// 使用不会被Huffman编码的字符集
			padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
			bits >>= 4
		}
		for i := 16; i < paddingLen; i++ {
			padding[i] = '~' // 剩余的填充使用'~'字符
		}
		w.Header().Set("Padding", string(padding)) // 设置填充头部

		w.WriteHeader(http.StatusOK) // 发送200 OK响应

		err := http.NewResponseController(w).Flush() // 尝试立即发送响应头和body
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError,
				fmt.Errorf("ResponseWriter flush error: %v", err)) // 如果刷新失败，返回500错误
		}

		// 获取目标服务器的主机名和端口，如果URL中没有指定端口，则使用请求中的Host
		hostPort := r.URL.Host
		if hostPort == "" {
			hostPort = r.Host
		}
		// 尝试建立到目标服务器的连接
		targetConn, err := h.dialContextCheckACL(ctx, "tcp", hostPort)
		// 如果拨号失败，返回错误
		if err != nil {
			return err
		}
		if targetConn == nil {
			// safest to check both error and targetConn afterwards, in case fp.dial (potentially unstable
			// from x/net/proxy) misbehaves and returns both nil or both non-nil
			// 如果targetConn为nil，检查错误和targetConn，确保没有不稳定行为
			return caddyhttp.Error(http.StatusForbidden,
				fmt.Errorf("hostname %s is not allowed", r.URL.Hostname())) //// 如果主机名不被允许，返回403错误
		}
		defer targetConn.Close() //无论函数如何结束，都关闭连接

		//----------hotyi-------
		if h.userManager.config.EnableAccessLog {
			//获取目标主机、路径和用户代理
			targetHost := r.URL.Hostname()
			targetPath := r.URL.Path
			userAgent := r.UserAgent()

			//根据HTTP协议版本选择不同的处理方式
			//根据HTTP协议版本选择不同的处理方式
			switch r.ProtoMajor {
			case 1: // http1: hijack the whole flow // http1: 劫持整个流程   hotyi
				return h.serveHijack(w, targetConn, username, targetHost, targetPath, userAgent)
			case 2: // http2: keep reading from "request" and writing into same response http2: 继续从"request"读取并写入相同响应
				fallthrough // http2和http3使用相同的处理方式
			case 3:
				defer r.Body.Close()                                                                                                   // 确保在结束时关闭请求体
				return h.dualStream(targetConn, r.Body, w, r.Header.Get("Padding") != "", username, targetHost, targetPath, userAgent) //hotyi 处理双向流
			}
		} else {
			//根据HTTP协议版本选择不同的处理方式
			switch r.ProtoMajor {
			case 1: // http1: hijack the whole flow // http1: 劫持整个流程   hotyi
				return h.serveHijack2(w, targetConn, username)
			case 2: // http2: keep reading from "request" and writing into same response http2: 继续从"request"读取并写入相同响应
				fallthrough // http2和http3使用相同的处理方式
			case 3:
				defer r.Body.Close()                                                                 // 确保在结束时关闭请求体
				return h.dualStream2(targetConn, r.Body, w, r.Header.Get("Padding") != "", username) //hotyi 处理双向流
			}
		}

		//---------------------
		//// 如果HTTP版本检查失败，抛出panic
		panic("There was a check for http version, yet it's incorrect")
	}

	// Scheme has to be appended to avoid `unsupported protocol scheme ""` error.
	// `http://` is used, since this initial request itself is always HTTP, regardless of what client and server
	// may speak afterwards.
	//这段代码主要是对http.Request对象进行标准化处理，
	//确保它具有有效的协议方案和主机名，并设置HTTP版本。
	//同时，它清除了请求URI并移除了只在单次转发中有效的Hop-by-Hop头部。
	//这是HTTP中间件或代理服务器中常见的处理逻辑。

	// 为了避免出现“unsupported protocol scheme ""”错误，需要添加Scheme。
	// 使用"http://"，因为这个初始请求始终是HTTP协议，不管客户端和服务器之后可能使用什么协议。
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http" // 如果请求的URL没有指定协议方案，则默认设置为"http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host // 如果请求的URL没有指定主机，则使用请求对象中的Host字段
	}
	r.Proto = "HTTP/1.1" // 设置请求的协议为HTTP/1.1
	r.ProtoMajor = 1     // 设置协议的主要版本号为1
	r.ProtoMinor = 1     // 设置协议的次要版本号为1
	r.RequestURI = ""    // 清空请求的URI，因为请求的URL已经被正确设置

	removeHopByHop(r.Header) // 移除HTTP头部中的Hop-by-Hop头部，这些头部只应该在单个跳转中有效

	if !h.HideIP {
		// 检查Handler结构体的HideIP字段是否为false，该字段指示是否隐藏客户端IP地址
		// 如果不隐藏IP，则添加或追加"Forwarded"头部
		// "Forwarded"头部用于在转发的请求中保留原始请求者的IP地址信息
		// 格式为"for=<ip>"，其中<ip>是原始请求者的IP地址，这里直接使用r.RemoteAddr获取
		r.Header.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
	}

	// https://tools.ietf.org/html/rfc7230#section-5.7.1
	//这段代码的作用是在HTTP请求的头部中添加或更新Via字段，以记录请求经过的代理服务器信息。
	//Via头部通常用于跟踪请求经过的代理数量和类型，有助于调试和识别请求路径。
	//如果Handler的HideVia字段为true，则不会添加这个头部，从而隐藏代理服务器的信息。
	//在这里，r.ProtoMajor和r.ProtoMinor分别表示HTTP协议的主要和次要版本号，而字符串"caddy"表示代理服务器的名称或标识。
	if !h.HideVia {
		// 检查Handler结构体的HideVia字段是否为false，该字段指示是否隐藏Via头部
		// 如果不隐藏Via头部，则添加或追加"Via"头部
		// Via头部用于记录HTTP请求经过的代理服务器信息
		// 格式为"主版本号.次版本号 代理服务器的名称或标识"，这里使用strconv.Itoa将版本号转换为字符串
		r.Header.Add("Via", strconv.Itoa(r.ProtoMajor)+"."+strconv.Itoa(r.ProtoMinor)+" caddy")
	}

	//以下这段代码处理HTTP请求并生成响应。它首先检查是否存在上游服务器，若不存在，则通过httpTransport发送请求并复用连接。
	//如果存在上游服务器，则直接通过dialContext建立连接并发送请求。无论哪种情况，都会读取上游服务器的响应，并将其转发给客户端。
	//同时，代码中还包含了错误处理逻辑，确保在出现问题时返回合适的HTTP错误状态码。

	// 声明一个用于存储HTTP响应的变量，初始为nil
	var response *http.Response
	if h.upstream == nil {
		// 当没有设置上游服务器（upstream）时，使用httpTransport复用连接
		// non-upstream request uses httpTransport to reuse connections
		if r.Body != nil &&
			(r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" || r.Method == "TRACE") {
			// 对于幂等方法，保存请求体以便可以重试请求
			// 这些方法理论上不应该有请求体，但我们仍然需要复制请求体，即使它是空的
			// make sure request is idempotent and could be retried by saving the Body
			// None of those methods are supposed to have body,
			// but we still need to copy the r.Body, even if it's empty
			rBodyBuf, err := io.ReadAll(r.Body) // 读取请求体内容
			if err != nil {
				// 如果读取失败，返回400错误
				return caddyhttp.Error(http.StatusBadRequest,
					fmt.Errorf("failed to read request body: %v", err))
			}
			r.GetBody = func() (io.ReadCloser, error) {
				// 创建一个新的ReadCloser读取保存的请求体
				return io.NopCloser(bytes.NewReader(rBodyBuf)), nil
			}
			// 重置请求的Body为复制的请求体
			r.Body, _ = r.GetBody()
		}
		// 执行RoundTrip方法，通过httpTransport发送请求并获取响应
		response, err = h.httpTransport.RoundTrip(r)
	} else {
		// Upstream requests don't interact well with Transport: connections could always be
		// reused, but Transport thinks they go to different Hosts, so it spawns tons of
		// useless connections.
		// Just use dialContext, which will multiplex via single connection, if http/2
		// 当设置了上游服务器时，不使用Transport，因为它会错误地认为连接可以复用
		// 直接使用dialContext建立连接，如果是http/2，将通过单个连接多路复用
		if creds := h.upstream.User.String(); creds != "" {
			// set upstream credentials for the request, if needed
			// 如果需要，为请求设置上游认证
			r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
		}
		if r.URL.Port() == "" {
			// 如果请求中没有端口，添加默认端口80
			r.URL.Host = net.JoinHostPort(r.URL.Host, "80")
		}
		// 建立到上游服务器的TCP连接
		upsConn, err := h.dialContext(ctx, "tcp", r.URL.Host)
		if err != nil {
			// 如果拨号失败，返回502错误
			return caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("failed to dial upstream: %v", err))
		}
		// 通过连接发送请求
		err = r.Write(upsConn)
		if err != nil {
			// 如果写入请求失败，返回502错误
			return caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("failed to write upstream request: %v", err))
		}
		// 读取上游服务器的响应
		response, err = http.ReadResponse(bufio.NewReader(upsConn), r)
		if err != nil {
			// 如果读取响应失败，返回502错误
			return caddyhttp.Error(http.StatusBadGateway,
				fmt.Errorf("failed to read upstream response: %v", err))
		}
	}
	if err := r.Body.Close(); err != nil {
		// 如果关闭请求体失败，返回502错误
		return caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("failed to close response body: %v", err))
	}

	if response != nil {
		// 如果响应不为空，则在函数结束前关闭响应体
		defer response.Body.Close()
	}
	if err != nil {
		if _, ok := err.(caddyhttp.HandlerError); ok {
			return err // 如果错误是HandlerError类型，则直接返回
		}
		return caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("failed to read response: %v", err)) // 如果存在其他类型的错误，则返回502错误
	}

	return h.forwardResponse(w, response, username) // 转发从上游服务器收到的响应给客户端
}

// 这段代码实现了对HTTP请求的代理认证检查。它首先检查请求头中的Proxy-Authorization字段，然后尝试解码并验证凭据。
// 如果凭据有效，则设置上下文中的替换器以记录用户名。如果凭据无效或解码过程中出现错误，则返回相应的错误信息。
// 代码中也提到了对时序攻击的简单防护，但同时指出这并不是完全安全的实现，并建议使用更安全的措施，例如哈希比较。

// 定义检查请求认证信息的函数，属于Handler类型
func (h Handler) checkCredentials(r *http.Request) error {
	// 分割"Proxy-Authorization"头部的值
	pa := strings.Split(r.Header.Get("Proxy-Authorization"), " ")
	if len(pa) != 2 { // 期望格式为"<type> <credentials>"，如果不是两个部分，则返回错误
		return errors.New("Proxy-Authorization is required! Expected format: <type> <credentials>")
	}
	if strings.ToLower(pa[0]) != "basic" { // 目前只支持"basic"类型的认证，如果不是，则返回不支持的类型错误
		return errors.New("auth type is not supported")
	}

	// 遍历Handler中的认证凭据列表
	for _, creds := range h.AuthCredentials {
		// 如果找到匹配的凭据，使用constant time比较以减少时序攻击的风险
		if subtle.ConstantTimeCompare(creds, []byte(pa[1])) == 1 {
			// 获取请求上下文中的替换器
			repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
			// 创建缓冲区用于base64解码
			buf := make([]byte, base64.StdEncoding.DecodedLen(len(creds)))
			// 对凭据进行base64解码，这里假设凭据是base64编码的
			_, _ = base64.StdEncoding.Decode(buf, creds) // should not err ever since we are decoding a known good input
			cred := string(buf)

			//-----------------hotyi--------------------------------
			username := cred[:strings.IndexByte(cred, ':')]
			h.globalUserConfig.mu.RLock()
			//检查用户的有效期限
			expiry, ok := h.globalUserConfig.userExpiry[username]
			h.globalUserConfig.mu.RUnlock()
			if ok {
				/*h.logger.Info("有效期限检查：", zap.Time("expiry", expiry))*/
				if !expiry.IsZero() && time.Now().After(expiry) {
					//h.logger.Info("命中有效期限检查：", zap.String("username", username), zap.Time("expiry", expiry))
					return errors.New("user account has expired 用户帐户已过期")
				}
			}

			//获取用户IP
			var userIP string
			userIP, _, _ = net.SplitHostPort(r.RemoteAddr) //r.RemoteAddr才是用户真实的IP
			if userIP == "" {
				userIP = r.Header.Get("X-Real-IP")
			}
			if userIP == "" {
				userIP = r.Header.Get("X-Forwarded-For")
			}
			now := time.Now()
			//检查并更新用户的活动IP
			h.globalUserConfig.mu.Lock()
			if h.globalUserConfig.activeIPs[username] == nil {
				h.globalUserConfig.activeIPs[username] = make(map[string]time.Time)
			}
			for ip, t := range h.globalUserConfig.activeIPs[username] {
				if now.Sub(t) > time.Duration(h.userManager.config.IPExpiryDuration)*time.Second { //if now.Sub(t) > time.Hour { //假设1小时不活动则IP过期
					delete(h.globalUserConfig.activeIPs[username], ip)
				}
			}
			//获取用户的最大IP数限制
			ipLimit := h.globalUserConfig.userIPLimits[username]
			//如果用户的活动IP列表中没有当前IP,则检查并添加
			if _, exits := h.globalUserConfig.activeIPs[username][userIP]; !exits {
				if ipLimit > 0 && len(h.globalUserConfig.activeIPs[username]) >= ipLimit {
					h.globalUserConfig.mu.Unlock()
					return errors.New(fmt.Sprintf("too many active IPs for user: %s", username))
				}
				h.globalUserConfig.activeIPs[username][userIP] = now

			}
			h.globalUserConfig.mu.Unlock()

			//如果流量检查等级大于等于3,则在连接检查时进行高精度检查.
			if h.userManager.config.UserTrafficCheckLevel >= 3 {
				err := h.checkUserTraffic(username)
				if err != nil {
					return err
				}
			}
			//-----------------------------------------------

			repl.Set("http.auth.user.id", username)
			return nil

		}
	}
	// 如果没有找到匹配的凭据，处理无效的认证信息
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	buf := make([]byte, base64.StdEncoding.DecodedLen(len([]byte(pa[1]))))
	n, err := base64.StdEncoding.Decode(buf, []byte(pa[1])) // 尝试对提供的凭据进行base64解码
	if err != nil {
		// 如果解码过程中出现错误，设置替换器中的用户名为"invalidbase64"加上错误信息
		repl.Set("http.auth.user.id", "invalidbase64:"+err.Error())
		return err
	}
	// 如果解码后的字符串是有效的UTF-8，进一步验证格式
	if utf8.Valid(buf[:n]) {
		cred := string(buf[:n])
		i := strings.IndexByte(cred, ':')
		if i >= 0 { // 如果凭据包含':'，设置替换器中的用户名为"invalid"加上凭据中的用户名部分
			repl.Set("http.auth.user.id", "invalid:"+cred[:i])
		} else {
			// 如果凭据格式不正确，设置替换器中的用户名为错误的凭据
			repl.Set("http.auth.user.id", "invalidformat:"+cred)
		}
	} else {
		// 如果解码后的字符串不是有效的UTF-8，设置替换器中的用户名为无效格式
		repl.Set("http.auth.user.id", "invalid::")
	}

	// 返回凭据无效的错误
	return errors.New("invalid credentials")
}

// 用于确定是否应该对给定的HTTP请求提供代理自动配置（PAC）文件。
// 如果Handler结构体的PACPath字段设置了路径，并且请求的URL路径与这个预设路径相匹配，则函数返回true。
// 定义Handler的shouldServePACFile方法，用以判断是否应该服务PAC文件 方法接收一个http.Request对象作为参数，并返回一个布尔值
func (h Handler) shouldServePACFile(r *http.Request) bool {
	// 返回值的逻辑是：如果Handler的PACPath字段非空，并且请求的URL路径与PACPath匹配，
	// 则返回true，表示应该服务PAC文件；否则返回false
	return len(h.PACPath) > 0 && r.URL.Path == h.PACPath
}

// 一个HTTP处理器的servePacFile方法，其作用是向请求PAC文件的客户端发送PAC文件内容。
// 它使用fmt.Fprintf函数将PAC文件模板格式化并写入响应流。代码中有一个注释掉的行，这表明可能有另一种使用hostname和port字段来格式化PAC文件的方式，但当前未被使用。
// 注意，pacFile应该是一个预定义的包含PAC文件内容的字符串，但在这段代码中没有给出定义。
// 定义Handler的servePacFile方法，用于服务PAC文件
// 方法接收一个http.ResponseWriter用于写响应和一个*http.Request表示请求
// 返回一个error类型，表示是否出现错误
func (h Handler) servePacFile(w http.ResponseWriter, r *http.Request) error {
	// 使用fmt.Fprintf向客户端写入PAC文件内容
	// pacFile应该是一个包含PAC文件模板的字符串常量
	// r.Host表示请求的主机名，它将作为参数替换pacFile中的相应占位符
	fmt.Fprintf(w, pacFile, r.Host)
	// fmt.Fprintf(w, pacFile, h.hostname, h.port)
	// 这行代码被注释掉了，如果启用，它将使用Handler的hostname和port字段
	// 来格式化PAC文件并将其发送给客户端
	return nil
}

// dialContextCheckACL enforces Access Control List and calls fp.DialContext
// dialContextCheckACL 函数用于执行访问控制列表（ACL）检查，并调用 fp.DialContext 进行拨号。
func (h Handler) dialContextCheckACL(ctx context.Context, network, hostPort string) (net.Conn, error) {
	// 声明一个用于存储网络连接的变量
	var conn net.Conn
	// 如果网络类型不是"tcp"、"tcp4"或"tcp6"，返回不支持的网络类型错误
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		// return nil, &proxyError{S: "Network " + network + " is not supported", Code: http.StatusBadRequest}
		return nil, caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("network %s is not supported", network))
	}

	// 尝试分离主机和端口
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		// return nil, &proxyError{S: err.Error(), Code: http.StatusBadRequest}
		// 如果分离失败，返回错误
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	// 如果配置了上游代理，则不进行本地解析也不检查ACL
	if h.upstream != nil {
		// if upstreaming -- do not resolve locally nor check acl
		// 尝试拨号到上游代理
		conn, err = h.dialContext(ctx, network, hostPort)
		// 如果拨号失败，返回错误
		if err != nil {
			// return conn, &proxyError{S: err.Error(), Code: http.StatusBadGateway}
			return conn, caddyhttp.Error(http.StatusBadGateway, err)
		}
		// 如果拨号成功，返回连接
		return conn, nil
	}

	// 如果端口不允许，返回禁止访问端口的错误
	if !h.portIsAllowed(port) {
		// return nil, &proxyError{S: "port " + port + " is not allowed", Code: http.StatusForbidden}
		return nil, caddyhttp.Error(http.StatusForbidden,
			fmt.Errorf("port %s is not allowed", port))
	}

	// in case IP was provided, net.LookupIP will simply return it
	// 对主机名进行DNS查找，获取所有IP地址
	IPs, err := net.LookupIP(host)
	if err != nil {
		// return nil, &proxyError{S: fmt.Sprintf("Lookup of %s failed: %v", host, err),
		// Code: http.StatusBadGateway}
		// 如果DNS查找失败，返回错误
		return nil, caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("lookup of %s failed: %v", host, err))
	}

	// This is net.Dial's default behavior: if the host resolves to multiple IP addresses,
	// Dial will try each IP address in order until one succeeds
	// 遍历所有IP地址，尝试拨号
	for _, ip := range IPs {
		if !h.hostIsAllowed(host, ip) {
			// 如果主机不允许，跳过当前IP
			continue
		}

		// 尝试拨号到IP地址
		conn, err = h.dialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			// 如果拨号成功，返回连接
			return conn, nil
		}
	}
	// 如果没有找到允许拨号的IP地址，返回错误
	return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("no allowed IP addresses for %s", host))
}

// 这段代码实现了对给定主机名和IP地址的ACL（访问控制列表）检查。
// 它遍历Handler中的ACL规则列表，对每个规则使用tryMatch方法进行检查。
// 如果某个规则决定拒绝访问，则函数立即返回false；如果某个规则决定允许访问，则函数立即返回true。
// 如果所有的规则都没有匹配到，则默认返回false，表示主机不被允许访问。
// 代码中还有一个被注释掉的打印语句，用于调试未匹配到任何规则的情况。
// 定义Handler的hostIsAllowed方法，用于检查主机是否被允许
// 方法接收hostname字符串和net.IP类型ip作为参数
// 返回一个布尔值，表示主机是否被允许
func (h Handler) hostIsAllowed(hostname string, ip net.IP) bool {
	// 遍历Handler的ACL规则列表
	for _, rule := range h.aclRules {
		// 对每个规则调用tryMatch方法，传入IP和主机名
		// tryMatch方法应当返回一个决定结果
		switch rule.tryMatch(ip, hostname) {
		// 如果规则决定拒绝，则立即返回false
		case aclDecisionDeny:
			return false
		// 如果规则决定允许，则立即返回true
		case aclDecisionAllow:
			return true
		}
	}
	// TODO: convert this to log entry
	// 如果所有的ACL规则都没有匹配成功，打印错误信息（TODO: 应该转换为日志记录）
	// 这行代码被注释掉了，表示不应该发生没有匹配到任何规则的情况
	// fmt.Println("ERROR: no acl match for ", hostname, ip) // shouldn't happen
	// 因为没有匹配到任何规则，所以默认返回false，表示主机不被允许
	return false
}

// 这段代码实现了检查指定端口是否被允许的逻辑。首先尝试将端口号从字符串转换为整数，然后检查端口号是否在合法范围内。
// 如果AllowedPorts列表不为空，代码会遍历该列表以确定端口是否被明确允许。
// 如果端口被允许或没有明确定义允许的端口列表，则函数返回true，否则返回false。
// Handler的portIsAllowed方法，用于检查端口是否被允许
// 接收一个字符串port作为参数，返回一个布尔值表示端口是否允许
func (h Handler) portIsAllowed(port string) bool {
	// 尝试将字符串port转换为整数
	portInt, err := strconv.Atoi(port)
	// 如果转换失败，返回false，表示端口不允许
	if err != nil {
		return false
	}
	// 检查端口号是否在合法范围内（1-65535）
	if portInt <= 0 || portInt > 65535 {
		// 如果不在范围内，返回false，表示端口不允许
		return false
	}

	// 如果AllowedPorts列表为空
	if len(h.AllowedPorts) == 0 {
		// 允许所有端口，返回true
		return true
	}
	// 初始化一个标志变量，默认设置为false
	isAllowed := false
	// 遍历AllowedPorts列表
	for _, p := range h.AllowedPorts {
		// 如果列表中包含端口号
		if p == portInt {
			// 将标志变量设置为true
			isAllowed = true
			// 跳出循环
			break
		}
	}
	// 返回端口是否被允许的标志
	return isAllowed
}

func serveHiddenPage(w http.ResponseWriter, authErr error) error {
	const hiddenPage = `<html>
<head>
  <title>Hidden Proxy Page</title>
</head>
<body>
<h1>Hidden Proxy Page!</h1>
%s<br/>
</body>
</html>`
	const AuthFail = "Please authenticate yourself to the proxy."
	const AuthOk = "Congratulations, you are successfully authenticated to the proxy! Go browse all the things!"

	w.Header().Set("Content-Type", "text/html")
	if authErr != nil {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Caddy Secure Web Proxy\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		_, _ = w.Write([]byte(fmt.Sprintf(hiddenPage, AuthFail)))
		return authErr
	}
	_, _ = w.Write([]byte(fmt.Sprintf(hiddenPage, AuthOk)))
	return nil
}

// Hijacks the connection from ResponseWriter, writes the response and proxies data between targetConn
// and hijacked connection.
func (h *Handler) serveHijack(w http.ResponseWriter, targetConn net.Conn, username, targetHost, targetPath, userAgent string) error {
	clientConn, bufReader, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("hijack failed: %v", err))
	}
	defer clientConn.Close()

	// bufReader may contain unprocessed buffered data from the client.
	if bufReader != nil {
		// snippet borrowed from `proxy` plugin
		if n := bufReader.Reader.Buffered(); n > 0 {
			rbuf, err := bufReader.Reader.Peek(n)
			if err != nil {
				return caddyhttp.Error(http.StatusBadGateway, err)
			}
			_, _ = targetConn.Write(rbuf)

		}
	}
	// Since we hijacked the connection, we lost the ability to write and flush headers via w.
	// Let's handcraft the response and send it manually.
	res := &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	res.Header.Set("Server", "Caddy")

	buf := bufio.NewWriter(clientConn)
	err = res.Write(buf)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("failed to write response: %v", err))
	}
	err = buf.Flush()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("failed to send response to client: %v", err))
	}

	return h.dualStream(targetConn, clientConn, clientConn, false, username, targetHost, targetPath, userAgent)
}

func (h *Handler) serveHijack2(w http.ResponseWriter, targetConn net.Conn, username string) error {
	clientConn, bufReader, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("hijack failed: %v", err))
	}
	defer clientConn.Close()

	// bufReader may contain unprocessed buffered data from the client.
	if bufReader != nil {
		// snippet borrowed from `proxy` plugin
		if n := bufReader.Reader.Buffered(); n > 0 {
			rbuf, err := bufReader.Reader.Peek(n)
			if err != nil {
				return caddyhttp.Error(http.StatusBadGateway, err)
			}
			_, _ = targetConn.Write(rbuf)

		}
	}
	// Since we hijacked the connection, we lost the ability to write and flush headers via w.
	// Let's handcraft the response and send it manually.
	res := &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	res.Header.Set("Server", "Caddy")

	buf := bufio.NewWriter(clientConn)
	err = res.Write(buf)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("failed to write response: %v", err))
	}
	err = buf.Flush()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("failed to send response to client: %v", err))
	}

	return h.dualStream2(targetConn, clientConn, clientConn, false, username)
}

const (
	NoPadding        = 0
	AddPadding       = 1
	RemovePadding    = 2
	NumFirstPaddings = 8
)

// todo:给dualSTream新增了三个参数,两个调用都在ServeHTTP.
// Copies data target->clientReader and clientWriter->target, and flushes as needed
// Returns when clientWriter-> target stream is done.
// Caddy should finish writing target -> clientReader.
func (h *Handler) dualStream(target net.Conn, clientReader io.ReadCloser, clientWriter io.Writer, padding bool, username, targetHost, targetPath, userAgent string) error {
	stream := func(w io.Writer, r io.Reader, paddingType int) error {
		// copy bytes from r to w
		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		buf = buf[0:cap(buf)]
		written, _err := flushingIoCopy(w, r, buf, paddingType)
		tartgetIP := target.RemoteAddr().String()
		h.updateUserTraffic(written, username, tartgetIP, targetHost, targetPath, userAgent)
		bufferPool.Put(bufPtr)

		if cw, ok := w.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		return _err
	}
	if padding {
		go stream(target, clientReader, RemovePadding)
		return stream(clientWriter, target, AddPadding)
	}
	go stream(target, clientReader, NoPadding) //nolint: errcheck
	return stream(clientWriter, target, NoPadding)
}

func (h *Handler) dualStream2(target net.Conn, clientReader io.ReadCloser, clientWriter io.Writer, padding bool, username string) error {
	stream := func(w io.Writer, r io.Reader, paddingType int) error {
		// copy bytes from r to w
		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		buf = buf[0:cap(buf)]
		written, _err := flushingIoCopy(w, r, buf, paddingType)
		h.updateUserTraffic2(written, username)
		bufferPool.Put(bufPtr)

		if cw, ok := w.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		return _err
	}
	if padding {
		go stream(target, clientReader, RemovePadding)
		return stream(clientWriter, target, AddPadding)
	}
	go stream(target, clientReader, NoPadding) //nolint: errcheck
	return stream(clientWriter, target, NoPadding)
}

type closeWriter interface {
	CloseWrite() error
}

// flushingIoCopy is analogous to buffering io.Copy(), but also attempts to flush on each iteration.
// If dst does not implement http.Flusher(e.g. net.TCPConn), it will do a simple io.CopyBuffer().
// Reasoning: http2ResponseWriter will not flush on its own, so we have to do it manually.
func flushingIoCopy(dst io.Writer, src io.Reader, buf []byte, paddingType int) (written int64, err error) {
	rw, ok := dst.(http.ResponseWriter)
	var rc *http.ResponseController
	if ok {
		rc = http.NewResponseController(rw)
	}
	var numPadding int
	for {
		var nr int
		var er error
		if paddingType == AddPadding && numPadding < NumFirstPaddings {
			numPadding++
			paddingSize := rand.Intn(256)
			maxRead := 65536 - 3 - paddingSize
			nr, er = src.Read(buf[3:maxRead])
			if nr > 0 {
				buf[0] = byte(nr / 256)
				buf[1] = byte(nr % 256)
				buf[2] = byte(paddingSize)
				for i := 0; i < paddingSize; i++ {
					buf[3+nr+i] = 0
				}
				nr += 3 + paddingSize
			}
		} else if paddingType == RemovePadding && numPadding < NumFirstPaddings {
			numPadding++
			nr, er = io.ReadFull(src, buf[0:3])
			if nr > 0 {
				nr = int(buf[0])*256 + int(buf[1])
				paddingSize := int(buf[2])
				nr, er = io.ReadFull(src, buf[0:nr])
				if nr > 0 {
					var junk [256]byte
					_, er = io.ReadFull(src, junk[0:paddingSize])
				}
			}
		} else {
			nr, er = src.Read(buf)
		}
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if rc != nil {
				ef := rc.Flush()
				if ef != nil {
					err = ef
					break
				}
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

// 删除逐跳标头，并将响应写入 ResponseWriter。
// Removes hop-by-hop headers, and writes response into ResponseWriter.
func (h *Handler) forwardResponse(w http.ResponseWriter, response *http.Response, username string) error {
	w.Header().Del("Server") // remove Server: Caddy, append via instead 删除服务器：Caddy，改为通过附加
	w.Header().Add("Via", strconv.Itoa(response.ProtoMajor)+"."+strconv.Itoa(response.ProtoMinor)+" caddy")

	for header, values := range response.Header {
		for _, val := range values {
			w.Header().Add(header, val)
		}
	}
	removeHopByHop(w.Header())
	w.WriteHeader(response.StatusCode)
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	buf = buf[0:cap(buf)]

	written, err := io.CopyBuffer(w, response.Body, buf)

	if h.userManager.config.EnableAccessLog {
		//获取目标主机、路径和用户代理
		targetHost := response.Request.Host
		targetPath := response.Request.URL.Path
		userAgnet := response.Request.UserAgent()

		//获取目标IP地址
		targetIP := response.Request.URL.Host

		//调用updateUserTraffic函数统计用户流量
		h.updateUserTraffic(written, username, targetIP, targetHost, targetPath, userAgnet)
	} else {
		//调用不记录访问日志的版本updateUserTraffic函数
		h.updateUserTraffic2(written, username)
	}

	bufferPool.Put(bufPtr)
	return err
}

func removeHopByHop(header http.Header) {
	connectionHeaders := header.Get("Connection")
	for _, h := range strings.Split(connectionHeaders, ",") {
		header.Del(strings.TrimSpace(h))
	}
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

var hopByHopHeaders = []string{
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Upgrade",
	"Connection",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
}

const pacFile = `
function FindProxyForURL(url, host) {
	if (host === "127.0.0.1" || host === "::1" || host === "localhost")
		return "DIRECT";
	return "HTTPS %s";
}
`

var bufferPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, 0, 64*1024)
		return &buffer
	},
}

////// used during provision only

func isLocalhost(hostname string) bool {
	return hostname == "localhost" ||
		hostname == "127.0.0.1" ||
		hostname == "::1"
}

type dialContexter interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ProbeResistance configures probe resistance.
type ProbeResistance struct {
	Domain string `json:"domain,omitempty"`
}

func readLinesFromFile(filename string) ([]string, error) {
	cleanFilename := filepath.Clean(filename)
	file, err := os.Open(cleanFilename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hostnames []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hostnames = append(hostnames, scanner.Text())
	}

	return hostnames, scanner.Err()
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
