package apache2lb

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// --- 转换器上下文和规则 ---
type ConversionWarning struct {
	Line    int
	Message string
}

type ConversionContext struct {
	NginxConfig *strings.Builder
	Warnings    []ConversionWarning
	// 可以添加更多上下文信息，如当前 Nginx server/location 块的缩进级别
	IndentLevel int
}

func (ctx *ConversionContext) AddWarning(line int, format string, args ...interface{}) {
	ctx.Warnings = append(ctx.Warnings, ConversionWarning{
		Line:    line,
		Message: fmt.Sprintf(format, args...),
	})
}

func (ctx *ConversionContext) WriteLine(line string) {
	for i := 0; i < ctx.IndentLevel; i++ {
		ctx.NginxConfig.WriteString("    ") // 或者 "	"
	}
	ctx.NginxConfig.WriteString(line)
	ctx.NginxConfig.WriteString("\n")
}

func convertApacheDirectiveToNginx(directive ApacheDirective, ctx *ConversionContext) {
	if len(directive.Args) == 0 {
		return
	}
	switch strings.ToLower(directive.Name) {
	case "errorlog":
		ctx.WriteLine(fmt.Sprintf("error_log %s;", "logs/"+path.Base(directive.Args[0])))
	case "customlog":
		ctx.WriteLine(fmt.Sprintf("access_log %s %s;", "logs/"+path.Base(directive.Args[0]), "main"))
	case "directoryindex":
		ctx.WriteLine(fmt.Sprintf("index %s;", strings.Join(directive.Args, " ")))
	case "sslcertificatefile":
		ctx.WriteLine(fmt.Sprintf("ssl_certificate %s;", directive.Args[0]))
	case "sslcertificatekeyfile":
		ctx.WriteLine(fmt.Sprintf("ssl_certificate_key %s;", directive.Args[0]))
	case "sslcertificatechainfile": // Nginx 通常链文件和证书文件合并
		ctx.WriteLine(fmt.Sprintf("# Apache SSLCertificateChainFile: %s. In Nginx, this is often combined with ssl_certificate or use ssl_trusted_certificate.", directive.Args[0]))
		ctx.AddWarning(directive.Line, "SSLCertificateChainFile %s. Combine with ssl_certificate or use ssl_trusted_certificate for client auth.", directive.Args[0])
	case "sslprotocol":
		// Apache: SSLProtocol all -SSLv2 -SSLv3
		// Nginx: ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
		ctx.WriteLine(fmt.Sprintf("ssl_protocols %s;", "ssl_protocols TLSv1.2 TLSv1.3"))
		ctx.AddWarning(directive.Line, "SSLProtocol conversion is basic. Review Nginx ssl_protocols carefully")
	case "sslciphersuite": // Apache 2.4.8+
		ctx.WriteLine(fmt.Sprintf("ssl_ciphers %s; # default format", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"))
		ctx.AddWarning(directive.Line, "SSLCipherSuite converted to ssl_ciphers. Apache and Nginx cipher string formats differ. Nginx set default.")
	case "sslproxyengine": // 通常在 location proxy_pass 上下文
		if strings.EqualFold(directive.Args[0], "on") {
			ctx.AddWarning(directive.Line, "SSLProxyEngine on. If used with ProxyPass, Nginx proxy_ssl_* directives might be needed in the corresponding location block.")
		}
	case "sslproxyverify":
		if strings.EqualFold(directive.Args[0], "none") {
			ctx.WriteLine(fmt.Sprintf("proxy_ssl_verify %s;", "off"))
		}
	case "proxypass":
		if len(directive.Args) < 2 {
			ctx.AddWarning(directive.Line, "ProxyPass directive requires <localPath> <remoteURL>")
			return
		}
		localPath := directive.Args[0]
		remoteURL := directive.Args[1]
		// Note: Apache ProxyPass can have a third argument with key=value pairs for options.
		// This basic conversion does not parse those. Example: ProxyPass /app http://backend connectiontimeout=5

		ctx.WriteLine(fmt.Sprintf("location %s {", localPath))
		ctx.IndentLevel++
		ctx.WriteLine(fmt.Sprintf("proxy_pass %s;", remoteURL))
		ctx.WriteLine("") // Blank line for readability
		ctx.WriteLine("proxy_set_header Host $host;")
		ctx.WriteLine("proxy_set_header X-Real-IP $remote_addr;")
		ctx.WriteLine("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
		ctx.WriteLine("proxy_set_header X-Forwarded-Proto $scheme;")
		ctx.WriteLine("# Add other proxy settings if needed (e.g., timeouts, buffer sizes)")
		ctx.IndentLevel--
		ctx.WriteLine("}")
		ctx.AddWarning(directive.Line, "Generated basic 'location' block for ProxyPass '%s'", localPath)
	case "htaccess":
		ctx.IndentLevel-- // 减少缩进，因为htaccess转换生成的字符串已经缩进了
		converter := NewRewriteConf()
		output := converter.Convert(strings.Join(directive.Args, "\n"))
		outputs := strings.Split(output, "\n")
		for _, out := range outputs {
			if len(out) > 0 {
				ctx.WriteLine(out)
			}
		}
		ctx.IndentLevel++
	// ... 更多指令转换
	default:
		ctx.AddWarning(directive.Line, "Apache directive '%s' inside VirtualHost needs manual conversion for Nginx.", directive.Name)
		return
	}
	ctx.WriteLine("")
}

// func convertApacheBlockToNginx(block ApacheBlock, ctx *ConversionContext)

func ConvertToNginx(apacheConf *ApacheConfig) (string, []ConversionWarning) {
	ctx := &ConversionContext{
		NginxConfig: &strings.Builder{},
		Warnings:    make([]ConversionWarning, 0),
		IndentLevel: 0,
	}

	// 示例：转换全局指令 (Apache 全局指令不多，大多在 VirtualHost 内)
	for _, directive := range apacheConf.GlobalDirectives {
		// 示例：User/Group 通常在 nginx.conf 主配置文件，而不是 server 块
		if strings.EqualFold(directive.Name, "User") || strings.EqualFold(directive.Name, "Group") {
			ctx.WriteLine(fmt.Sprintf("# Consider setting '%s %s;' in the main nginx.conf (original line %d)", strings.ToLower(directive.Name), strings.Join(directive.Args, " "), directive.Line))
		} else if strings.EqualFold(directive.Name, "Include") || strings.EqualFold(directive.Name, "IncludeOptional") {
			if len(directive.Args) > 0 {
				ctx.WriteLine(fmt.Sprintf("include %s; # Original Apache Include on line %d", directive.Args[0], directive.Line))
				ctx.AddWarning(directive.Line, "Apache Include/IncludeOptional '%s' converted to Nginx include. Ensure path is valid for Nginx and files are also converted if they are Apache configs.", directive.Args[0])
			}
		} else {
			ctx.AddWarning(directive.Line, "Global Apache directive '%s' may need manual handling or placement in Nginx.", directive.Name)
		}
	}
	//默认配置
	ctx.WriteLine("user root;")
	ctx.WriteLine("worker_processes auto;")
	ctx.WriteLine("error_log logs/error.log warn;")
	ctx.WriteLine("events {")
	ctx.IndentLevel++
	ctx.WriteLine("worker_connections 1024;")
	ctx.IndentLevel--
	ctx.WriteLine("}")
	ctx.WriteLine("")

	ctx.WriteLine("http {") // 通常Nginx配置在http块内
	ctx.IndentLevel++
	ctx.WriteLine("include       mime.types;")
	ctx.WriteLine("default_type  application/octet-stream;")
	ctx.WriteLine("log_format  main  '$remote_addr - $remote_user [$time_local] \"$request\" '")
	ctx.WriteLine("                  '$status $body_bytes_sent \"$http_referer\" '")
	ctx.WriteLine("                  '\"$http_user_agent\" \"$http_x_forwarded_for\"';")
	ctx.WriteLine("access_log  logs/access.log  main;")
	ctx.WriteLine("sendfile        on;")
	ctx.WriteLine("keepalive_timeout  65;")
	ctx.WriteLine("")

	for _, block := range apacheConf.Blocks {
		if strings.EqualFold(block.Name, "VirtualHost") {
			ctx.WriteLine("server {")
			ctx.IndentLevel++

			// --- 处理 VirtualHost 参数和内部指令 ---
			// 解析 Listen, ServerName, ServerAlias 等
			var listenDirectives []string
			var serverNames []string
			var documentRoot string

			// 预扫描指令以收集关键信息
			for _, directive := range block.Directives {
				if strings.EqualFold(directive.Name, "Listen") { // Apache Listen 在 VirtualHost 内不常见，通常全局
					listenDirectives = append(listenDirectives, strings.Join(directive.Args, " "))
				} else if strings.EqualFold(directive.Name, "ServerName") {
					serverNames = append(serverNames, directive.Args...)
				} else if strings.EqualFold(directive.Name, "ServerAlias") {
					serverNames = append(serverNames, directive.Args...)
				} else if strings.EqualFold(directive.Name, "DocumentRoot") {
					if len(directive.Args) > 0 {
						documentRoot = directive.Args[0]
					}
				}
			}

			// 处理 <VirtualHost host:port> 参数
			if len(block.Args) > 0 {
				vhostArg := block.Args[0]
				// 简单解析 host:port, *:port, ip:port
				parts := strings.SplitN(vhostArg, ":", 2)
				port := "80" // 默认
				host := ""
				if len(parts) == 2 {
					host = parts[0]
					port = parts[1]
				} else {
					// 可能是 IP, Hostname, or *
					if strings.Contains(vhostArg, ".") || vhostArg == "*" || strings.Contains(vhostArg, "[") { // 粗略判断 IPv6 [::]:80
						host = vhostArg
					} else { // 可能是端口
						port = vhostArg
					}
				}

				listenStr := port
				// Nginx listen 格式: address[:port] [ssl] [http2] [proxy_protocol] [setfib=number] [fastopen=number] ...
				// Apache: IP:Port, *:Port, Port
				if host != "" && host != "*" && host != "_default_" {
					// 如果 host 是 IP 地址，则 Nginx listen 可以是 IP:Port
					// 如果 host 是域名，则不应放在 Nginx listen 指令的地址部分，而是由 server_name 处理
					// Apache 的 <VirtualHost example.com:80> 行为是监听所有 IP 的 80 端口，然后匹配 Host header
					// Nginx 中，这通常是 listen 80; server_name example.com;
					// 如果 host 是一个具体的 IP，如 <VirtualHost 192.168.1.1:80>，则 Nginx listen 192.168.1.1:80;
					isIP := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^\[.*\]$`).MatchString(host) // 简单IP判断
					if isIP {
						listenStr = fmt.Sprintf("%s:%s", host, port)
					} else if len(serverNames) == 0 { // 如果 ServerName 没指定，用这个host作为server_name
						serverNames = append(serverNames, host)
					}
				}
				listenDirectives = append(listenDirectives, listenStr)
			}

			if len(listenDirectives) == 0 {
				listenDirectives = append(listenDirectives, "80") // 默认
			}
			uniqueListens := make(map[string]bool)
			for _, l := range listenDirectives {
				if !uniqueListens[l] {
					// 检查是否有 SSL 指令，如果有，则添加 ssl 到 listen
					hasSSL := false
					for _, dir := range block.Directives {
						if strings.EqualFold(dir.Name, "SSLEngine") && len(dir.Args) > 0 && strings.EqualFold(dir.Args[0], "on") {
							hasSSL = true
							break
						}
					}
					if hasSSL && !strings.Contains(l, "ssl") { // 避免重复添加 ssl
						ctx.WriteLine(fmt.Sprintf("listen %s ssl;", l))
					} else {
						ctx.WriteLine(fmt.Sprintf("listen %s;", l))
					}
					uniqueListens[l] = true
				}
			}

			if len(serverNames) > 0 {
				ctx.WriteLine(fmt.Sprintf("server_name %s;", strings.Join(serverNames, " ")))
			} else {
				ctx.AddWarning(block.Line, "<VirtualHost> block without ServerName/ServerAlias. Nginx might require a server_name or use default.")
			}

			if documentRoot != "" {
				ctx.WriteLine(fmt.Sprintf("root %s;", documentRoot))
			}

			// 转换 VirtualHost 内的其他指令 (伪代码)
			for _, directive := range block.Directives {
				// skip already processed directives
				if strings.EqualFold(directive.Name, "Listen") ||
					strings.EqualFold(directive.Name, "ServerName") ||
					strings.EqualFold(directive.Name, "ServerAlias") ||
					strings.EqualFold(directive.Name, "DocumentRoot") ||
					strings.EqualFold(directive.Name, "SSLEngine") { // SSLEngine 被 listen ssl 处理
					continue
				}
				convertApacheDirectiveToNginx(directive, ctx)

				// 转换嵌套块 (如 <Directory>, <Location>) (伪代码)
				//for _, childBlock := range block.Children {
				//	// convertApacheBlockToNginx(childBlock, ctx)
				//	// 简单的占位符，实际转换需要递归调用并增加缩进
				//	ctx.WriteLine("") // 空行分隔
				//	ctx.AddWarning(childBlock.Line, "Attempting basic conversion for Apache block '<%s>' to Nginx location.", childBlock.Name)
				//	locationPath := "/"
				//	if len(childBlock.Args) > 0 {
				//		locationPath = strings.Trim(childBlock.Args[0], "\"") // 去除引号
				//	}
				//	// 简单处理，实际需要区分 Directory, DirectoryMatch, Location, LocationMatch
				//	// 并正确处理路径和正则表达式
				//	matchType := ""
				//	if strings.EqualFold(childBlock.Name, "DirectoryMatch") || strings.EqualFold(childBlock.Name, "LocationMatch") {
				//		matchType = "~ "                          // 假设是大小写敏感正则
				//		if strings.HasPrefix(locationPath, "~") { // Apache <Directory ~ "regex">
				//			locationPath = strings.TrimSpace(strings.TrimPrefix(locationPath, "~"))
				//		}
				//	} else if strings.EqualFold(childBlock.Name, "Directory") {
				//		// Apache <Directory path> 是文件系统路径，Nginx location 是 URL 路径
				//		// 这是一个复杂点，需要根据 DocumentRoot 和 Alias 来推断 URL 路径
				//		ctx.AddWarning(childBlock.Line, "<Directory %s> conversion to Nginx location is complex. Assuming path maps directly to URL. Review carefully.", locationPath)
				//	}
				//
				//	ctx.WriteLine(fmt.Sprintf("location %s%s {", matchType, locationPath))
				//	ctx.IndentLevel++
				//	// 转换子块内部的指令
				//	for _, dir := range childBlock.Directives {
				//		// 这里应该调用一个转换指令的函数
				//		ctx.WriteLine(fmt.Sprintf("# Apache (L%d): %s %s", dir.Line, dir.Name, strings.Join(dir.Args, " ")))
				//		ctx.AddWarning(dir.Line, "Directive '%s' inside <%s> block needs manual conversion for Nginx location.", dir.Name, childBlock.Name)
				//	}
				//	ctx.IndentLevel--
				//	ctx.WriteLine("}")
				//
			}

			ctx.IndentLevel--
			ctx.WriteLine("} # end server")
			ctx.WriteLine("")
		} else {
			ctx.AddWarning(block.Line, "Top-level Apache block '<%s>' needs manual conversion for Nginx.", block.Name)
		}
	}
	ctx.IndentLevel--
	ctx.WriteLine("} # end http")

	return ctx.NginxConfig.String(), ctx.Warnings
}
