package main

import (
	"apache2lb/apache2lb"
	"flag"
	"log"
	"os"
)

func main() {
	apacheConfFile := flag.String("apache", "httpd.conf", "Path to Apache configuration file")
	nginxOutFile := flag.String("nginx", "nginx.conf.generated", "Path to output Nginx configuration file")
	flag.Parse()

	if *apacheConfFile == "" {
		log.Fatal("Apache configuration file path must be provided via -apache flag.")
	}

	log.Printf("Parsing Apache config: %s", *apacheConfFile)
	apacheAST, parseErrors := apache2lb.ParseApacheFile(*apacheConfFile)
	if len(parseErrors) > 0 {
		log.Println("--- Errors during parsing Apache config ---")
		for _, e := range parseErrors {
			log.Printf("  %s", e.Error())
		}
		log.Println("--- End of Parsing Errors ---")
	}
	if apacheAST == nil && len(parseErrors) > 0 { // 如果AST是nil且有错误，则可能无法继续
		log.Fatal("Failed to parse Apache config due to critical errors. Cannot continue conversion.")
	}
	if apacheAST == nil { // 如果AST是nil但没有错误（例如空文件），则可以生成一个空的Nginx配置
		apacheAST = &apache2lb.ApacheConfig{} // 创建一个空的AST以避免nil指针
		log.Println("Warning: Apache configuration file was empty or resulted in no parseable content.")
	}
	// 模拟一个简单的 ApacheConfig 供演示
	//apacheAST := &ApacheConfig{
	//	Blocks: []*ApacheBlock{
	//		{
	//			Name: "VirtualHost",
	//			Args: []string{"*:90"},
	//			Line: 10,
	//			Directives: []ApacheDirective{
	//				{Name: "ServerName", Args: []string{"example.com"}, Line: 11},
	//				{Name: "ServerAlias", Args: []string{"www.example.com", "test.example.com"}, Line: 12},
	//				{Name: "DocumentRoot", Args: []string{"/var/www/html"}, Line: 13},
	//				{Name: "ErrorLog", Args: []string{"/var/log/apache2/error.log"}, Line: 14},
	//				{Name: "CustomLog", Args: []string{"/var/log/apache2/access.log", "combined"}, Line: 15},
	//			},
	//		},
	//	},
	//}

	log.Println("Converting to Nginx configuration...")
	nginxResult, warnings := apache2lb.ConvertToNginx(apacheAST)

	if len(warnings) > 0 {
		log.Println("\n--- Warnings (Manual Review Required for Nginx Config) ---")
		for _, warn := range warnings {
			log.Printf("  L%d (Apache Ref): %s", warn.Line, warn.Message)
		}
		log.Println("--- End of Warnings ---")
	}

	log.Printf("Writing Nginx configuration to: %s", *nginxOutFile)
	err := os.WriteFile(*nginxOutFile, []byte(nginxResult), 0644)
	if err != nil {
		log.Fatalf("Error writing Nginx config: %v", err)
	}

	log.Println("Conversion complete. Please review the generated Nginx configuration carefully.")
}
