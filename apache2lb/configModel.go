package apache2lb

// Apache 指令
type ApacheDirective struct {
	Name        string       // 指令名称，如 ServerName, DocumentRoot
	Args        []string     // 指令参数列表
	Line        int          // 原始文件中的行号 (用于调试和错误报告)
	Comments    []string     // 指令前后的注释 (可选，但有助于保留信息)
	ParentBlock *ApacheBlock // 指向父块 (可选，便于上下文分析)
}

// Apache 配置块
type ApacheBlock struct {
	Name        string            // 块名称，如 VirtualHost, Directory
	Args        []string          // 块的参数，如 *:80
	Directives  []ApacheDirective // 块内部的指令
	Children    []*ApacheBlock    // 嵌套的块
	Line        int
	Comments    []string
	ParentBlock *ApacheBlock // 指向父块
}

// 整个 Apache 配置
type ApacheConfig struct {
	GlobalDirectives []ApacheDirective // 全局指令
	Blocks           []*ApacheBlock    // 顶层块 (主要是 VirtualHost)
	Includes         []string          // Include 的文件路径 (需要递归处理)
	RawLines         []string          // 原始文件行 (可选，用于无法解析时的回退)
}
