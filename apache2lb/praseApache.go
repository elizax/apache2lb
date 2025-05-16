package apache2lb

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// --- 解析器部分 ---

// ParseError 结构用于存储解析过程中的错误信息
type ParseError struct {
	Line    int
	Message string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Message)
}

// splitDirectiveArgs 将指令行分割为指令名和参数列表
// 它尝试处理被引号包围的参数
func splitDirectiveArgs(line string) (string, []string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil
	}
	directiveName := parts[0]
	rawArgs := strings.TrimSpace(strings.TrimPrefix(line, directiveName))

	var args []string
	var currentArg strings.Builder
	inQuote := false
	for i, r := range rawArgs {
		if r == '"' {
			inQuote = !inQuote
			if !inQuote && currentArg.Len() > 0 { // 结束一个引号参数
				// 如果引号是参数的一部分，则保留它们，否则可以去掉
				// args = append(args, currentArg.String())
				// currentArg.Reset()
			}
			currentArg.WriteRune(r) // 保留引号
			continue
		}
		if r == ' ' && !inQuote {
			if currentArg.Len() > 0 {
				args = append(args, currentArg.String())
				currentArg.Reset()
			}
			continue
		}
		currentArg.WriteRune(r)
		// 处理最后一个参数
		if i == len(rawArgs)-1 && currentArg.Len() > 0 {
			args = append(args, currentArg.String())
		}
	}
	// 如果参数是用空格分隔且没有引号的简单情况，上面的逻辑可能不够完美
	// 对于更简单的场景，可以直接使用 strings.Fields(rawArgs)
	// 但为了处理引号，需要更复杂的逻辑。
	// 一个折中方案：如果初步分割后，参数看起来像是被引号破坏的，则尝试合并
	// 此处为了简化，我们先用一个基础的分割，实际项目中需要更健壮的解析器
	if len(args) == 0 && rawArgs != "" { // 如果上面的复杂逻辑没有产生参数，但确实有参数字符串
		args = strings.Fields(rawArgs) // 回退到简单分割
	}

	// 清理参数，去除可能的多余引号 (如果参数本身不是带引号的字符串)
	cleanedArgs := make([]string, 0, len(args))
	for _, arg := range args {
		if len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"' {
			cleanedArgs = append(cleanedArgs, arg[1:len(arg)-1])
		} else {
			cleanedArgs = append(cleanedArgs, arg)
		}
	}
	return directiveName, cleanedArgs
}

// parseApacheFile 解析指定的 Apache 配置文件路径
func ParseApacheFile(filePath string) (*ApacheConfig, []ParseError) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, []ParseError{{Line: 0, Message: fmt.Sprintf("Error opening file %s: %v", filePath, err)}}
	}
	defer file.Close()

	config := &ApacheConfig{}
	var errors []ParseError
	var currentBlock *ApacheBlock // 当前正在处理的块
	var blockStack []*ApacheBlock // 用于处理嵌套块的栈
	var htaccess []string         //用于存储block中的htaccess

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	var accumulatedLine strings.Builder // 用于处理续行符

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// 处理续行符 '\'
		if strings.HasSuffix(line, "\\") {
			accumulatedLine.WriteString(strings.TrimSuffix(line, "\\"))
			accumulatedLine.WriteString(" ") // 在续行处添加空格，以防两行内容粘连
			continue
		}
		if accumulatedLine.Len() > 0 {
			accumulatedLine.WriteString(line)
			line = accumulatedLine.String()
			accumulatedLine.Reset()
			line = strings.TrimSpace(line) // 合并后再次 trim
		}

		if line == "" || strings.HasPrefix(line, "#") {
			// TODO: 可以考虑保留注释并关联到下一个指令或块
			continue
		}

		// 尝试匹配块结束标签: </BlockName>
		if strings.HasPrefix(line, "</") && strings.HasSuffix(line, ">") {
			if len(htaccess) != 0 {
				htaccessContent := ApacheDirective{
					Name: "htaccess",
					Args: htaccess,
					Line: lineNumber,
				}
				if currentBlock != nil {
					htaccessContent.ParentBlock = currentBlock
					currentBlock.Directives = append(currentBlock.Directives, htaccessContent)
				} else {
					config.GlobalDirectives = append(config.GlobalDirectives, htaccessContent)
				}
			}

			htaccess = []string{}

			if len(blockStack) == 0 {
				errors = append(errors, ParseError{Line: lineNumber, Message: fmt.Sprintf("Unmatched closing tag: %s", line)})
				currentBlock = nil // 无效状态
				continue
			}
			expectedBlockName := strings.TrimSuffix(strings.TrimPrefix(line, "</"), ">")
			if currentBlock == nil || !strings.EqualFold(currentBlock.Name, expectedBlockName) { // 不区分大小写比较块名
				errors = append(errors, ParseError{Line: lineNumber, Message: fmt.Sprintf("Mismatched closing tag: found %s, expected </%s>", line, expectedBlockName)})
				// 尝试从栈中恢复，或者标记错误并继续
			}
			// 从栈中弹出当前块
			blockStack = blockStack[:len(blockStack)-1]
			if len(blockStack) > 0 {
				currentBlock = blockStack[len(blockStack)-1]
			} else {
				currentBlock = nil // 回到全局作用域
			}
			continue
		}

		// 尝试匹配块开始标签: <BlockName args...>
		// 使用正则表达式来更健壮地捕获块名和参数
		// 例如: <VirtualHost *:80> or <Directory "/var/www/html"> or <IfVersion >= 2.4>
		//blockRegex := regexp.MustCompile(`^<(\S+)(?:\s+([^>]*))?>$`)
		//matches := blockRegex.FindStringSubmatch(line)

		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && line[1] != '/' {
			htaccess = []string{}

			matches := strings.Split(line[1:len(line)-1], " ")

			if len(matches) > 0 {
				blockName := matches[0]
				blockArgsStr := ""

				for i := 1; i < len(matches); i++ {
					blockArgsStr += strings.TrimSpace(matches[i])
				}

				// TODO: 更精细地分割 blockArgsStr，处理引号等
				var blockArgs []string
				if blockArgsStr != "" {
					// 简单的按空格分割，实际可能需要更复杂的逻辑处理带引号的参数
					blockArgs = strings.Fields(blockArgsStr)
					// 清理参数中的引号
					for i, arg := range blockArgs {
						blockArgs[i] = strings.Trim(arg, "\"")
					}
				}

				newBlock := &ApacheBlock{
					Name:       blockName,
					Args:       blockArgs,
					Line:       lineNumber,
					Directives: make([]ApacheDirective, 0),
					Children:   make([]*ApacheBlock, 0),
				}

				if currentBlock != nil {
					newBlock.ParentBlock = currentBlock
					currentBlock.Children = append(currentBlock.Children, newBlock)
				} else {
					config.Blocks = append(config.Blocks, newBlock)
				}
				blockStack = append(blockStack, newBlock) // 新块入栈
				currentBlock = newBlock                   // 设置为当前块
				continue
			}
		}
		// 如果不是块标签，则认为是指令
		directiveName, directiveArgs := splitDirectiveArgs(line)
		if directiveName == "" {
			errors = append(errors, ParseError{Line: lineNumber, Message: fmt.Sprintf("Unable to parse directive: %s", line)})
			continue
		}

		directive := ApacheDirective{
			Name: directiveName,
			Args: directiveArgs,
			Line: lineNumber,
		}

		if strings.EqualFold(directiveName, "Include") || strings.EqualFold(directiveName, "IncludeOptional") {
			if len(directiveArgs) > 0 {
				config.Includes = append(config.Includes, directiveArgs[0])
				// 注意：这里只是记录了Include指令，实际转换时需要递归解析这些文件
				// 转换器需要处理 Include 路径的解析（相对路径、绝对路径）
				parseApacheIncludeFile(directiveArgs[0], config, currentBlock, blockStack, errors)
			} else {
				errors = append(errors, ParseError{Line: lineNumber, Message: fmt.Sprintf("'%s' directive without a path argument", directiveName)})
			}
			// Include 指令通常不属于某个特定块的直接子指令，而是影响整体配置
			// 但为了简单起见，如果它在块内，我们也可以先加进去，转换时特殊处理
		}

		//处理htacess
		if strings.EqualFold(directiveName, "RewriteEngine") || strings.EqualFold(directiveName, "RewriteRule") || strings.EqualFold(directiveName, "RewriteCond") {
			htaccess = append(htaccess, line)
			continue
		}

		if currentBlock != nil {
			directive.ParentBlock = currentBlock
			currentBlock.Directives = append(currentBlock.Directives, directive)
		} else {
			config.GlobalDirectives = append(config.GlobalDirectives, directive)
		}
	}

	if err := scanner.Err(); err != nil {
		errors = append(errors, ParseError{Line: 0, Message: fmt.Sprintf("Error reading file: %v", err)})
	}

	if len(blockStack) > 0 {
		for _, openBlock := range blockStack {
			errors = append(errors, ParseError{Line: openBlock.Line, Message: fmt.Sprintf("Unclosed block: <%s>", openBlock.Name)})
		}
	}

	// 填充 RawLines (可选)
	// file.Seek(0, 0) // Reset scanner if needed for a second pass, or store lines during first pass
	// rawScanner := bufio.NewScanner(file)
	// for rawScanner.Scan() {
	// 	config.RawLines = append(config.RawLines, rawScanner.Text())
	// }

	return config, errors
}

// parseApacheIncludeFile 解析指定的 Apache 配置文件Include
func parseApacheIncludeFile(filePath string, config *ApacheConfig, currentBlock *ApacheBlock, blockStack []*ApacheBlock, errors []ParseError) {
	file, err := os.Open(filePath)
	if err != nil {
		errors = append(errors, ParseError{Line: 0, Message: fmt.Sprintf("Error opening file %s: %v", filePath, err)})
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	var accumulatedLine strings.Builder // 用于处理续行符

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// 处理续行符 '\'
		if strings.HasSuffix(line, "\\") {
			accumulatedLine.WriteString(strings.TrimSuffix(line, "\\"))
			accumulatedLine.WriteString(" ") // 在续行处添加空格，以防两行内容粘连
			continue
		}
		if accumulatedLine.Len() > 0 {
			accumulatedLine.WriteString(line)
			line = accumulatedLine.String()
			accumulatedLine.Reset()
			line = strings.TrimSpace(line) // 合并后再次 trim
		}

		if line == "" || strings.HasPrefix(line, "#") {
			// TODO: 可以考虑保留注释并关联到下一个指令或块
			continue
		}

		// 尝试匹配块结束标签: </BlockName>
		if strings.HasPrefix(line, "</") && strings.HasSuffix(line, ">") {
			if len(blockStack) == 0 {
				errors = append(errors, ParseError{Line: lineNumber, Message: fmt.Sprintf("Unmatched closing tag: %s", line)})
				currentBlock = nil // 无效状态
				continue
			}
			expectedBlockName := strings.TrimSuffix(strings.TrimPrefix(line, "</"), ">")
			if currentBlock == nil || !strings.EqualFold(currentBlock.Name, expectedBlockName) { // 不区分大小写比较块名
				errors = append(errors, ParseError{Line: lineNumber, Message: fmt.Sprintf("Mismatched closing tag: found %s, expected </%s>", line, currentBlock.Name)})
				// 尝试从栈中恢复，或者标记错误并继续
			}
			// 从栈中弹出当前块
			blockStack = blockStack[:len(blockStack)-1]
			if len(blockStack) > 0 {
				currentBlock = blockStack[len(blockStack)-1]
			} else {
				currentBlock = nil // 回到全局作用域
			}
			continue
		}

		// 尝试匹配块开始标签: <BlockName args...>
		// 使用正则表达式来更健壮地捕获块名和参数
		// 例如: <VirtualHost *:80> or <Directory "/var/www/html"> or <IfVersion >= 2.4>
		//blockRegex := regexp.MustCompile(`^<(\S+)(?:\s+([^>]*))?>$`)
		//matches := blockRegex.FindStringSubmatch(line)

		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && line[1] != '/' {
			matches := strings.Split(line[1:len(line)-1], " ")

			if len(matches) > 0 {
				blockName := matches[0]
				blockArgsStr := ""

				for i := 1; i < len(matches); i++ {
					blockArgsStr += strings.TrimSpace(matches[i])
				}

				// TODO: 更精细地分割 blockArgsStr，处理引号等
				var blockArgs []string
				if blockArgsStr != "" {
					// 简单的按空格分割，实际可能需要更复杂的逻辑处理带引号的参数
					blockArgs = strings.Fields(blockArgsStr)
					// 清理参数中的引号
					for i, arg := range blockArgs {
						blockArgs[i] = strings.Trim(arg, "\"")
					}
				}

				newBlock := &ApacheBlock{
					Name:       blockName,
					Args:       blockArgs,
					Line:       lineNumber,
					Directives: make([]ApacheDirective, 0),
					Children:   make([]*ApacheBlock, 0),
				}

				if currentBlock != nil {
					newBlock.ParentBlock = currentBlock
					currentBlock.Children = append(currentBlock.Children, newBlock)
				} else {
					config.Blocks = append(config.Blocks, newBlock)
				}
				blockStack = append(blockStack, newBlock) // 新块入栈
				currentBlock = newBlock                   // 设置为当前块
				continue
			}
		}
		// 如果不是块标签，则认为是指令
		directiveName, directiveArgs := splitDirectiveArgs(line)
		if directiveName == "" {
			errors = append(errors, ParseError{Line: lineNumber, Message: fmt.Sprintf("Unable to parse directive: %s", line)})
			continue
		}

		directive := ApacheDirective{
			Name: directiveName,
			Args: directiveArgs,
			Line: lineNumber,
		}

		if strings.EqualFold(directiveName, "Include") || strings.EqualFold(directiveName, "IncludeOptional") {
			if len(directiveArgs) > 0 {
				config.Includes = append(config.Includes, directiveArgs[0])
				// 注意：这里只是记录了Include指令，实际转换时需要递归解析这些文件
				// 转换器需要处理 Include 路径的解析（相对路径、绝对路径）
				parseApacheIncludeFile(directiveArgs[0], config, currentBlock, blockStack, errors)
			} else {
				errors = append(errors, ParseError{Line: lineNumber, Message: fmt.Sprintf("'%s' directive without a path argument", directiveName)})
			}
		}

		if currentBlock != nil {
			directive.ParentBlock = currentBlock
			currentBlock.Directives = append(currentBlock.Directives, directive)
		} else {
			config.GlobalDirectives = append(config.GlobalDirectives, directive)
		}
	}

	if err := scanner.Err(); err != nil {
		errors = append(errors, ParseError{Line: 0, Message: fmt.Sprintf("Error reading file: %v", err)})
	}

	if len(blockStack) > 0 {
		for _, openBlock := range blockStack {
			errors = append(errors, ParseError{Line: openBlock.Line, Message: fmt.Sprintf("Unclosed block: <%s>", openBlock.Name)})
		}
	}

	return
}
