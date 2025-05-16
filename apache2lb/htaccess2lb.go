package apache2lb

//根据rewrite-conf.js进行翻译的go代码

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// RewriteConf 是处理重写规则转换的主要结构体。
type RewriteConf struct{}

// ParsedFlags 代表从 RewriteRule 或 RewriteCond 解析的标志。
type ParsedFlags struct {
	Return        int      `json:"return"`        // 0 或 HTTP 状态码
	Break         int      `json:"break"`         // 0 或 1 (用于内部逻辑，Nginx 中通常是 last)
	AppendEnd     string   `json:"appendEnd"`     // last|permanent|redirect (JS 中有 break，这里映射到 Nginx 行为)
	Env           []string `json:"env"`           // var=value
	MatchOperator string   `json:"matchOperator"` // ~* (不区分大小写) 或 ~ (区分大小写)
	Unknown       int      `json:"unknown"`       // 0 或 1 (根据 JS 逻辑分析，此值始终为 0)
	Set           []string `json:"set"`           // 用于 Nginx 的 set 指令，例如 "$rule_0 1"
}

// RewriteRuleRaw 存储 RewriteRule 的原始部分。
type RewriteRuleRaw struct {
	Regex string   `json:"regex"`
	Rew   string   `json:"rew"`
	Flags []string `json:"flags"` // 原始标志字符串数组, e.g., ["L", "R=301"]
}

// RewriteRuleProcessed 存储 RewriteRule 的处理后数据。
type RewriteRuleProcessed struct {
	Regex   string      `json:"regex,omitempty"`   // 可选，因为 RewriteRule "-" 会删除它
	Rew     string      `json:"rew,omitempty"`     // 可选
	Flags   ParsedFlags `json:"flags"`             // 解析后的标志
	TrueExp string      `json:"trueExp,omitempty"` // 用于 Nginx $rule_X 变量检查
	Raw     string      `json:"-"`                 // 存储原始规则行，用于可能的注释
}

// RewriteCondRaw 存储 RewriteCond 的原始部分。
type RewriteCondRaw struct {
	Match string   `json:"match"` // TestString
	Rule  string   `json:"rule"`  // CondPattern
	Flags []string `json:"flags"` // 原始标志字符串数组
	Raw   string   `json:"-"`     // 存储原始条件行
}

// ConditionMatch 存储解析后的 RewriteCond 详细信息，用于 Nginx 'if' 块。
type ConditionMatch struct {
	Left    string      `json:"left"`
	Right   string      `json:"right"`
	Operand string      `json:"operand"`
	Flags   ParsedFlags `json:"flags"` // 解析后的标志
	Raw     string      `json:"-"`     // 存储原始条件行
}

// RuleWithConditions 将 RewriteRule 与其前面的 RewriteConds 组合在一起。
type RuleWithConditions struct {
	Rule       RewriteRuleRaw   `json:"rule"`
	CondBit    string           `json:"condBit"` // "AND" 或 "OR"
	Conditions []RewriteCondRaw `json:"conditions"`
}

// FinalConfigItem 代表一个完全解析和处理过的规则/条件集，准备好生成 Nginx 配置。
// 它也用于 _walkRecursive 替换变量。
type FinalConfigItem struct {
	Conds         []ConditionMatch     `json:"conds"`
	Rule          RewriteRuleProcessed `json:"rule"`
	CondBit       string               `json:"condBit"`
	OriginalIndex int                  // 用于生成 $rule_X 中的 X
	// 如果整个条目由于 _mustSkipForCond (虽然目前看来不会发生) 而被跳过，
	// 可以添加一个 SkipMessage 字段。但基于JS分析，这个路径不会被采用。
}

// NewRewriteConf 创建一个新的 RewriteConf 实例。
func NewRewriteConf() *RewriteConf {
	return &RewriteConf{}
}

// Convert 是将 Apache 重写规则内容转换为 Nginx 配置的入口点。
func (rc *RewriteConf) Convert(content string) string {
	configs := rc._parseContent(content)
	return rc._writeConfig(configs)
}

func (rc *RewriteConf) _trimLine(str string) string {
	return strings.TrimSpace(str)
}

// _parseLine 解析 Apache 配置中的单行。
// 返回: [regex/match, rew/rule, flagsArray]
func (rc *RewriteConf) _parseLine(line string) (string, string, []string) {
	parts := strings.Fields(line) // 使用 Fields 来处理多个空格
	var p1, p2, p3 string
	if len(parts) > 1 {
		p1 = parts[1]
	}
	if len(parts) > 2 {
		p2 = parts[2]
	}
	if len(parts) > 3 {
		p3 = parts[3] // flags string, e.g., [L,R=301]
	}

	var flagsArray []string
	if p3 != "" && strings.HasPrefix(p3, "[") && strings.HasSuffix(p3, "]") {
		// 去掉首尾的 '[' 和 ']'
		flagsStr := p3[1 : len(p3)-1]
		rawFlags := strings.Split(flagsStr, ",")
		for _, flag := range rawFlags {
			trimmedFlag := rc._trimLine(flag)
			if trimmedFlag != "" {
				flagsArray = append(flagsArray, trimmedFlag)
			}
		}
	}
	return p1, p2, flagsArray
}

// _arrayUnique 返回一个包含源数组唯一元素的新数组。
func (rc *RewriteConf) _arrayUnique(source []string) []string {
	seen := make(map[string]struct{})
	result := []string{}
	for _, item := range source {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// _readRules 从内容中读取所有规则和条件。
func (rc *RewriteConf) _readRules(content string) []RuleWithConditions {
	lines := strings.Split(content, "\n")
	var currentConds []RewriteCondRaw
	var rules []RuleWithConditions

	for _, lineStr := range lines {
		line := rc._trimLine(lineStr)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matchOrRegex, ruleOrRew, flags := rc._parseLine(line)

		if strings.HasPrefix(strings.ToUpper(line), "REWRITECOND") {
			currentConds = append(currentConds, RewriteCondRaw{
				Match: matchOrRegex,
				Rule:  ruleOrRew,
				Flags: flags,
				Raw:   lineStr,
			})
		} else if strings.HasPrefix(strings.ToUpper(line), "REWRITERULE") {
			condBit := "AND"
			if len(currentConds) > 0 {
				// 检查第一个条件的标志中是否包含 "OR"
				firstCondFlags := currentConds[0].Flags
				for _, flag := range firstCondFlags {
					if strings.ToUpper(flag) == "OR" {
						condBit = "OR"
						break
					}
				}
			}
			rules = append(rules, RuleWithConditions{
				Rule: RewriteRuleRaw{
					Regex: matchOrRegex,
					Rew:   ruleOrRew,
					Flags: flags,
				},
				CondBit:    condBit,
				Conditions: currentConds, // 使用副本以避免后续修改影响
			})
			currentConds = []RewriteCondRaw{} // 为下一个 RewriteRule 重置条件
		}
	}
	return rules
}

// _parseFlags 解析标志数组。
// type: 0 -> rule, 1 -> condition (在JS中几乎未使用，这里保留以防万一)
// r: rule index, c: condition index (用于 $rule_r 变量名)
func (rc *RewriteConf) _parseFlags(flagArray []string, ruleType int, r int, c int) ParsedFlags {
	parsed := ParsedFlags{
		Return:        0,
		Break:         0,
		AppendEnd:     "",
		Env:           []string{},
		MatchOperator: "~", // 默认为区分大小写匹配
		Unknown:       0,   // 根据JS分析，这个值实际上总是0
		Set:           []string{},
	}

	for _, flag := range flagArray {
		// JS的 `flag.charAt(0)` 对于空字符串会出错，Go中取子串前需要检查长度。
		// 但flagArray中的元素应由_parseLine保证非空。
		// 对于像 R=301 这样的标志，我们只关心第一个字符。
		// NC (NoCase) -> N
		// OR (Next Rule OR) -> O (JS用O代表OR, A代表AND)
		// 这些标志在Apache中是[NC,OR], 而不是N,C,O,R
		// JS的 switch (flag.charAt(0)) 逻辑是针对短格式或已处理过的标志
		// 这里我们假设 flagArray 包含的是 "L", "R=301", "NC", "OR" 这样的字符串

		upperFlag := strings.ToUpper(flag)

		switch {
		case upperFlag == "NC": // NoCase
			parsed.MatchOperator = "~*"
			// JS: if ('undefined' == typeof returnArray["unknown"]) { returnArray["unknown"] = 0; }
			// 由于 parsed.Unknown 初始化为0，这个JS逻辑在这里不起作用。
		case upperFlag == "F": // Forbidden
			parsed.Return = 403
			parsed.Break = 1
		case upperFlag == "G": // Gone
			parsed.Return = 410
			parsed.Break = 1
		case strings.HasPrefix(upperFlag, "R") || strings.HasPrefix(upperFlag, "REDIRECT"): // Redirect
			rcode := "302" // 默认临时重定向
			if strings.Contains(upperFlag, "=") {
				parts := strings.SplitN(flag, "=", 2)
				if len(parts) == 2 {
					val := strings.ToLower(parts[1])
					if val == "301" || val == "permanent" {
						rcode = "301"
					}
					// 其他状态码如303, temp等可以按需添加
				}
			}
			if rcode == "301" {
				parsed.AppendEnd = "permanent"
			} else {
				parsed.AppendEnd = "redirect" // Nginx 'redirect' 默认是 302
			}
			parsed.Break = 1
		case upperFlag == "L": // Last
			if parsed.AppendEnd == "" { // R 标志优先
				parsed.AppendEnd = "last"
			}
		case strings.HasPrefix(upperFlag, "E="): // Environment variable
			parts := strings.SplitN(flag, "=", 2)
			if len(parts) == 2 {
				parsed.Env = append(parsed.Env, parts[1])
			}
		// JS中的 'O' 和 'A' 标志用于生成 $rule_X 变量，这在 Apache 中是 OR 和 AND 的链式逻辑
		// 在Apache中，[OR] 是一个标志。JS的 _parseFlags 中 'O' 和 'A' case 是其内部转换逻辑
		// 我们在 _parseCondMatch 中将 condBit (OR/AND) 也加入 flags 列表来触发这个
		case upperFlag == "OR": // Corresponds to 'O' in JS _parseFlags's set logic
			// $rule_r = "1"  (r is rule index)
			parsed.Set = append(parsed.Set, fmt.Sprintf("$rule_%d 1", r))
		case upperFlag == "AND": // Corresponds to 'A' in JS _parseFlags's set logic
			// $rule_r = (c+1)$rule_r (c is condition index)
			// 确保 $rule_%d 存在，如果不存在，则效果可能不佳
			// JS: '$rule_' + r + ' ' + (c + 1) + '$rule_' + r
			// 这似乎是在构建一个字符串值，例如 set $rule_0 "1$rule_0";
			parsed.Set = append(parsed.Set, fmt.Sprintf("$rule_%d %d$rule_%d", r, c+1, r))
		}
	}

	// JS的最后一部分关于 unknown 的逻辑:
	// if (flagArray.length > 1) {
	//     if ('undefined' == typeof returnArray["unknown"]) {
	//         returnArray["unknown"] = 1;
	//     }
	// } else {
	//     returnArray["unknown"] = 0;
	// }
	// 由于 returnArray["unknown"] 总是被初始化为0，并且JS中 'undefined' == typeof 0 为 false，
	// 所以这个逻辑块实际上总是使 unknown 为0。
	// parsed.Unknown = 0; // 已经是默认值
	return parsed
}

// _parseCondMatch 解析 RewriteCond。
func (rc *RewriteConf) _parseCondMatch(condition RewriteCondRaw, r int, c int, condBit string) ConditionMatch {
	matchOperator := "~" // 默认区分大小写
	noMatch := ""
	condRule := condition.Rule

	if strings.HasPrefix(condRule, "!") {
		noMatch = "!"
		condRule = condRule[1:]
	}

	// 将 condBit (OR/AND) 添加到条件标志中，以供 _parseFlags 处理
	// 这是为了模拟JS中将 OR/AND 传递给 _parseFlags 以便在 set 数组中生成 $rule_X 逻辑
	tempFlags := make([]string, len(condition.Flags))
	copy(tempFlags, condition.Flags)
	if condBit == "OR" { // JS 将 "OR" 标志添加到条件标志列表以触发 'O' case
		tempFlags = append(tempFlags, "OR") // "OR" 会在 _parseFlags 中触发 'O' case
	} else { // "AND"
		tempFlags = append(tempFlags, "AND") // "AND" 会在 _parseFlags 中触发 'A' case
	}
	tempFlags = rc._arrayUnique(tempFlags)

	fromFlags := rc._parseFlags(tempFlags, 1, r, c) // type 1 for condition

	if fromFlags.MatchOperator != "" { // 如果 NC 标志设置了 ~*
		matchOperator = fromFlags.MatchOperator
	}

	var left, right, operand string
	switch condRule {
	case "-f": // is regular file
		left = noMatch + "-f"
		right = condition.Match // TestString
		operand = ""            // Nginx: if (-f $variable)
	case "-d": // is directory
		left = noMatch + "-d"
		right = condition.Match
		operand = ""
	case "-s": // is regular file with size > 0
		// Nginx 没有直接的 -s, 但 -e (exists) 是最接近的通用检查，具体大小检查较复杂
		// JS 将 -s 映射到 -e (exists)
		left = noMatch + "-e"
		right = condition.Match
		operand = ""
	default: // 默认是正则表达式匹配
		left = condition.Match            // TestString (e.g., %{HTTP_HOST})
		right = condRule                  // CondPattern (e.g., ^www\.example\.com$)
		operand = noMatch + matchOperator // e.g., ~, !~, ~*, !~*
	}

	return ConditionMatch{
		Left:    left,
		Right:   right,
		Operand: operand,
		Flags:   fromFlags,
		Raw:     condition.Raw,
	}
}

// _parseRewriteCond 解析给定规则的所有 RewriteCond。
func (rc *RewriteConf) _parseRewriteCond(rule RuleWithConditions, r int) []ConditionMatch {
	var condResult []ConditionMatch
	for i, cond := range rule.Conditions {
		condResult = append(condResult, rc._parseCondMatch(cond, r, i, rule.CondBit))
	}
	return condResult
}

// _mustSkipForCond 检查是否应跳过规则，因为其条件包含未知/不支持的标志。
// 根据JS代码分析，此函数可能总是返回0 (不跳过)，因为 _parseFlags 中的 unknown 总是0。
func (rc *RewriteConf) _mustSkipForCond(conditions []ConditionMatch) interface{} { // JS 返回 0 或 string
	if len(conditions) == 0 {
		return 0
	}
	if len(conditions) == 1 {
		if conditions[0].Flags.Unknown == 1 {
			return "skipped because all flags in condition are unknown"
		}
		return 0
	}

	unknownCount := 0
	for _, cond := range conditions {
		if cond.Flags.Unknown == 1 {
			unknownCount++
		}
	}
	if len(conditions) == unknownCount {
		return "skipped because all flags for all conditions are unknown"
	}
	return 0
}

// _setBackRef 处理 Apache 的 %N 反向引用。
func (rc *RewriteConf) _setBackRef(rule RuleWithConditions, condsParsed []ConditionMatch) (RuleWithConditions, []ConditionMatch) {
	// 返回修改后的 rule (主要是 rule.Rule) 和 condsParsed

	// 这里我们需要修改 rule.Rule 的字段，所以传递整个 RuleWithConditions
	// 并返回修改后的 RuleWithConditions (虽然只有 rule.Rule 部分被改)
	// 和修改后的 condsParsed (其 Flags.Set 可能被添加内容)

	var totalMatches []int // 存储 %N 中的 N
	for i := 0; i < 10; i++ {
		// JS: var regExp = new RegExp('\%' + i);
		// Go: 需要字面量 % 和数字 i
		searchPattern := "%" + strconv.Itoa(i)
		replacePattern := "$bref_" + strconv.Itoa(i) // Nginx 风格的变量

		// 检查并替换 rule.Rule.Regex
		if strings.Contains(rule.Rule.Regex, searchPattern) {
			rule.Rule.Regex = strings.ReplaceAll(rule.Rule.Regex, searchPattern, replacePattern)
			totalMatches = append(totalMatches, i)
		}
		// 检查并替换 rule.Rule.Rew
		if strings.Contains(rule.Rule.Rew, searchPattern) {
			rule.Rule.Rew = strings.ReplaceAll(rule.Rule.Rew, searchPattern, replacePattern)
			totalMatches = append(totalMatches, i)
		}
		// 检查并替换 rule.Rule.Flags (虽然不常见，但JS代码检查了)
		for j, flagVal := range rule.Rule.Flags {
			if strings.Contains(flagVal, searchPattern) {
				rule.Rule.Flags[j] = strings.ReplaceAll(flagVal, searchPattern, replacePattern)
				totalMatches = append(totalMatches, i)
			}
		}
	}

	// 去重 totalMatches (N 的值)
	seen := make(map[int]struct{})
	uniqueMatches := []int{}
	for _, m := range totalMatches {
		if _, exists := seen[m]; !exists {
			seen[m] = struct{}{}
			uniqueMatches = append(uniqueMatches, m)
		}
	}
	sort.Ints(uniqueMatches) // 排序以保证一致性 (JS的 for m < totalMatches 依赖于 push 顺序)

	// 为捕获到的反向引用添加 'set' 指令到条件中
	for _, matchNum := range uniqueMatches { // matchNum 是 N (%N 中的 N)
		// JS: '$bref_' + match + ' $' + match
		// Nginx: set $bref_N $N; (这里的 $N 是条件正则表达式的捕获组)
		setInstruction := fmt.Sprintf("$bref_%d $%d", matchNum, matchNum)

		if len(condsParsed) > 0 {
			if rule.CondBit == "OR" {
				// 如果是 OR，添加到所有条件
				for k := range condsParsed {
					condsParsed[k].Flags.Set = append(condsParsed[k].Flags.Set, setInstruction)
				}
			} else {
				// 如果是 AND，添加到最后一个条件
				lastCondIdx := len(condsParsed) - 1
				condsParsed[lastCondIdx].Flags.Set = append(condsParsed[lastCondIdx].Flags.Set, setInstruction)
			}
		}
	}
	return rule, condsParsed
}

// _parseRule 进一步处理 RewriteRule。
// c 是条件数量
func (rc *RewriteConf) _parseRule(inputRule RuleWithConditions, numConditions int) RewriteRuleProcessed {
	// inputRule.Rule 是 RewriteRuleRaw
	// 返回 RewriteRuleProcessed

	processedRule := RewriteRuleProcessed{
		Regex: inputRule.Rule.Regex,
		Rew:   inputRule.Rule.Rew,
		// Flags 将在 _parseContent 中单独解析并赋值
		Raw: inputRule.Rule.Regex, // TODO: 更好的原始行存储
	}

	// 规范化 Regex 路径
	if strings.HasPrefix(processedRule.Regex, "^") {
		if len(processedRule.Regex) > 1 && processedRule.Regex[1] != '/' {
			processedRule.Regex = "^/" + processedRule.Regex[1:]
		}
	} else {
		if !strings.HasPrefix(processedRule.Regex, "/") {
			processedRule.Regex = "/" + processedRule.Regex
		}
	}

	// 规范化 Rew 路径 (除非是 http/https 开头)
	if !strings.HasPrefix(strings.ToLower(processedRule.Rew), "http://") &&
		!strings.HasPrefix(strings.ToLower(processedRule.Rew), "https://") {
		if strings.HasPrefix(processedRule.Rew, "^") { // JS: rule["rule"]["rew"].charAt(0) == '^'
			if len(processedRule.Rew) > 1 && processedRule.Rew[1] != '/' {
				processedRule.Rew = "^/" + processedRule.Rew[1:]
			}
		} else {
			if !strings.HasPrefix(processedRule.Rew, "/") {
				// JS: rule["rule"]["rew"].charAt(0) != '/'
				processedRule.Rew = "/" + processedRule.Rew
			}
		}
	}

	// 处理 `RewriteRule Pattern - [FLAGS]` (没有替换)
	// JS: if (rule["rule"]["rew"] == '/-')
	if processedRule.Rew == "/-" || processedRule.Rew == "-" { // Apache 允许 `RewriteRule Pattern -`
		processedRule.Rew = "" // 表示无替换
		// JS also deletes regex, but Nginx might still need it if flags like [L] are applied after conditions
		// For now, let's keep regex if only rew is "-". If it causes issues, we can clear it.
		// However, the JS example deletes both. Let's follow.
		// If rew is empty, it implies conditions are primary.
		// The Nginx "rewrite" directive requires a replacement.
		// If 'rew' becomes empty, _writeConfig will likely skip the 'rewrite' or handle it.
		// The JS logic 'delete rule["rule"]["rew"]' makes it undefined.
		// Here, setting to empty string and _writeConfig checks for it.
		// If JS deletes regex, then that rule effectively becomes a no-op for matching,
		// only conditions and flags like [L] or [R] would matter.
		// For Nginx, an empty regex is not valid for `rewrite`.
		// Let's stick to the JS: if rew is /-, the rule implies "apply flags if conditions met".
		// _writeConfig must handle this (e.g. by not emitting a `rewrite` if regex/rew are empty).
		// The JS sets them to undefined, which causes the rewrite line to be skipped in _writeConfig.
		// Setting them to empty strings here achieves a similar effect for Go checks.
		if processedRule.Rew == "/-" { // Specifically matching JS `/-` which normalizes to `/-`
			processedRule.Regex = "" // Mark as not for rewrite directive
			processedRule.Rew = ""
		}
	}

	// 设置 trueExp 用于 Nginx 的 $rule_X 条件链
	if numConditions > 0 {
		if inputRule.CondBit == "OR" {
			processedRule.TrueExp = "1" // Any OR condition sets $rule_X to 1
		} else { // AND
			// JS: backme = (i + 1) + backme;
			// Example: 3 conditions -> "321"
			backme := ""
			for i := 0; i < numConditions; i++ {
				backme = strconv.Itoa(i+1) + backme
			}
			processedRule.TrueExp = backme
		}
	}
	return processedRule
}

var (
	httpVarRegex = regexp.MustCompile(`%\{HTTP:([^}]+)}`)
	varRegex     = regexp.MustCompile(`%\{[^}]+}`) // General pattern for any %{VAR}
)

// _replaceVariables 替换 Apache 变量为 Nginx 变量。
// key 参数在 JS 中未使用，这里也省略。
func (rc *RewriteConf) _replaceVariables(val string) string {
	originalVal := val

	// 处理 %{HTTP:Header-Name}
	val = httpVarRegex.ReplaceAllStringFunc(val, func(match string) string {
		param := httpVarRegex.FindStringSubmatch(match)[1]
		return "$http_" + strings.ToLower(strings.ReplaceAll(param, "-", "_"))
	})

	// Apache 变量到 Nginx 变量的映射表
	apacheToNginxVars := map[string]string{
		"%{HTTP_USER_AGENT}":       "$http_user_agent",
		"%{HTTP_REFERER}":          "$http_referer",
		"%{HTTP_COOKIE}":           "$http_cookie",
		"%{HTTP_FORWARDED}":        "$http_forwarded", // More complex, often $proxy_add_x_forwarded_for or specific header
		"%{HTTP_HOST}":             "$http_host",      // Or $host
		"%{HTTP_PROXY_CONNECTION}": "$http_proxy_connection",
		"%{HTTP_ACCEPT}":           "$http_accept",
		"%{REMOTE_ADDR}":           "$remote_addr",
		"%{REMOTE_PORT}":           "$remote_port",
		"%{REMOTE_USER}":           "$remote_user",
		"%{REQUEST_METHOD}":        "$request_method",
		"%{SCRIPT_FILENAME}":       "$document_root$uri", // Or $request_filename if SCRIPT_FILENAME = DOCUMENT_ROOT + REQUEST_URI
		"%{PATH_INFO}":             "$fastcgi_path_info", // Or often part of $uri, depends on setup
		"%{QUERY_STRING}":          "$args",
		"%{DOCUMENT_ROOT}":         "$document_root",
		"%{SERVER_NAME}":           "$server_name", // Or $host
		"%{SERVER_ADDR}":           "$server_addr",
		"%{SERVER_PORT}":           "$server_port",
		"%{SERVER_PROTOCOL}":       "$server_protocol",
		"%{REQUEST_URI}":           "$request_uri", // Includes query string in Nginx for $request_uri
		"%{REQUEST_FILENAME}":      "$request_filename",
		// Less common or more complex ones
		"%{THE_REQUEST}":     "$request",     // Line of request
		"%{REMOTE_HOST}":     "$remote_addr", // Nginx usually doesn't do reverse DNS lookup for $remote_host unless configured
		"%{SERVER_SOFTWARE}": "",             // Nginx doesn't expose this easily as a variable
		"%{TIME_YEAR}":       "$time_local",  // Needs formatting
		// ... add more as needed
	}
	// JS 使用一个 pat 和 rep 数组。这里用 map 更 Go 一些，但顺序不固定。
	// 为保持 JS 的替换顺序（如果重要的话），可以使用 slice of structs。
	// 但对于这些独立的变量，顺序通常不关键。
	for apacheVar, nginxVar := range apacheToNginxVars {
		if strings.Contains(val, apacheVar) { // 避免不必要的 ReplaceAll 调用
			val = strings.ReplaceAll(val, apacheVar, nginxVar)
		}
	}

	// JS: %{SCRIPT_FILENAME} -> $uri, %{PATH_INFO} -> $uri, %{REQUEST_URI} -> $uri
	// My map is slightly different based on common Nginx practice.
	// Let's refine specific JS choices if needed, e.g. SCRIPT_FILENAME -> $uri
	// JS pat/rep:
	// '%{SCRIPT_FILENAME}' -> '$uri' (This is often $document_root$fastcgi_script_name or $request_filename)
	// '%{PATH_INFO}' -> '$uri' (Path info is complex, can be part of $uri or separate)
	// '%{REQUEST_URI}' -> '$uri' (Nginx $request_uri includes query, Apache %{REQUEST_URI} is path only)
	// To be closer to JS's specific choices for these three:
	val = strings.ReplaceAll(val, "%{SCRIPT_FILENAME}", "$uri") // Overriding map if JS specific is desired
	val = strings.ReplaceAll(val, "%{PATH_INFO}", "$uri")       // Overriding map
	// Note: Apache's %{REQUEST_URI} is path part, Nginx's $uri is normalized path part (no query)
	// Nginx $request_uri is path + query. JS maps %{REQUEST_URI} to $uri. This seems correct.
	// The map already has %{REQUEST_URI} -> $request_uri. JS uses $uri. Let's follow JS if that was intended.
	// The JS `rep` array maps REQUEST_URI to $uri, not $request_uri.
	val = strings.ReplaceAll(val, "%{REQUEST_URI}", "$uri")

	// 如果替换后字符串未变，并且仍包含 %{...} 形式的变量，则标记为IGNORE
	if originalVal == val && varRegex.MatchString(val) {
		return "IGNORE"
	}

	return val
}

// _walkRecursiveAndReplace applies _replaceVariables to all string fields in FinalConfigItem.
// This is a targeted version of the JS _walkRecursive.
func (rc *RewriteConf) _walkRecursiveAndReplace(item *FinalConfigItem) {
	// Replace in Conditions
	for i := range item.Conds {
		cond := &item.Conds[i] // Get pointer to modify original
		if newLeft := rc._replaceVariables(cond.Left); newLeft != "IGNORE" {
			cond.Left = newLeft
		} else {
			cond.Left = "" // Or mark for comment out
		}
		if newRight := rc._replaceVariables(cond.Right); newRight != "IGNORE" {
			cond.Right = newRight
		} else {
			// If right side is pattern for regex, IGNORE means it's unusable
			cond.Right = "__IGNORED_PATTERN__" // Or handle in _writeConfig
		}
		// Operand and Flags.Env/Set might also contain variables, though less common for operand
		for j, envVar := range cond.Flags.Env {
			if newEnv := rc._replaceVariables(envVar); newEnv != "IGNORE" {
				cond.Flags.Env[j] = newEnv
			} else {
				cond.Flags.Env[j] = "__IGNORED_ENV__"
			}
		}
		for j, setVar := range cond.Flags.Set { // Set "key value"
			parts := strings.Fields(setVar)
			if len(parts) >= 2 {
				key := parts[0]
				value := strings.Join(parts[1:], " ")
				if newValue := rc._replaceVariables(value); newValue != "IGNORE" {
					cond.Flags.Set[j] = key + " " + newValue
				} else {
					cond.Flags.Set[j] = key + " __IGNORED_VALUE__"
				}
			}
		}
	}

	// Replace in Rule
	rule := &item.Rule
	if newRegex := rc._replaceVariables(rule.Regex); newRegex != "IGNORE" {
		rule.Regex = newRegex
	} else {
		rule.Regex = "" // Mark as unusable for rewrite
	}
	if newRew := rc._replaceVariables(rule.Rew); newRew != "IGNORE" {
		rule.Rew = newRew
	} else {
		rule.Rew = "" // Mark as unusable for rewrite
	}

	for j, envVar := range rule.Flags.Env {
		if newEnv := rc._replaceVariables(envVar); newEnv != "IGNORE" {
			rule.Flags.Env[j] = newEnv
		} else {
			rule.Flags.Env[j] = "__IGNORED_ENV__"
		}
	}
	for j, setVar := range rule.Flags.Set {
		parts := strings.Fields(setVar)
		if len(parts) >= 2 {
			key := parts[0]
			value := strings.Join(parts[1:], " ")
			if newValue := rc._replaceVariables(value); newValue != "IGNORE" {
				rule.Flags.Set[j] = key + " " + newValue
			} else {
				rule.Flags.Set[j] = key + " __IGNORED_VALUE__"
			}
		}
	}
}

// _writeConfig 生成 Nginx 配置字符串。
func (rc *RewriteConf) _writeConfig(finalConfigs []FinalConfigItem) string {
	var result strings.Builder
	ruleCounter := 0 // Used for $rule_X variable in Nginx if ($rule_X = ...)

	for i := range finalConfigs {
		conf := &finalConfigs[i] // Get a pointer to modify with _walkRecursiveAndReplace

		// JS: conf = this._walkRecursive(conf, this._replaceVariables);
		// Apply variable replacement to all relevant string fields
		rc._walkRecursiveAndReplace(conf)

		isReturnedOrBrokenInCond := false // If a return/break happens inside an OR'd condition's if block

		// --- 条件处理 ---
		if len(conf.Conds) > 0 {
			for j, cond := range conf.Conds {
				// JS: if (cond["flags"]["unknown"] != 1 && cond["left"] && cond["right"])
				// Our unknown is always 0. Check for essential parts.
				// Check if left/right became empty or marked IGNORED by _replaceVariables
				if cond.Flags.Unknown == 1 || cond.Left == "" || (cond.Operand != "" && cond.Right == "__IGNORED_PATTERN__") {
					result.WriteString(fmt.Sprintf("#ignored: condition %d of rule %d (%s)\n", j, conf.OriginalIndex, cond.Raw))
					// JS: conf["rule"]["trueExp"] = conf["rule"]["trueExp"].replace(new RegExp(j, 'g'), '');
					// This means if a condition in an AND chain is skipped, the trueExp needs adjustment.
					// For simplicity here, if a condition is bad, the whole rule might be iffy.
					// Current JS does not correctly remove the number from trueExp "123" if cond 2 is bad.
					// It would try to replace "1" (j=1 for second cond) from "123" giving "23".
					// The logic in JS for this (`replace(new RegExp(j, 'g'), '')`) is incorrect for `j` as index.
					// It should be `replace(new RegExp(String(j+1), 'g'), '')`.
					// Given this, and that `unknown` is always 0, this path is less likely.
					continue
				}

				if cond.Operand == "" { // File/dir checks like -f, -d
					result.WriteString(fmt.Sprintf("    if (%s %s) {\n", cond.Left, cond.Right))
				} else { // Regex checks
					// Quote the right operand (pattern) if it's not a variable itself
					// Nginx regex patterns are typically not quoted unless they contain spaces or special chars
					// that would break the if statement. Variables like $uri don't need quotes.
					// Apache patterns are also typically unquoted. For safety, quoting if it's not a var.
					// JS always quotes: 'if (' + cond["left"] + ' ' + cond["operand"] + ' "' + cond["right"] + '"){'
					// Let's follow JS for consistency, though Nginx often doesn't need quotes for regex.
					result.WriteString(fmt.Sprintf("    if (%s %s \"%s\") {\n", cond.Left, cond.Operand, cond.Right))
				}

				for _, setVal := range cond.Flags.Set {
					if !strings.Contains(setVal, "__IGNORED_VALUE__") {
						result.WriteString(fmt.Sprintf("        set %s;\n", setVal))
					} else {
						result.WriteString(fmt.Sprintf("        #ignored set: %s (due to unknown variable)\n", setVal))
					}
				}
				for _, envVal := range cond.Flags.Env {
					if !strings.Contains(envVal, "__IGNORED_ENV__") {
						result.WriteString(fmt.Sprintf("        setenv %s;\n", envVal)) // NB: setenv is not standard Nginx
					} else {
						result.WriteString(fmt.Sprintf("        #ignored setenv: %s (due to unknown variable)\n", envVal))
					}
				}

				// 如果是 OR 条件链，并且规则本身有 return/break，则在每个条件块内应用
				if conf.CondBit == "OR" {
					if conf.Rule.Flags.Return > 0 {
						result.WriteString(fmt.Sprintf("        return %d;\n", conf.Rule.Flags.Return))
						isReturnedOrBrokenInCond = true
					}
					// Nginx 'break' is context-dependent. Apache 'L' often means 'last' or 'break processing this ruleset'.
					// If conf.Rule.Flags.Break == 1 (from F, G flags) or conf.Rule.Flags.AppendEnd == "last" (from L flag)
					// and it's an OR chain, these should apply if the condition is met.
					// JS code implies `break;` for `F` or `G` flags, even in OR.
					if conf.Rule.Flags.Break == 1 && conf.Rule.Flags.Return > 0 { // F or G implies return + break
						// The 'break' in JS seems to be a general stop. Nginx 'break' stops rewrite phase for current location.
						// If 'return' is already issued, 'break' might be redundant or have specific meaning in context.
						// The JS outputs 'break;' after 'return;' if rule.flags.break is 1.
						result.WriteString("        break;\n")
						isReturnedOrBrokenInCond = true
					} else if conf.Rule.Flags.AppendEnd == "last" && conf.Rule.Flags.Return == 0 {
						// If an OR condition leads to an L flag on the rule, and no R/F/G
						result.WriteString("        # Rule has [L] flag, processing might stop here for this OR branch\n")
						// An actual 'rewrite ... last;' might be needed if there's a rewrite target.
						// This part is tricky. JS just sets isReturned = 1 for any return in OR cond.
						// For now, rely on the main rule processing to emit rewrite if needed.
					}
				}
				result.WriteString("    }\n") // End of if(cond)
			}
		}

		// --- 规则处理 ---
		// JS: if (null == isReturned)
		if !isReturnedOrBrokenInCond {
			// JS: if (conf["rule"]["flags"]["unknown"] != 1)
			// Our .Unknown is always 0
			if conf.Rule.Flags.Unknown == 1 { // This path is effectively not taken
				result.WriteString(fmt.Sprintf("#ignored: unknown variable or flag in rule %d\n", conf.OriginalIndex))
				continue
			}

			ruleBlockOpened := false
			if conf.Rule.TrueExp != "" {
				// Nginx variable $rule_X (where X is conf.OriginalIndex from _parseContent)
				result.WriteString(fmt.Sprintf("    if ($rule_%d = \"%s\") {\n", conf.OriginalIndex, conf.Rule.TrueExp))
				ruleBlockOpened = true
			}

			indent := "    "
			if ruleBlockOpened {
				indent = "        "
			}

			if conf.Rule.Flags.Return > 0 { // F, G, or R flag that implies return code
				for _, setVal := range conf.Rule.Flags.Set { // Set from rule flags (e.g. E=...)
					if !strings.Contains(setVal, "__IGNORED_VALUE__") {
						result.WriteString(fmt.Sprintf("%sset %s;\n", indent, setVal))
					}
				}
				for _, envVal := range conf.Rule.Flags.Env {
					if !strings.Contains(envVal, "__IGNORED_ENV__") {
						result.WriteString(fmt.Sprintf("%ssetenv %s;\n", indent, envVal))
					}
				}
				result.WriteString(fmt.Sprintf("%sreturn %d;\n", indent, conf.Rule.Flags.Return))
				if conf.Rule.Flags.Break == 1 { // F or G flags
					result.WriteString(fmt.Sprintf("%sbreak;\n", indent))
				}
			} else { // No early return from flags, try to write rewrite directive
				// First, process any set/env from rule's own flags (e.g. [E=foo:bar])
				// These should apply if the rule's conditions (if any) are met.
				for _, setVal := range conf.Rule.Flags.Set {
					if !strings.Contains(setVal, "__IGNORED_VALUE__") {
						result.WriteString(fmt.Sprintf("%sset %s;\n", indent, setVal))
					}
				}
				for _, envVal := range conf.Rule.Flags.Env {
					if !strings.Contains(envVal, "__IGNORED_ENV__") {
						result.WriteString(fmt.Sprintf("%ssetenv %s;\n", indent, envVal))
					}
				}

				if conf.Rule.Regex != "" && (conf.Rule.Rew != "" || conf.Rule.Flags.AppendEnd != "") {
					// A rewrite directive needs a regex and a replacement, or just a regex if flags like `last` are applied without changing URI
					// But Nginx `rewrite regex replacement flag;` means replacement is mandatory.
					// If conf.Rule.Rew is "" (e.g. from `RewriteRule pattern - [L]`), this means "apply flag L if pattern matches".
					// Nginx: `rewrite pattern $uri last;` (if $uri is the current uri) or just use if for flags.
					// The JS logic: `if (conf["rule"]["regex"] && conf["rule"]["rew"])`
					// This implies if `rew` is empty (e.g. from `/-`), it won't emit `rewrite`.
					// Let's adjust: if Rew is empty, but there's an appendEnd flag like 'last',
					// it means "stop processing if regex matches".
					// This can be `rewrite regex regex last;` if no change, or `rewrite regex $uri last;`
					// Or if it's just `[L]`, often `if (...) { break; }` or `if (...) { # last flag }`
					// For simplicity with this converter, if 'rew' is empty, don't emit 'rewrite'.
					// The flags like L, R, etc., are in `AppendEnd`.

					currentRew := conf.Rule.Rew
					if currentRew == "" && conf.Rule.Flags.AppendEnd != "" {
						// If replacement is empty but flags like 'last' or 'permanent' exist,
						// Nginx rewrite needs a replacement. Use $uri or $request_uri.
						// $request_uri includes args, $uri does not. Apache RewriteRule usually works on path.
						currentRew = "$uri" // A common way to rewrite to "itself" just to apply a flag.
						// Or, if the rule was `^foo$ - [L]`, it becomes `rewrite ^foo$ $uri last;`
					}

					if conf.Rule.Regex != "" && currentRew != "" { // Regex and Rew must be present
						appendEndStr := ""
						if conf.Rule.Flags.AppendEnd != "" {
							appendEndStr = " " + conf.Rule.Flags.AppendEnd
						}
						result.WriteString(fmt.Sprintf("%srewrite %s %s%s;\n", indent, conf.Rule.Regex, currentRew, appendEndStr))
					} else if conf.Rule.Regex == "" && conf.Rule.Rew == "" && conf.Rule.Flags.AppendEnd != "" {
						// This case could be for rules like `RewriteRule - - [L]` (if that makes sense)
						// Or after `RewriteRule pattern -` has cleared regex and rew.
						// Effectively, just applying flags based on conditions.
						// Nginx doesn't have a "rewrite" without regex/rew.
						// The `if ($rule_X)` handles condition check.
						// Flags like L would be handled by `break` or `last` on a dummy rewrite.
						// This scenario implies the JS's deletion of regex/rew for `/-`
						// and subsequent check `if (conf["rule"]["regex"] && conf["rule"]["rew"])`
						// correctly skips emitting a `rewrite` line.
						result.WriteString(fmt.Sprintf("%s#ignored: rule %d has no regex/rew for rewrite, possibly due to '-' or IGNOREd variable\n", indent, conf.OriginalIndex))
					} else {
						// If regex is present but rew became empty due to IGNORE, or vice-versa.
						result.WriteString(fmt.Sprintf("%s#ignored: rule %d missing regex or replacement for rewrite (value was IGNOREd or rule was '-')\n", indent, conf.OriginalIndex))
					}
				} else {
					// Case where rule.Regex or rule.Rew is empty due to earlier processing (e.g. IGNORE or '-')
					// and no return code set by flags.
					// JS: result += '#ignored: "-" thing used or unknown variable in regex/rew' + "\n";
					result.WriteString(fmt.Sprintf("%s#ignored: rule %d cannot be written (no regex/rew or no action)\n", indent, conf.OriginalIndex))
				}
			}

			if ruleBlockOpened {
				result.WriteString("    }\n") // End of if($rule_X)
			}
		}
		ruleCounter++
		result.WriteString("\n") // Add a blank line between rules
	}
	return result.String()
}

// _parseContent 是主要的解析编排函数。
func (rc *RewriteConf) _parseContent(content string) []FinalConfigItem {
	rawRules := rc._readRules(content) // []RuleWithConditions
	var finalConfigs []FinalConfigItem

	// var mscr interface{} // Corresponds to JS mscr, 0 or string
	// var beforeMscr interface{}

	for i, rule := range rawRules { // rule is RuleWithConditions
		condsParsed := rc._parseRewriteCond(rule, i) // Pass rule index 'i' for $rule_i

		// JS: mscr = this._mustSkipForCond(condsParsed)
		// As analyzed, _mustSkipForCond always returns 0 with current JS logic.
		// So, the 'if mscr != 0' block in JS is never taken.
		// We proceed as if mscr is always 0.

		// JS: var backRef = this._setBackRef(rule, condsParsed);
		// rule = backRef.rule; condsParsed = backRef.condsParsed;
		// _setBackRef modifies rule.Rule (part of RuleWithConditions) and condsParsed.
		// In Go, structs/slices are reference types if passed as pointers or if they contain refs.
		// Here, rule is a copy, condsParsed is a slice (reference type).
		// Let's make _setBackRef return modified values.
		modifiedRuleContainer, modifiedCondsParsed := rc._setBackRef(rule, condsParsed)

		// Parse rule flags AFTER _setBackRef (as _setBackRef might modify raw flags if they contain %N)
		// Though it's unlikely for flags to contain %N.
		// JS: rule["rule"]["flags"] = this._parseFlags(rule["rule"]["flags"], 0, i, 0);
		// The flags are on modifiedRuleContainer.Rule.Flags (which is []string)
		parsedRuleFlags := rc._parseFlags(modifiedRuleContainer.Rule.Flags, 0, i, 0)

		// JS: rule = this._parseRule(rule, condsParsed.length);
		// This rule is the container (RuleWithConditions). _parseRule expects this.
		// It returns the processed rule part (RewriteRuleProcessed in JS terms).
		processedRulePart := rc._parseRule(modifiedRuleContainer, len(modifiedCondsParsed))
		processedRulePart.Flags = parsedRuleFlags // Assign the parsed flags

		curConf := FinalConfigItem{
			Conds:         modifiedCondsParsed,
			Rule:          processedRulePart,
			CondBit:       modifiedRuleContainer.CondBit,
			OriginalIndex: i, // Store original rule index for $rule_i
		}
		finalConfigs = append(finalConfigs, curConf)
	}
	return finalConfigs
}
