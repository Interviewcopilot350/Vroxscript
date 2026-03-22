package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	RED    = "\033[91m"
	GREEN  = "\033[92m"
	YELLOW = "\033[93m"
	BLUE   = "\033[94m"
	CYAN   = "\033[96m"
	BOLD   = "\033[1m"
	RESET  = "\033[0m"
)

var tlsConfig = &tls.Config{InsecureSkipVerify: true}
var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: tlsConfig,
	},
}

func vroxError(msg string, lineNum int) {
	fmt.Println(RED + "\n[VroxScript Error] Line " + strconv.Itoa(lineNum) + ": " + msg + RESET)
	fmt.Println(YELLOW + "-> Fix your .vs file and try again\n" + RESET)
	os.Exit(1)
}

func vroxSuccess(msg string) { fmt.Println(GREEN + msg + RESET) }
func vroxInfo(msg string)    { fmt.Println(CYAN + msg + RESET) }
func vroxWarn(msg string)    { fmt.Println(YELLOW + msg + RESET) }

func resolveValue(key string, variables map[string]interface{}) string {
	key = strings.TrimSpace(key)
	key = strings.Trim(key, "\"")
	if v, ok := variables[key]; ok {
		return fmt.Sprint(v)
	}
	return key
}

func evalCondition(condition string, variables map[string]interface{}) bool {
	condition = strings.TrimSpace(condition)
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if strings.Contains(condition, op) {
			parts := strings.SplitN(condition, op, 2)
			left := resolveValue(strings.TrimSpace(parts[0]), variables)
			right := resolveValue(strings.TrimSpace(parts[1]), variables)
			switch op {
			case "==":
				return left == right
			case "!=":
				return left != right
			case ">":
				l, _ := strconv.ParseFloat(left, 64)
				r, _ := strconv.ParseFloat(right, 64)
				return l > r
			case "<":
				l, _ := strconv.ParseFloat(left, 64)
				r, _ := strconv.ParseFloat(right, 64)
				return l < r
			case ">=":
				l, _ := strconv.ParseFloat(left, 64)
				r, _ := strconv.ParseFloat(right, 64)
				return l >= r
			case "<=":
				l, _ := strconv.ParseFloat(left, 64)
				r, _ := strconv.ParseFloat(right, 64)
				return l <= r
			}
		}
	}
	return false
}

func scanSubdomains(domain string) []string {
	wordlist := []string{
		"www", "mail", "ftp", "api", "dev", "test", "staging", "admin",
		"blog", "shop", "app", "portal", "dashboard", "secure", "cdn",
		"static", "media", "images", "login", "auth", "support", "docs",
		"beta", "old", "new", "v1", "v2", "api2", "mx", "smtp", "pop",
		"imap", "vpn", "remote", "cloud", "s3", "files", "upload", "git",
		"jenkins", "jira", "confluence", "gitlab", "prod", "sandbox", "qa",
		"internal", "intranet", "uat", "mobile", "m", "api3", "beta2",
	}
	found := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, sub := range wordlist {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			full := s + "." + domain
			_, err := net.LookupHost(full)
			if err == nil {
				mu.Lock()
				found = append(found, full)
				fmt.Println(GREEN + "[scan] Found: " + full + RESET)
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()
	return found
}

func checkAlive(hosts []string) []string {
	alive := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			resp, err := httpClient.Get("https://" + h)
			if err == nil {
				defer resp.Body.Close()
				result := h + " -> " + strconv.Itoa(resp.StatusCode)
				mu.Lock()
				alive = append(alive, result)
				fmt.Println(GREEN + "[alive] " + result + RESET)
				mu.Unlock()
			} else {
				fmt.Println(RED + "[alive] " + h + " -> dead" + RESET)
			}
		}(host)
	}
	wg.Wait()
	return alive
}

func scanPorts(host string) []int {
	ports := []int{21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443, 8888, 9200, 6379, 27017}
	open := []int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(p), 1*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				fmt.Println(GREEN + "[ports] " + host + ":" + strconv.Itoa(p) + " -> open" + RESET)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return open
}

func grabHeaders(targetURL string) map[string]string {
	headers := map[string]string{}
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		fmt.Println(RED + "[headers] Failed: " + err.Error() + RESET)
		return headers
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
		fmt.Println(CYAN + "[header] " + k + ": " + strings.Join(v, ", ") + RESET)
	}
	return headers
}

func checkSecHeaders(targetURL string) ([]string, []string) {
	important := map[string]string{
		"Strict-Transport-Security": "HSTS",
		"X-Frame-Options":           "Clickjacking Protection",
		"X-Content-Type-Options":    "MIME Sniffing Protection",
		"Content-Security-Policy":   "CSP",
		"X-XSS-Protection":          "XSS Protection",
		"Referrer-Policy":           "Referrer Policy",
	}
	headers := grabHeaders(targetURL)
	missing := []string{}
	present := []string{}
	for header, name := range important {
		if _, ok := headers[header]; ok {
			present = append(present, name)
			fmt.Println(GREEN + "[security] Present: " + name + RESET)
		} else {
			missing = append(missing, name)
			fmt.Println(RED + "[security] Missing: " + name + RESET)
		}
	}
	return missing, present
}

func dnsLookup(domain string) map[string]string {
	records := map[string]string{}
	ips, err := net.LookupHost(domain)
	if err == nil {
		records["A"] = strings.Join(ips, ", ")
		fmt.Println(GREEN + "[dns] A: " + strings.Join(ips, ", ") + RESET)
	}
	cname, err := net.LookupCNAME(domain)
	if err == nil {
		records["CNAME"] = cname
		fmt.Println(CYAN + "[dns] CNAME: " + cname + RESET)
	}
	mxs, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxs {
			fmt.Println(CYAN + "[dns] MX: " + mx.Host + RESET)
		}
	}
	txts, err := net.LookupTXT(domain)
	if err == nil {
		for _, txt := range txts {
			fmt.Println(CYAN + "[dns] TXT: " + txt + RESET)
		}
	}
	return records
}

func fetchPage(targetURL string) (int, string) {
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		fmt.Println(RED + "[fetch] " + targetURL + " -> failed" + RESET)
		return 0, ""
	}
	defer resp.Body.Close()
	buf := make([]byte, 10000)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	fmt.Println(GREEN + "[fetch] " + targetURL + " -> " + strconv.Itoa(resp.StatusCode) + RESET)
	return resp.StatusCode, body
}

func crawlLinks(targetURL string) []string {
	_, body := fetchPage(targetURL)
	links := []string{}
	re := regexp.MustCompile(`href="(https?://[^"]+)"`)
	matches := re.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		links = append(links, m[1])
		fmt.Println(CYAN + "[crawl] " + m[1] + RESET)
	}
	return links
}

func extractJSUrls(targetURL string) []string {
	_, body := fetchPage(targetURL)
	results := []string{}
	seen := map[string]bool{}
	re1 := regexp.MustCompile(`["'](/[a-zA-Z0-9/_\-.]+)["']`)
	re2 := regexp.MustCompile(`src=["']([^"']+\.js)["']`)
	for _, m := range re1.FindAllStringSubmatch(body, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			results = append(results, m[1])
			fmt.Println(CYAN + "[js] " + m[1] + RESET)
		}
	}
	for _, m := range re2.FindAllStringSubmatch(body, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			results = append(results, m[1])
			fmt.Println(CYAN + "[js] " + m[1] + RESET)
		}
	}
	return results
}

func extractParams(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return []string{}
	}
	results := []string{}
	for k, v := range parsed.Query() {
		result := k + "=" + strings.Join(v, ",")
		results = append(results, result)
		fmt.Println(CYAN + "[params] " + result + RESET)
	}
	return results
}

func waybackLookup(domain string) []string {
	apiURL := "http://web.archive.org/cdx/search/cdx?url=" + domain + "/*&output=json&limit=20&fl=original"
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		fmt.Println(RED + "[wayback] Failed: " + err.Error() + RESET)
		return []string{}
	}
	defer resp.Body.Close()
	var data [][]string
	json.NewDecoder(resp.Body).Decode(&data)
	results := []string{}
	if len(data) > 1 {
		for _, item := range data[1:] {
			results = append(results, item[0])
			fmt.Println(CYAN + "[wayback] " + item[0] + RESET)
		}
	}
	return results
}

func fuzzDirs(targetURL string) []string {
	wordlist := []string{
		"admin", "login", "dashboard", "api", "v1", "v2", "config",
		"backup", "test", "dev", "staging", "upload", "files", "static",
		"assets", "images", "js", "css", "includes", "wp-admin",
		"administrator", "manager", "panel", "secret", "private",
		"internal", "debug", "console", ".git", ".env", "robots.txt",
		"sitemap.xml", "security.txt", ".well-known", "phpinfo.php",
		"server-status", "api/v1", "api/v2", "api/v3", "graphql",
	}
	found := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, path := range wordlist {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			fullURL := strings.TrimRight(targetURL, "/") + "/" + p
			resp, err := httpClient.Get(fullURL)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode != 404 {
					result := fullURL + " -> " + strconv.Itoa(resp.StatusCode)
					mu.Lock()
					found = append(found, result)
					if resp.StatusCode == 200 {
						fmt.Println(GREEN + "[fuzz] " + result + RESET)
					} else {
						fmt.Println(YELLOW + "[fuzz] " + result + RESET)
					}
					mu.Unlock()
				}
			}
		}(path)
	}
	wg.Wait()
	return found
}

func grepSecrets(content string) map[string][]string {
	patterns := map[string]string{
		"API Key":     `(?i)api[_-]?key["'\s:=]+([a-zA-Z0-9_\-]{20,})`,
		"Secret":      `(?i)secret["'\s:=]+([a-zA-Z0-9_\-]{20,})`,
		"Token":       `(?i)token["'\s:=]+([a-zA-Z0-9_\-]{20,})`,
		"Password":    `(?i)password["'\s:=]+([a-zA-Z0-9_\-]{8,})`,
		"AWS Key":     `AKIA[0-9A-Z]{16}`,
		"Private Key": `-----BEGIN (RSA |EC )?PRIVATE KEY-----`,
		"Email":       `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
	}
	found := map[string][]string{}
	for name, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(content, -1)
		if len(matches) > 0 {
			found[name] = matches
			fmt.Println(RED + "[secrets] Found " + name + ": " + strings.Join(matches, ", ") + RESET)
		}
	}
	return found
}

func regexSearch(pattern string, content string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		fmt.Println(RED + "[regex] Invalid pattern: " + err.Error() + RESET)
		return []string{}
	}
	matches := re.FindAllString(content, -1)
	for _, m := range matches {
		fmt.Println(CYAN + "[regex] Found: " + m + RESET)
	}
	return matches
}

func generateReport(target string, variables map[string]interface{}) string {
	now := time.Now().Format("2006-01-02 15:04:05")
	lines := []string{
		"============================================================",
		"VroxScript Security Recon Report",
		"Target: " + target,
		"Generated: " + now,
		"============================================================",
	}
	if v, ok := variables["resolved_ip"]; ok {
		lines = append(lines, "\n[IP Address]")
		lines = append(lines, "  "+fmt.Sprint(v))
	}
	if v, ok := variables["scan_results"]; ok {
		subs := v.([]string)
		lines = append(lines, "\n[Subdomains Found: "+strconv.Itoa(len(subs))+"]")
		for _, s := range subs {
			lines = append(lines, "  "+s)
		}
	}
	if v, ok := variables["alive_results"]; ok {
		alive := v.([]string)
		lines = append(lines, "\n[Alive Hosts: "+strconv.Itoa(len(alive))+"]")
		for _, s := range alive {
			lines = append(lines, "  "+s)
		}
	}
	if v, ok := variables["port_results"]; ok {
		lines = append(lines, "\n[Open Ports]")
		lines = append(lines, "  "+fmt.Sprint(v))
	}
	if v, ok := variables["fuzz_results"]; ok {
		fuzz := v.([]string)
		lines = append(lines, "\n[Fuzz Results: "+strconv.Itoa(len(fuzz))+"]")
		for _, s := range fuzz {
			lines = append(lines, "  "+s)
		}
	}
	if v, ok := variables["wayback_results"]; ok {
		wb := v.([]string)
		lines = append(lines, "\n[Wayback URLs: "+strconv.Itoa(len(wb))+"]")
		for _, s := range wb {
			lines = append(lines, "  "+s)
		}
	}
	if v, ok := variables["missing_headers"]; ok {
		missing := v.([]string)
		lines = append(lines, "\n[Missing Security Headers]")
		for _, s := range missing {
			lines = append(lines, "  MISSING: "+s)
		}
	}
	if v, ok := variables["secrets_found"]; ok {
		lines = append(lines, "\n[Potential Secrets]")
		lines = append(lines, "  "+fmt.Sprint(v))
	}
	lines = append(lines, "\n============================================================")
	lines = append(lines, "Generated by VroxScript 1.0 Go Edition")
	lines = append(lines, "Built by Prince Aswal, age 14")
	lines = append(lines, "============================================================")
	return strings.Join(lines, "\n")
}

func saveToFile(filename string, content string) {
	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		fmt.Println(RED + "[save] Failed: " + err.Error() + RESET)
	} else {
		vroxInfo("[save] Written to " + filename)
	}
}

func importFile(filename string, variables map[string]interface{}, debug bool) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println(RED + "[import] Cannot open: " + filename + RESET)
		return
	}
	vroxInfo("[import] Loading: " + filename)
	runCode(string(data), variables, debug)
}

func runCode(code string, variables map[string]interface{}, debug bool) {
	lines := strings.Split(code, "\n")
	i := 0

	for i < len(lines) {
		line := strings.TrimSpace(lines[i])

		if line == "" || strings.HasPrefix(line, "#") {
			i++
			continue
		}

		if debug {
			fmt.Println(YELLOW + "[debug] Line " + strconv.Itoa(i+1) + ": " + line + RESET)
		}

		saveTo := ""
		if strings.Contains(line, ">>") {
			parts := strings.SplitN(line, ">>", 2)
			line = strings.TrimSpace(parts[0])
			saveTo = strings.TrimSpace(parts[1])
		}

		switch {

		case strings.HasPrefix(line, "if "):
			condition := strings.TrimSuffix(strings.TrimPrefix(line, "if "), " {")
			block := []string{}
			elseBlock := []string{}
			i++
			inElse := false
			for i < len(lines) {
				l := strings.TrimSpace(lines[i])
				if l == "}" && !inElse {
					if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "else") {
						inElse = true
						i += 2
						continue
					}
					break
				} else if l == "}" && inElse {
					break
				} else if inElse {
					elseBlock = append(elseBlock, lines[i])
				} else {
					block = append(block, lines[i])
				}
				i++
			}
			if evalCondition(condition, variables) {
				runCode(strings.Join(block, "\n"), variables, debug)
			} else if len(elseBlock) > 0 {
				runCode(strings.Join(elseBlock, "\n"), variables, debug)
			}

		case strings.HasPrefix(line, "while "):
			condition := strings.TrimSuffix(strings.TrimPrefix(line, "while "), " {")
			block := []string{}
			i++
			for i < len(lines) {
				if strings.TrimSpace(lines[i]) == "}" {
					break
				}
				block = append(block, lines[i])
				i++
			}
			count := 0
			for evalCondition(condition, variables) && count < 1000 {
				runCode(strings.Join(block, "\n"), variables, debug)
				count++
			}

		case strings.HasPrefix(line, "repeat "):
			parts := strings.Fields(line)
			count, _ := strconv.Atoi(resolveValue(parts[1], variables))
			block := []string{}
			i++
			for i < len(lines) {
				if strings.TrimSpace(lines[i]) == "}" {
					break
				}
				block = append(block, lines[i])
				i++
			}
			for j := 0; j < count; j++ {
				runCode(strings.Join(block, "\n"), variables, debug)
			}

		case strings.HasPrefix(line, "for "):
			parts := strings.Fields(strings.TrimSuffix(line, " {"))
			varName := parts[1]
			listName := parts[3]
			block := []string{}
			i++
			for i < len(lines) {
				if strings.TrimSpace(lines[i]) == "}" {
					break
				}
				block = append(block, lines[i])
				i++
			}
			if items, ok := variables[listName].([]string); ok {
				for _, item := range items {
					variables[varName] = item
					runCode(strings.Join(block, "\n"), variables, debug)
				}
			}

		case strings.HasPrefix(line, "func "):
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "func "), " {"))
			block := []string{}
			i++
			for i < len(lines) {
				if strings.TrimSpace(lines[i]) == "}" {
					break
				}
				block = append(block, lines[i])
				i++
			}
			variables["__func_"+name] = strings.Join(block, "\n")

		case strings.HasPrefix(line, "call "):
			parts := strings.Fields(line)
			name := parts[1]
			args := parts[2:]
			if code, ok := variables["__func_"+name].(string); ok {
				localVars := map[string]interface{}{}
				for k, v := range variables {
					localVars[k] = v
				}
				for idx, arg := range args {
					localVars["arg"+strconv.Itoa(idx+1)] = resolveValue(arg, variables)
				}
				runCode(code, localVars, debug)
				for k, v := range localVars {
					if !strings.HasPrefix(k, "arg") {
						variables[k] = v
					}
				}
			} else {
				vroxError("Unknown function: "+name, i+1)
			}

		case strings.HasPrefix(line, "try"):
			tryBlock := []string{}
			catchBlock := []string{}
			i++
			inCatch := false
			for i < len(lines) {
				l := strings.TrimSpace(lines[i])
				if l == "}" && !inCatch {
					if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "catch") {
						inCatch = true
						i += 2
						continue
					}
					break
				} else if l == "}" && inCatch {
					break
				} else if inCatch {
					catchBlock = append(catchBlock, lines[i])
				} else {
					tryBlock = append(tryBlock, lines[i])
				}
				i++
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						if len(catchBlock) > 0 {
							runCode(strings.Join(catchBlock, "\n"), variables, debug)
						}
					}
				}()
				runCode(strings.Join(tryBlock, "\n"), variables, debug)
			}()

		default:
			interpretLine(line, i+1, variables, debug, saveTo)
		}

		i++
	}
}

func interpretLine(line string, lineNum int, variables map[string]interface{}, debug bool, saveTo string) {
	switch {

	case strings.HasPrefix(line, "let "):
		parts := strings.SplitN(line[4:], "=", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
				variables[name] = strings.Trim(val, "\"")
			} else if strings.Contains(val, "+") || strings.Contains(val, "-") ||
				strings.Contains(val, "*") || strings.Contains(val, "/") {
				result := evalMath(val, variables)
				variables[name] = result
			} else {
				if v, ok := variables[val]; ok {
					variables[name] = v
				} else {
					variables[name] = val
				}
			}
			if debug {
				fmt.Println(BLUE + "[debug] Set " + name + " = " + fmt.Sprint(variables[name]) + RESET)
			}
		}

	case strings.HasPrefix(line, "out "):
		expr := strings.TrimSpace(line[4:])
		fmt.Println(resolveExpression(expr, variables))

	case strings.HasPrefix(line, "print "):
		expr := strings.TrimSpace(line[6:])
		fmt.Println(GREEN + resolveExpression(expr, variables) + RESET)

	case strings.HasPrefix(line, "warn "):
		expr := strings.TrimSpace(line[5:])
		fmt.Println(YELLOW + resolveExpression(expr, variables) + RESET)

	case strings.HasPrefix(line, "error "):
		expr := strings.TrimSpace(line[6:])
		fmt.Println(RED + resolveExpression(expr, variables) + RESET)

	case strings.HasPrefix(line, "input "):
		varName := strings.TrimSpace(line[6:])
		fmt.Print(CYAN + varName + ": " + RESET)
		reader := bufio.NewReader(os.Stdin)
		val, _ := reader.ReadString('\n')
		variables[varName] = strings.TrimSpace(val)

	case strings.HasPrefix(line, "import "):
		filename := strings.TrimSpace(line[7:])
		importFile(filename, variables, debug)

	case strings.HasPrefix(line, "resolve "):
		domain := resolveValue(line[8:], variables)
		ips, err := net.LookupHost(domain)
		if err == nil {
			variables["resolved_ip"] = ips[0]
			vroxSuccess("[resolve] " + domain + " -> " + ips[0])
			if saveTo != "" {
				saveToFile(saveTo, ips[0])
			}
		} else {
			variables["resolved_ip"] = ""
			fmt.Println(RED + "[resolve] " + domain + " -> failed" + RESET)
		}

	case strings.HasPrefix(line, "scan subdomains "):
		domain := resolveValue(line[16:], variables)
		vroxInfo("[scan] Scanning " + domain + "...")
		results := scanSubdomains(domain)
		variables["scan_results"] = results
		vroxSuccess("[scan] Found " + strconv.Itoa(len(results)) + " subdomains")
		if saveTo != "" {
			saveToFile(saveTo, strings.Join(results, "\n"))
		}

	case strings.HasPrefix(line, "alive "):
		varName := strings.TrimSpace(line[6:])
		if hosts, ok := variables[varName].([]string); ok {
			results := checkAlive(hosts)
			variables["alive_results"] = results
			if saveTo != "" {
				saveToFile(saveTo, strings.Join(results, "\n"))
			}
		}

	case strings.HasPrefix(line, "ports "):
		host := resolveValue(line[6:], variables)
		vroxInfo("[ports] Scanning " + host + "...")
		results := scanPorts(host)
		variables["port_results"] = results
		portsStr := []string{}
		for _, p := range results {
			portsStr = append(portsStr, strconv.Itoa(p))
		}
		vroxSuccess("[ports] Open: " + strings.Join(portsStr, ", "))
		if saveTo != "" {
			saveToFile(saveTo, strings.Join(portsStr, "\n"))
		}

	case strings.HasPrefix(line, "headers "):
		targetURL := resolveValue(line[8:], variables)
		vroxInfo("[headers] Grabbing from " + targetURL + "...")
		results := grabHeaders(targetURL)
		variables["header_results"] = results
		if saveTo != "" {
			content := ""
			for k, v := range results {
				content += k + ": " + v + "\n"
			}
			saveToFile(saveTo, content)
		}

	case strings.HasPrefix(line, "secheaders "):
		targetURL := resolveValue(line[11:], variables)
		vroxInfo("[security] Checking security headers...")
		missing, present := checkSecHeaders(targetURL)
		variables["missing_headers"] = missing
		variables["present_headers"] = present
		if saveTo != "" {
			saveToFile(saveTo, "Missing: "+strings.Join(missing, ", ")+"\nPresent: "+strings.Join(present, ", "))
		}

	case strings.HasPrefix(line, "dns "):
		domain := resolveValue(line[4:], variables)
		vroxInfo("[dns] Looking up " + domain + "...")
		results := dnsLookup(domain)
		variables["dns_results"] = results
		if saveTo != "" {
			content := ""
			for k, v := range results {
				content += k + ": " + v + "\n"
			}
			saveToFile(saveTo, content)
		}

	case strings.HasPrefix(line, "fetch get "):
		targetURL := resolveValue(line[10:], variables)
		status, body := fetchPage(targetURL)
		variables["fetch_status"] = status
		variables["fetch_body"] = body
		if saveTo != "" {
			saveToFile(saveTo, strconv.Itoa(status))
		}

	case strings.HasPrefix(line, "fetch post "):
		parts := strings.SplitN(line[11:], " ", 2)
		targetURL := resolveValue(parts[0], variables)
		data := url.Values{}
		if len(parts) > 1 {
			for _, p := range strings.Split(parts[1], "&") {
				kv := strings.SplitN(p, "=", 2)
				if len(kv) == 2 {
					data.Set(resolveValue(kv[0], variables), resolveValue(kv[1], variables))
				}
			}
		}
		resp, err := httpClient.PostForm(targetURL, data)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 5000)
			n, _ := resp.Body.Read(buf)
			variables["fetch_status"] = resp.StatusCode
			variables["fetch_body"] = string(buf[:n])
			vroxSuccess("[post] " + targetURL + " -> " + strconv.Itoa(resp.StatusCode))
		} else {
			fmt.Println(RED + "[post] Failed: " + err.Error() + RESET)
		}

	case strings.HasPrefix(line, "crawl "):
		targetURL := resolveValue(line[6:], variables)
		vroxInfo("[crawl] Crawling " + targetURL + "...")
		results := crawlLinks(targetURL)
		variables["crawl_results"] = results
		vroxSuccess("[crawl] Found " + strconv.Itoa(len(results)) + " links")
		if saveTo != "" {
			saveToFile(saveTo, strings.Join(results, "\n"))
		}

	case strings.HasPrefix(line, "js "):
		targetURL := resolveValue(line[3:], variables)
		vroxInfo("[js] Extracting from " + targetURL + "...")
		results := extractJSUrls(targetURL)
		variables["js_results"] = results
		vroxSuccess("[js] Found " + strconv.Itoa(len(results)) + " endpoints")
		if saveTo != "" {
			saveToFile(saveTo, strings.Join(results, "\n"))
		}

	case strings.HasPrefix(line, "params "):
		targetURL := resolveValue(line[7:], variables)
		results := extractParams(targetURL)
		variables["param_results"] = results
		if saveTo != "" {
			saveToFile(saveTo, strings.Join(results, "\n"))
		}

	case strings.HasPrefix(line, "wayback "):
		domain := resolveValue(line[8:], variables)
		vroxInfo("[wayback] Looking up " + domain + "...")
		results := waybackLookup(domain)
		variables["wayback_results"] = results
		vroxSuccess("[wayback] Found " + strconv.Itoa(len(results)) + " URLs")
		if saveTo != "" {
			saveToFile(saveTo, strings.Join(results, "\n"))
		}

	case strings.HasPrefix(line, "fuzz "):
		targetURL := resolveValue(line[5:], variables)
		vroxInfo("[fuzz] Fuzzing " + targetURL + "...")
		results := fuzzDirs(targetURL)
		variables["fuzz_results"] = results
		vroxSuccess("[fuzz] Found " + strconv.Itoa(len(results)) + " paths")
		if saveTo != "" {
			saveToFile(saveTo, strings.Join(results, "\n"))
		}

	case strings.HasPrefix(line, "secrets "):
		varName := strings.TrimSpace(line[8:])
		content := fmt.Sprint(variables[varName])
		vroxInfo("[secrets] Scanning for sensitive data...")
		results := grepSecrets(content)
		variables["secrets_found"] = results
		if saveTo != "" {
			saveToFile(saveTo, fmt.Sprint(results))
		}

	case strings.HasPrefix(line, "regex "):
		parts := strings.SplitN(line[6:], " ", 2)
		if len(parts) == 2 {
			pattern := strings.Trim(parts[0], "\"")
			content := fmt.Sprint(variables[strings.TrimSpace(parts[1])])
			results := regexSearch(pattern, content)
			variables["regex_result"] = results
			if saveTo != "" {
				saveToFile(saveTo, strings.Join(results, "\n"))
			}
		}

	case strings.HasPrefix(line, "grep "):
		parts := strings.SplitN(line[5:], " ", 2)
		if len(parts) == 2 {
			varName := parts[0]
			keyword := strings.Trim(parts[1], "\"")
			keyword = resolveValue(keyword, variables)
			content := fmt.Sprint(variables[varName])
			if strings.Contains(strings.ToLower(content), strings.ToLower(keyword)) {
				vroxSuccess("[grep] Found: " + keyword)
				variables["grep_result"] = true
			} else {
				fmt.Println(RED + "[grep] Not found: " + keyword + RESET)
				variables["grep_result"] = false
			}
		}

	case strings.HasPrefix(line, "report "):
		target := resolveValue(line[7:], variables)
		vroxInfo("[report] Generating for " + target + "...")
		content := generateReport(target, variables)
		fmt.Println(content)
		if saveTo != "" {
			saveToFile(saveTo, content)
			vroxSuccess("[report] Saved to " + saveTo)
		}

	case strings.HasPrefix(line, "save "):
		parts := strings.SplitN(line[5:], " ", 2)
		if len(parts) == 2 {
			filename := parts[0]
			content := resolveExpression(parts[1], variables)
			saveToFile(filename, content)
		}

	case strings.HasPrefix(line, "show "):
		filename := resolveValue(line[5:], variables)
		data, err := os.ReadFile(filename)
		if err == nil {
			fmt.Println(string(data))
		} else {
			fmt.Println(RED + "[show] Cannot open: " + filename + RESET)
		}

	case strings.HasPrefix(line, "read "):
		filename := resolveValue(line[5:], variables)
		data, err := os.ReadFile(filename)
		if err == nil {
			variables["read_result"] = string(data)
			fmt.Println(string(data))
		} else {
			vroxError("Cannot read: "+filename, lineNum)
		}

	case strings.HasPrefix(line, "append "):
		parts := strings.SplitN(line[7:], " ", 2)
		if len(parts) == 2 {
			filename := parts[0]
			content := resolveExpression(parts[1], variables)
			f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				f.WriteString(content + "\n")
				f.Close()
				vroxInfo("[append] Written to " + filename)
			}
		}

	case strings.HasPrefix(line, "delete "):
		filename := resolveValue(line[7:], variables)
		err := os.Remove(filename)
		if err == nil {
			vroxSuccess("[delete] Removed: " + filename)
		} else {
			vroxError("Cannot delete: "+filename, lineNum)
		}

	case strings.HasPrefix(line, "exists "):
		filename := resolveValue(line[7:], variables)
		if _, err := os.Stat(filename); err == nil {
			vroxSuccess("[exists] " + filename + " -> yes")
			variables["exists_result"] = true
		} else {
			fmt.Println(RED + "[exists] " + filename + " -> no" + RESET)
			variables["exists_result"] = false
		}

	case strings.HasPrefix(line, "upper "):
		val := resolveExpression(line[6:], variables)
		variables["upper_result"] = strings.ToUpper(val)
		fmt.Println(strings.ToUpper(val))

	case strings.HasPrefix(line, "lower "):
		val := resolveExpression(line[6:], variables)
		variables["lower_result"] = strings.ToLower(val)
		fmt.Println(strings.ToLower(val))

	case strings.HasPrefix(line, "strlen "):
		val := resolveExpression(line[7:], variables)
		variables["strlen_result"] = len(val)
		fmt.Println(len(val))

	case strings.HasPrefix(line, "split "):
		parts := strings.SplitN(line[6:], " by ", 2)
		if len(parts) == 2 {
			val := resolveExpression(parts[0], variables)
			delimiter := strings.Trim(parts[1], "\"")
			result := strings.Split(val, delimiter)
			variables["split_result"] = result
			fmt.Println(result)
		}

	case strings.HasPrefix(line, "replace "):
		parts := strings.Fields(line[8:])
		if len(parts) == 3 {
			val := resolveExpression(parts[0], variables)
			old := strings.Trim(parts[1], "\"")
			new := strings.Trim(parts[2], "\"")
			result := strings.ReplaceAll(val, old, new)
			variables["replace_result"] = result
			fmt.Println(result)
		}

	case strings.HasPrefix(line, "count "):
		varName := strings.TrimSpace(line[6:])
		switch v := variables[varName].(type) {
		case []string:
			variables["count_result"] = len(v)
			fmt.Println(len(v))
		case string:
			variables["count_result"] = len(v)
			fmt.Println(len(v))
		default:
			variables["count_result"] = 0
			fmt.Println(0)
		}

	case strings.HasPrefix(line, "math "):
		expr := line[5:]
		result := evalMath(expr, variables)
		variables["math_result"] = result
		fmt.Println(result)

	case strings.HasPrefix(line, "randint "):
		parts := strings.Fields(line[8:])
		if len(parts) == 2 {
			min, _ := strconv.Atoi(resolveValue(parts[0], variables))
			max, _ := strconv.Atoi(resolveValue(parts[1], variables))
			result := rand.Intn(max-min+1) + min
			variables["randint_result"] = result
			fmt.Println(result)
		}

	case line == "random":
		result := rand.Float64()
		variables["random_result"] = result
		fmt.Println(result)

	case strings.HasPrefix(line, "timestamp"):
		now := time.Now().Format("2006-01-02 15:04:05")
		variables["timestamp_result"] = now
		fmt.Println(now)

	case strings.HasPrefix(line, "type "):
		varName := strings.TrimSpace(line[5:])
		if v, ok := variables[varName]; ok {
			t := fmt.Sprintf("%T", v)
			variables["type_result"] = t
			fmt.Println(t)
		}

	case strings.HasPrefix(line, "push "):
		parts := strings.SplitN(line[5:], " ", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := resolveExpression(parts[1], variables)
			if items, ok := variables[name].([]string); ok {
				variables[name] = append(items, val)
			} else {
				variables[name] = []string{val}
			}
		}

	case strings.HasPrefix(line, "pop "):
		name := strings.TrimSpace(line[4:])
		if items, ok := variables[name].([]string); ok && len(items) > 0 {
			variables[name] = items[:len(items)-1]
		}

	case strings.HasPrefix(line, "list "):
		parts := strings.SplitN(line[5:], "=", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, "[]")
			items := strings.Split(val, ",")
			result := []string{}
			for _, item := range items {
				result = append(result, strings.TrimSpace(strings.Trim(item, "\"")))
			}
			variables[name] = result
		}
	}
}

func resolveExpression(expr string, variables map[string]interface{}) string {
	expr = strings.TrimSpace(expr)
	if strings.Contains(expr, "+") {
		parts := strings.SplitN(expr, "+", 2)
		left := resolveExpression(strings.TrimSpace(parts[0]), variables)
		right := resolveExpression(strings.TrimSpace(parts[1]), variables)
		lNum, lErr := strconv.ParseFloat(left, 64)
		rNum, rErr := strconv.ParseFloat(right, 64)
		if lErr == nil && rErr == nil {
			result := lNum + rNum
			if result == float64(int(result)) {
				return strconv.Itoa(int(result))
			}
			return strconv.FormatFloat(result, 'f', 2, 64)
		}
		return left + right
	}
	if v, ok := variables[expr]; ok {
		return fmt.Sprint(v)
	}
	return strings.Trim(expr, "\"")
}

func evalMath(expr string, variables map[string]interface{}) float64 {
	expr = strings.TrimSpace(expr)
	for k, v := range variables {
		expr = strings.ReplaceAll(expr, k, fmt.Sprint(v))
	}
	if strings.Contains(expr, "+") {
		parts := strings.SplitN(expr, "+", 2)
		l, _ := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		r, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		return l + r
	}
	if strings.Contains(expr, "-") {
		parts := strings.SplitN(expr, "-", 2)
		l, _ := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		r, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		return l - r
	}
	if strings.Contains(expr, "*") {
		parts := strings.SplitN(expr, "*", 2)
		l, _ := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		r, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		return l * r
	}
	if strings.Contains(expr, "/") {
		parts := strings.SplitN(expr, "/", 2)
		l, _ := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		r, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if r != 0 {
			return l / r
		}
	}
	result, _ := strconv.ParseFloat(expr, 64)
	return result
}

func interactive() {
	fmt.Println(BOLD + CYAN + "VroxScript 1.0 Go Edition - Interactive Mode" + RESET)
	fmt.Println(YELLOW + "Type 'exit' to quit\n" + RESET)
	variables := map[string]interface{}{}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(GREEN + "vrox> " + RESET)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "exit" {
			fmt.Println(CYAN + "Bye!" + RESET)
			break
		}
		if line != "" {
			interpretLine(line, 1, variables, false, "")
		}
	}
}

func showHelp() {
	fmt.Println(BOLD + CYAN + "\nVroxScript 1.0 Go Edition" + RESET)
	fmt.Println(CYAN + "Security Scripting Language\n" + RESET)
	fmt.Println(YELLOW + "USAGE:" + RESET)
	fmt.Println("  vrox file.vs            Run a VroxScript file")
	fmt.Println("  vrox --debug file.vs    Debug mode")
	fmt.Println("  vrox --version          Version")
	fmt.Println("  vrox --help             Help")
	fmt.Println("  vrox                    Interactive mode")
	fmt.Println(YELLOW + "\nSECURITY COMMANDS:" + RESET)
	fmt.Println(GREEN+"  scan subdomains domain"+RESET, "  Find subdomains")
	fmt.Println(GREEN+"  alive scan_results"+RESET, "      Check live hosts")
	fmt.Println(GREEN+"  ports domain"+RESET, "            Scan ports")
	fmt.Println(GREEN+"  headers https://url"+RESET, "     Grab headers")
	fmt.Println(GREEN+"  secheaders https://url"+RESET, "  Check security headers")
	fmt.Println(GREEN+"  dns domain"+RESET, "              DNS lookup (A,MX,TXT,CNAME)")
	fmt.Println(GREEN+"  crawl https://url"+RESET, "       Find all links")
	fmt.Println(GREEN+"  js https://url"+RESET, "          Extract JS endpoints")
	fmt.Println(GREEN+"  params url"+RESET, "              Extract URL parameters")
	fmt.Println(GREEN+"  wayback domain"+RESET, "          Wayback Machine URLs")
	fmt.Println(GREEN+"  fuzz https://url"+RESET, "        Directory fuzzing")
	fmt.Println(GREEN+"  secrets variable"+RESET, "        Scan for secrets/keys")
	fmt.Println(GREEN+"  regex pattern variable"+RESET, "  Regex search")
	fmt.Println(GREEN+"  grep variable keyword"+RESET, "   Search in results")
	fmt.Println(GREEN+"  fetch get https://url"+RESET, "   HTTP GET")
	fmt.Println(GREEN+"  fetch post url data"+RESET, "     HTTP POST")
	fmt.Println(GREEN+"  resolve domain"+RESET, "          Resolve IP")
	fmt.Println(GREEN+"  report target"+RESET, "           Generate report")
	fmt.Println(YELLOW + "\nLANGUAGE:" + RESET)
	fmt.Println(GREEN+"  let x = 5"+RESET, "              Variable")
	fmt.Println(GREEN+"  out/print/warn/error x"+RESET, "  Output")
	fmt.Println(GREEN+"  math 10 + 5"+RESET, "            Math operations")
	fmt.Println(GREEN+"  randint 1 100"+RESET, "          Random integer")
	fmt.Println(GREEN+"  timestamp"+RESET, "              Current time")
	fmt.Println(GREEN+"  if condition { }"+RESET, "       Condition")
	fmt.Println(GREEN+"  while condition { }"+RESET, "    While loop")
	fmt.Println(GREEN+"  repeat 5 { }"+RESET, "          Repeat")
	fmt.Println(GREEN+"  for item in list { }"+RESET, "   For loop")
	fmt.Println(GREEN+"  func name { }"+RESET, "          Function")
	fmt.Println(GREEN+"  call name arg1 arg2"+RESET, "    Call with args")
	fmt.Println(GREEN+"  try { } catch { }"+RESET, "      Error handling")
	fmt.Println(GREEN+"  import file.vs"+RESET, "         Import file")
	fmt.Println(GREEN+"  command >> file.txt"+RESET, "    Save output")
}

func showVersion() {
	fmt.Println(BOLD + CYAN + "VroxScript 1.0 Go Edition" + RESET)
	fmt.Println("Built by Prince Aswal, age 14")
	fmt.Println("The Security Scripting Language")
	fmt.Println("github.com/princeaswal00/vroxscript")
}

func main() {
	rand.Seed(time.Now().UnixNano())
	if len(os.Args) < 2 {
		interactive()
		return
	}
	switch os.Args[1] {
	case "--help":
		showHelp()
	case "--version":
		showVersion()
	case "--debug":
		if len(os.Args) < 3 {
			fmt.Println(RED + "Error: No file specified" + RESET)
			return
		}
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Println(RED + "Error: Cannot open file" + RESET)
			return
		}
		runCode(string(data), map[string]interface{}{}, true)
	default:
		data, err := os.ReadFile(os.Args[1])
		if err != nil {
			fmt.Println(RED + "Error: Cannot open file: " + os.Args[1] + RESET)
			return
		}
		runCode(string(data), map[string]interface{}{}, false)
	}
}
