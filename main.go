package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"archive/zip"
	"io"
)

// ============================================================
// COLORS
// ============================================================
var COLORS = map[string]string{
	"RED":       "\033[91m",
	"GREEN":     "\033[92m",
	"YELLOW":    "\033[93m",
	"BLUE":      "\033[94m",
	"CYAN":      "\033[96m",
	"PURPLE":    "\033[95m",
	"WHITE":     "\033[97m",
	"BOLD":      "\033[1m",
	"DIM":       "\033[2m",
	"BLINK":     "\033[5m",
	"UNDERLINE": "\033[4m",
	"RESET":     "\033[0m",
	"BG_RED":    "\033[41m",
	"BG_GREEN":  "\033[42m",
	"BG_YELLOW": "\033[43m",
	"BG_BLUE":   "\033[44m",
	"BG_CYAN":   "\033[46m",
	"BG_PURPLE": "\033[45m",
	"ORANGE":    "\033[38;5;208m",
	"PINK":      "\033[38;5;213m",
	"LIME":      "\033[38;5;154m",
	"TEAL":      "\033[38;5;51m",
	"GOLD":      "\033[38;5;220m",
}

const VERSION = "2.2"

var tlsConfig = &tls.Config{InsecureSkipVerify: true}
var httpClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{TLSClientConfig: tlsConfig},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}
var httpClientFollow = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{TLSClientConfig: tlsConfig},
}

var globalCookies = map[string]string{}
var globalHeaders = map[string]string{}
var globalAPIKeys = map[string]string{}
var breakSignal = false
var continueSignal = false

// Loaded modules
var loadedModules = map[string]bool{}

func vroxError(msg string, lineNum int) {
	fmt.Println(COLORS["RED"] + "\n[VroxScript Error] Line " + strconv.Itoa(lineNum) + ": " + msg + COLORS["RESET"])
	fmt.Println(COLORS["YELLOW"] + "-> Fix your .vs file and try again\n" + COLORS["RESET"])
	os.Exit(1)
}
func vroxSuccess(msg string) { fmt.Println(COLORS["GREEN"] + msg + COLORS["RESET"]) }
func vroxInfo(msg string)    { fmt.Println(COLORS["CYAN"] + msg + COLORS["RESET"]) }
func vroxWarn(msg string)    { fmt.Println(COLORS["YELLOW"] + msg + COLORS["RESET"]) }
func vroxPurple(msg string)  { fmt.Println(COLORS["PURPLE"] + msg + COLORS["RESET"]) }
func vroxOrange(msg string)  { fmt.Println(COLORS["ORANGE"] + msg + COLORS["RESET"]) }

// ============================================================
// STRING HELPERS
// ============================================================
func resolveColor(s string, variables map[string]interface{}) string {
	re := regexp.MustCompile(`\{([A-Z_0-9]+)\}`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		name := match[1 : len(match)-1]
		if v, ok := variables["__color_"+name]; ok { return fmt.Sprint(v) }
		if c, ok := COLORS[name]; ok { return c }
		return match
	})
}

func interpolateString(s string, variables map[string]interface{}) string {
	s = resolveColor(s, variables)
	re := regexp.MustCompile(`\{([^}]+)\}`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		varName := match[1 : len(match)-1]
		if v, ok := variables[varName]; ok { return fmt.Sprint(v) }
		return match
	})
}

func resolveValue(key string, variables map[string]interface{}) string {
	key = strings.TrimSpace(strings.Trim(key, "\""))
	if v, ok := variables[key]; ok { return fmt.Sprint(v) }
	return key
}

func resolveExpression(expr string, variables map[string]interface{}) string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\"") {
		return interpolateString(expr[1:len(expr)-1], variables)
	}
	if strings.Contains(expr, " + ") {
		parts := strings.SplitN(expr, " + ", 2)
		left := resolveExpression(strings.TrimSpace(parts[0]), variables)
		right := resolveExpression(strings.TrimSpace(parts[1]), variables)
		l, le := strconv.ParseFloat(left, 64)
		r, re2 := strconv.ParseFloat(right, 64)
		if le == nil && re2 == nil {
			res := l + r
			if res == float64(int(res)) { return strconv.Itoa(int(res)) }
			return strconv.FormatFloat(res, 'f', 2, 64)
		}
		return left + right
	}
	if v, ok := variables[expr]; ok { return fmt.Sprint(v) }
	if c, ok := COLORS[expr]; ok { return c }
	return strings.Trim(expr, "\"")
}

func evalCondition(condition string, variables map[string]interface{}) bool {
	condition = strings.TrimSpace(condition)
	if strings.Contains(condition, " and ") {
		parts := strings.SplitN(condition, " and ", 2)
		return evalCondition(parts[0], variables) && evalCondition(parts[1], variables)
	}
	if strings.Contains(condition, " or ") {
		parts := strings.SplitN(condition, " or ", 2)
		return evalCondition(parts[0], variables) || evalCondition(parts[1], variables)
	}
	if strings.HasPrefix(condition, "not ") {
		return !evalCondition(condition[4:], variables)
	}
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if strings.Contains(condition, op) {
			parts := strings.SplitN(condition, op, 2)
			left := resolveValue(strings.TrimSpace(parts[0]), variables)
			right := resolveValue(strings.TrimSpace(parts[1]), variables)
			switch op {
			case "==": return left == right
			case "!=": return left != right
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
	if v, ok := variables[condition]; ok {
		s := fmt.Sprint(v)
		return s != "" && s != "false" && s != "0" && s != "null"
	}
	return condition == "true"
}

func evalMath(expr string, variables map[string]interface{}) float64 {
	expr = strings.TrimSpace(expr)
	for k, v := range variables { expr = strings.ReplaceAll(expr, k, fmt.Sprint(v)) }
	for _, op := range []string{"+", "-", "*", "/", "%"} {
		if strings.Contains(expr, op) {
			parts := strings.SplitN(expr, op, 2)
			l, _ := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			r, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			switch op {
			case "+": return l + r
			case "-": return l - r
			case "*": return l * r
			case "/": if r != 0 { return l / r }
			case "%": return float64(int(l) % int(r))
			}
		}
	}
	res, _ := strconv.ParseFloat(expr, 64)
	return res
}

// ============================================================
// PASSIVE SUBDOMAIN SOURCES (NEW IN 2.2)
// ============================================================

func queryCrtSh(domain string) []string {
	vroxInfo("[passive] Querying crt.sh...")
	resp, err := httpClientFollow.Get("https://crt.sh/?q=%25." + domain + "&output=json")
	if err != nil { return []string{} }
	defer resp.Body.Close()
	var data []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	results := []string{}
	seen := map[string]bool{}
	for _, entry := range data {
		name := fmt.Sprint(entry["name_value"])
		for _, sub := range strings.Split(name, "\n") {
			sub = strings.TrimSpace(strings.ToLower(sub))
			sub = strings.TrimPrefix(sub, "*.")
			if strings.HasSuffix(sub, "."+domain) && !seen[sub] {
				seen[sub] = true
				results = append(results, sub)
				fmt.Println(COLORS["TEAL"] + "[crt.sh] " + sub + COLORS["RESET"])
			}
		}
	}
	vroxSuccess("[crt.sh] Found " + strconv.Itoa(len(results)) + " subdomains")
	return results
}

func queryHackerTarget(domain string) []string {
	vroxInfo("[passive] Querying HackerTarget...")
	resp, err := httpClientFollow.Get("https://api.hackertarget.com/hostsearch/?q=" + domain)
	if err != nil { return []string{} }
	defer resp.Body.Close()
	buf := make([]byte, 100000)
	n, _ := resp.Body.Read(buf)
	results := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			sub := strings.TrimSpace(parts[0])
			if strings.HasSuffix(sub, "."+domain) && !seen[sub] {
				seen[sub] = true
				results = append(results, sub)
				fmt.Println(COLORS["TEAL"] + "[hackertarget] " + sub + COLORS["RESET"])
			}
		}
	}
	vroxSuccess("[hackertarget] Found " + strconv.Itoa(len(results)) + " subdomains")
	return results
}

func queryRapidDNS(domain string) []string {
	vroxInfo("[passive] Querying RapidDNS...")
	resp, err := httpClientFollow.Get("https://rapiddns.io/subdomain/" + domain + "?full=1&down=1")
	if err != nil { return []string{} }
	defer resp.Body.Close()
	buf := make([]byte, 500000)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	re := regexp.MustCompile(`([a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(body, -1)
	results := []string{}
	seen := map[string]bool{}
	for _, m := range matches {
		m = strings.ToLower(m)
		if !seen[m] {
			seen[m] = true
			results = append(results, m)
			fmt.Println(COLORS["TEAL"] + "[rapiddns] " + m + COLORS["RESET"])
		}
	}
	vroxSuccess("[rapiddns] Found " + strconv.Itoa(len(results)) + " subdomains")
	return results
}

func queryURLScan(domain string) []string {
	vroxInfo("[passive] Querying URLScan.io...")
	resp, err := httpClientFollow.Get("https://urlscan.io/api/v1/search/?q=domain:" + domain + "&size=100")
	if err != nil { return []string{} }
	defer resp.Body.Close()
	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	results := []string{}
	seen := map[string]bool{}
	if results_data, ok := data["results"].([]interface{}); ok {
		for _, r := range results_data {
			if entry, ok := r.(map[string]interface{}); ok {
				if page, ok := entry["page"].(map[string]interface{}); ok {
					if d, ok := page["domain"].(string); ok {
						d = strings.ToLower(d)
						if strings.HasSuffix(d, "."+domain) && !seen[d] {
							seen[d] = true
							results = append(results, d)
							fmt.Println(COLORS["TEAL"] + "[urlscan] " + d + COLORS["RESET"])
						}
					}
				}
			}
		}
	}
	vroxSuccess("[urlscan] Found " + strconv.Itoa(len(results)) + " subdomains")
	return results
}

func queryAlienVault(domain string) []string {
	vroxInfo("[passive] Querying AlienVault OTX...")
	resp, err := httpClientFollow.Get("https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns")
	if err != nil { return []string{} }
	defer resp.Body.Close()
	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	results := []string{}
	seen := map[string]bool{}
	if passive, ok := data["passive_dns"].([]interface{}); ok {
		for _, r := range passive {
			if entry, ok := r.(map[string]interface{}); ok {
				if hostname, ok := entry["hostname"].(string); ok {
					hostname = strings.ToLower(hostname)
					if strings.HasSuffix(hostname, "."+domain) && !seen[hostname] {
						seen[hostname] = true
						results = append(results, hostname)
						fmt.Println(COLORS["TEAL"] + "[alienvault] " + hostname + COLORS["RESET"])
					}
				}
			}
		}
	}
	vroxSuccess("[alienvault] Found " + strconv.Itoa(len(results)) + " subdomains")
	return results
}

func queryVirusTotal(domain string) []string {
	apiKey := globalAPIKeys["VIRUSTOTAL"]
	if apiKey == "" {
		vroxWarn("[virustotal] No API key set. Use: setkey VIRUSTOTAL your_key")
		return []string{}
	}
	vroxInfo("[passive] Querying VirusTotal...")
	req, _ := http.NewRequest("GET", "https://www.virustotal.com/api/v3/domains/"+domain+"/subdomains?limit=40", nil)
	req.Header.Set("x-apikey", apiKey)
	resp, err := httpClientFollow.Do(req)
	if err != nil { return []string{} }
	defer resp.Body.Close()
	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	results := []string{}
	seen := map[string]bool{}
	if d, ok := data["data"].([]interface{}); ok {
		for _, item := range d {
			if entry, ok := item.(map[string]interface{}); ok {
				if id, ok := entry["id"].(string); ok {
					id = strings.ToLower(id)
					if !seen[id] {
						seen[id] = true
						results = append(results, id)
						fmt.Println(COLORS["TEAL"] + "[virustotal] " + id + COLORS["RESET"])
					}
				}
			}
		}
	}
	vroxSuccess("[virustotal] Found " + strconv.Itoa(len(results)) + " subdomains")
	return results
}

// ============================================================
// UPGRADED SUBDOMAIN SCANNER (2.2)
// ============================================================
func scanSubdomains(domain string, wordlistFile string, passive bool) []string {
	allFound := []string{}
	seen := map[string]bool{}
	var mu sync.Mutex

	addResult := func(sub string) {
		sub = strings.ToLower(strings.TrimSpace(sub))
		mu.Lock()
		if !seen[sub] && strings.HasSuffix(sub, domain) {
			seen[sub] = true
			allFound = append(allFound, sub)
		}
		mu.Unlock()
	}

	// PASSIVE SOURCES (NEW IN 2.2)
	if passive {
		vroxPurple("[scan] Starting passive reconnaissance...")
		var wg sync.WaitGroup

		sources := []func(string) []string{
			queryCrtSh,
			queryHackerTarget,
			queryRapidDNS,
			queryURLScan,
			queryAlienVault,
			queryVirusTotal,
		}

		for _, source := range sources {
			wg.Add(1)
			go func(fn func(string) []string) {
				defer wg.Done()
				results := fn(domain)
				for _, r := range results { addResult(r) }
			}(source)
		}
		wg.Wait()
		vroxSuccess("[passive] Total from passive sources: " + strconv.Itoa(len(allFound)))
	}

	// ACTIVE BRUTE FORCE
	wordlist := []string{
		"www","mail","ftp","api","dev","test","staging","admin","blog","shop",
		"app","portal","dashboard","secure","cdn","static","media","images",
		"login","auth","support","docs","beta","old","new","v1","v2","api2",
		"mx","smtp","pop","imap","vpn","remote","cloud","s3","files","upload",
		"git","jenkins","jira","confluence","gitlab","prod","sandbox","qa",
		"internal","intranet","uat","mobile","m","api3","status","monitor",
		"metrics","grafana","kibana","elastic","redis","mysql","postgres",
		"mongo","backup","archive","pay","payment","checkout","store",
		"ns1","ns2","ns3","cpanel","whm","webmail","autodiscover","lyncdiscover",
		"sip","voip","wiki","forum","community","kb","help","demo","stage",
		"preprod","preview","uat2","test2","dev2","api4","gateway","proxy",
	}

	if wordlistFile != "" {
		data, err := os.ReadFile(wordlistFile)
		if err == nil {
			wordlist = strings.Split(strings.TrimSpace(string(data)), "\n")
			vroxInfo("[scan] Custom wordlist: " + strconv.Itoa(len(wordlist)) + " entries")
		}
	}

	vroxPurple("[scan] Starting active brute force...")
	var wg sync.WaitGroup
	for _, sub := range wordlist {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			full := s + "." + domain
			_, err := net.LookupHost(full)
			if err == nil {
				addResult(full)
				fmt.Println(COLORS["GREEN"] + "[bruteforce] Found: " + full + COLORS["RESET"])
			}
		}(sub)
	}
	wg.Wait()

	vroxSuccess("[scan] Total unique subdomains found: " + strconv.Itoa(len(allFound)))
	return allFound
}

// ============================================================
// UPGRADED HTTP PROBER — httpx-like (2.2)
// ============================================================
type HostInfo struct {
	Host       string
	StatusCode int
	Title      string
	Tech       []string
	Server     string
	ContentLen int
	ResponseMs int64
	Redirect   string
}

func probeHost(host string) HostInfo {
	info := HostInfo{Host: host}
	start := time.Now()
	req, err := http.NewRequest("GET", "https://"+host, nil)
	if err != nil { return info }
	req.Header.Set("User-Agent", "VroxScript/"+VERSION)
	for k, v := range globalHeaders { req.Header.Set(k, v) }
	resp, err := httpClientFollow.Do(req)
	if err != nil {
		// Try HTTP
		req2, err2 := http.NewRequest("GET", "http://"+host, nil)
		if err2 != nil { return info }
		resp2, err3 := httpClientFollow.Do(req2)
		if err3 != nil { return info }
		resp = resp2
	}
	defer resp.Body.Close()
	info.ResponseMs = time.Since(start).Milliseconds()
	info.StatusCode = resp.StatusCode
	info.Server = resp.Header.Get("Server")
	info.Redirect = resp.Header.Get("Location")
	buf := make([]byte, 50000)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	info.ContentLen = n
	// Extract title
	titleRe := regexp.MustCompile(`(?i)<title>([^<]+)</title>`)
	if m := titleRe.FindStringSubmatch(body); len(m) > 1 {
		info.Title = strings.TrimSpace(m[1])
	}
	// Detect tech
	techPatterns := map[string]string{
		"WordPress":"wp-content","React":"react","Angular":"angular",
		"Vue":"vue","jQuery":"jquery","Bootstrap":"bootstrap",
		"Nginx":"nginx","Apache":"apache","PHP":"php",
		"Cloudflare":"cloudflare","Next.js":"__NEXT_DATA__",
	}
	for tech, pattern := range techPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			info.Tech = append(info.Tech, tech)
		}
	}
	return info
}

func probeHosts(hosts []string) []HostInfo {
	results := []HostInfo{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	vroxInfo("[probe] Probing " + strconv.Itoa(len(hosts)) + " hosts...")
	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			// Clean host
			h = strings.Replace(h, "https://", "", 1)
			h = strings.Replace(h, "http://", "", 1)
			h = strings.Split(h, " ")[0]
			info := probeHost(h)
			if info.StatusCode > 0 {
				mu.Lock()
				results = append(results, info)
				color := COLORS["GREEN"]
				if info.StatusCode >= 400 { color = COLORS["YELLOW"] }
				if info.StatusCode >= 500 { color = COLORS["RED"] }
				fmt.Println(color + "[probe] " + h + " -> " + strconv.Itoa(info.StatusCode) +
					" | " + info.Title +
					" | " + strconv.FormatInt(info.ResponseMs, 10) + "ms" +
					" | " + info.Server + COLORS["RESET"])
				mu.Unlock()
			} else {
				fmt.Println(COLORS["RED"] + "[probe] " + h + " -> dead" + COLORS["RESET"])
			}
		}(host)
	}
	wg.Wait()
	vroxSuccess("[probe] " + strconv.Itoa(len(results)) + " hosts alive")
	return results
}

// ============================================================
// UPGRADED FUZZER — ffuf-like (2.2)
// ============================================================
type FuzzResult struct {
	URL        string
	StatusCode int
	Size       int
	Words      int
	ResponseMs int64
}

func fuzzAdvanced(targetURL string, wordlistFile string, filterStatus []int, filterSize int, threads int) []FuzzResult {
	wordlist := []string{
		"admin","login","dashboard","api","v1","v2","v3","config","backup",
		"test","dev","staging","upload","files","static","assets","images",
		"js","css","includes","wp-admin","administrator","manager","panel",
		"secret","private","internal","debug","console",".git",".env",
		"robots.txt","sitemap.xml","security.txt",".well-known","phpinfo.php",
		"server-status","api/v1","api/v2","api/v3","graphql","swagger",
		"swagger-ui","api-docs","actuator","metrics","health","status",
		"info","env","trace","dump","phpmyadmin","adminer","wp-login.php",
		"xmlrpc.php","wp-json","api/users","api/admin","api/config",
		"api/login","api/register","api/password","api/token","api/key",
	}

	if wordlistFile != "" {
		data, err := os.ReadFile(wordlistFile)
		if err == nil {
			wordlist = strings.Split(strings.TrimSpace(string(data)), "\n")
			vroxInfo("[fuzz] Custom wordlist: " + strconv.Itoa(len(wordlist)) + " entries")
		}
	}

	if threads <= 0 { threads = 50 }

	found := []FuzzResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	vroxInfo("[fuzz] Fuzzing " + targetURL + " with " + strconv.Itoa(len(wordlist)) + " words...")

	for _, path := range wordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			fullURL := strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(p, "/")
			start := time.Now()
			resp, err := httpClient.Get(fullURL)
			elapsed := time.Since(start).Milliseconds()

			if err != nil { return }
			defer resp.Body.Close()

			buf := make([]byte, 10000)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])
			wordCount := len(strings.Fields(body))

			// Apply filters
			if len(filterStatus) > 0 {
				found := false
				for _, s := range filterStatus {
					if resp.StatusCode == s { found = true; break }
				}
				if !found { return }
			} else if resp.StatusCode == 404 { return }

			if filterSize > 0 && n == filterSize { return }

			result := FuzzResult{
				URL: fullURL,
				StatusCode: resp.StatusCode,
				Size: n,
				Words: wordCount,
				ResponseMs: elapsed,
			}

			mu.Lock()
			found = append(found, result)
			color := COLORS["GREEN"]
			if resp.StatusCode == 403 { color = COLORS["YELLOW"] }
			if resp.StatusCode >= 500 { color = COLORS["RED"] }
			fmt.Println(color + "[fuzz] " + fullURL +
				" [" + strconv.Itoa(resp.StatusCode) + "]" +
				" [size:" + strconv.Itoa(n) + "]" +
				" [words:" + strconv.Itoa(wordCount) + "]" +
				" [" + strconv.FormatInt(elapsed, 10) + "ms]" + COLORS["RESET"])
			mu.Unlock()
		}(path)
	}
	wg.Wait()
	vroxSuccess("[fuzz] Found " + strconv.Itoa(len(found)) + " results")
	return found
}

// ============================================================
// NUCLEI-LIKE TEMPLATE ENGINE (2.2)
// ============================================================
type VroxTemplate struct {
	Name     string
	Severity string
	Target   string
	Method   string
	Path     string
	Headers  map[string]string
	Body     string
	Matchers []string
	Extractor string
}

func loadTemplate(filename string) (VroxTemplate, error) {
	data, err := os.ReadFile(filename)
	if err != nil { return VroxTemplate{}, err }

	tmpl := VroxTemplate{Headers: map[string]string{}}
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name:") { tmpl.Name = strings.TrimSpace(line[5:]) }
		if strings.HasPrefix(line, "severity:") { tmpl.Severity = strings.TrimSpace(line[9:]) }
		if strings.HasPrefix(line, "method:") { tmpl.Method = strings.TrimSpace(line[7:]) }
		if strings.HasPrefix(line, "path:") { tmpl.Path = strings.TrimSpace(line[5:]) }
		if strings.HasPrefix(line, "body:") { tmpl.Body = strings.TrimSpace(line[5:]) }
		if strings.HasPrefix(line, "match:") { tmpl.Matchers = append(tmpl.Matchers, strings.TrimSpace(line[6:])) }
		if strings.HasPrefix(line, "extract:") { tmpl.Extractor = strings.TrimSpace(line[8:]) }
		if strings.HasPrefix(line, "header:") {
			parts := strings.SplitN(line[7:], ":", 2)
			if len(parts) == 2 { tmpl.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1]) }
		}
	}
	return tmpl, nil
}

func runTemplate(tmpl VroxTemplate, target string) (bool, string) {
	method := tmpl.Method
	if method == "" { method = "GET" }

	path := tmpl.Path
	if path == "" { path = "/" }

	fullURL := strings.TrimRight(target, "/") + path
	if strings.HasPrefix(path, "http") { fullURL = path }

	var req *http.Request
	var err error

	if tmpl.Body != "" {
		req, err = http.NewRequest(method, fullURL, strings.NewReader(tmpl.Body))
	} else {
		req, err = http.NewRequest(method, fullURL, nil)
	}
	if err != nil { return false, "" }

	req.Header.Set("User-Agent", "VroxScript/"+VERSION)
	for k, v := range tmpl.Headers { req.Header.Set(k, v) }
	for k, v := range globalHeaders { req.Header.Set(k, v) }

	resp, err := httpClientFollow.Do(req)
	if err != nil { return false, "" }
	defer resp.Body.Close()

	buf := make([]byte, 50000)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Check matchers
	for _, matcher := range tmpl.Matchers {
		if strings.HasPrefix(matcher, "status:") {
			code, _ := strconv.Atoi(strings.TrimSpace(matcher[7:]))
			if resp.StatusCode != code { return false, "" }
		} else if strings.HasPrefix(matcher, "regex:") {
			pattern := strings.TrimSpace(matcher[6:])
			re, err := regexp.Compile(pattern)
			if err != nil { continue }
			if !re.MatchString(body) { return false, "" }
		} else {
			if !strings.Contains(body, matcher) { return false, "" }
		}
	}

	// Extract data
	extracted := ""
	if tmpl.Extractor != "" {
		re, err := regexp.Compile(tmpl.Extractor)
		if err == nil {
			matches := re.FindAllString(body, -1)
			extracted = strings.Join(matches, ", ")
		}
	}

	return true, extracted
}

func runTemplatesDir(dir string, target string) []string {
	results := []string{}
	vroxInfo("[templates] Scanning with templates from: " + dir + "...")

	files, err := os.ReadDir(dir)
	if err != nil {
		vroxWarn("[templates] Cannot read directory: " + dir)
		return results
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".vstemplate") { continue }

		tmpl, err := loadTemplate(dir + "/" + file.Name())
		if err != nil { continue }

		matched, extracted := runTemplate(tmpl, target)
		if matched {
			severity := tmpl.Severity
			color := COLORS["YELLOW"]
			if severity == "critical" { color = COLORS["RED"] + COLORS["BOLD"] }
			if severity == "high" { color = COLORS["RED"] }
			if severity == "medium" { color = COLORS["YELLOW"] }
			if severity == "low" { color = COLORS["CYAN"] }
			if severity == "info" { color = COLORS["GREEN"] }

			result := "[" + strings.ToUpper(severity) + "] " + tmpl.Name + " -> " + target
			if extracted != "" { result += " | Extracted: " + extracted }
			results = append(results, result)
			fmt.Println(color + "[template] MATCH: " + result + COLORS["RESET"])
		}
	}

	if len(results) == 0 { vroxSuccess("[templates] No vulnerabilities found") }
	return results
}

// ============================================================
// ALL EXISTING SECURITY FUNCTIONS (KEPT FROM 2.1)
// ============================================================
func checkAlive(hosts []string) []string {
	results := probeHosts(hosts)
	alive := []string{}
	for _, r := range results {
		alive = append(alive, r.Host+" -> "+strconv.Itoa(r.StatusCode))
	}
	return alive
}

func scanPorts(host string, customPorts []int) []string {
	ports := []int{21,22,23,25,53,80,443,445,3306,3389,8080,8443,8888,9200,6379,27017,5432,1433,9300,4443}
	if len(customPorts) > 0 { ports = customPorts }
	portNames := map[int]string{
		21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
		443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",8080:"HTTP-Alt",
		8443:"HTTPS-Alt",9200:"Elasticsearch",6379:"Redis",27017:"MongoDB",
		5432:"PostgreSQL",1433:"MSSQL",
	}
	open := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(p), 1*time.Second)
			if err == nil {
				conn.Close()
				name := portNames[p]
				if name == "" { name = "Unknown" }
				result := strconv.Itoa(p) + "/" + name
				mu.Lock()
				open = append(open, result)
				color := COLORS["GREEN"]
				if p == 22 || p == 3389 || p == 3306 || p == 27017 { color = COLORS["RED"] }
				fmt.Println(color + "[ports] " + host + ":" + result + " -> open" + COLORS["RESET"])
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return open
}

func grabHeaders(targetURL string) map[string]string {
	headers := map[string]string{}
	req, _ := http.NewRequest("GET", targetURL, nil)
	for k, v := range globalHeaders { req.Header.Set(k, v) }
	for k, v := range globalCookies { req.AddCookie(&http.Cookie{Name: k, Value: v}) }
	resp, err := httpClientFollow.Do(req)
	if err != nil { fmt.Println(COLORS["RED"] + "[headers] Failed: " + err.Error() + COLORS["RESET"]); return headers }
	defer resp.Body.Close()
	for _, c := range resp.Cookies() { globalCookies[c.Name] = c.Value }
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
		fmt.Println(COLORS["CYAN"] + "[header] " + k + ": " + strings.Join(v, ", ") + COLORS["RESET"])
	}
	return headers
}

func checkSecHeaders(targetURL string) ([]string, []string) {
	important := map[string]string{
		"Strict-Transport-Security":"HSTS","X-Frame-Options":"Clickjacking Protection",
		"X-Content-Type-Options":"MIME Sniffing Protection","Content-Security-Policy":"CSP",
		"X-XSS-Protection":"XSS Protection","Referrer-Policy":"Referrer Policy",
		"Permissions-Policy":"Permissions Policy",
	}
	headers := grabHeaders(targetURL)
	missing := []string{}
	present := []string{}
	for header, name := range important {
		found := false
		for k := range headers {
			if strings.EqualFold(k, header) { found = true; break }
		}
		if found {
			present = append(present, name)
			fmt.Println(COLORS["GREEN"] + "[secheaders] Present: " + name + COLORS["RESET"])
		} else {
			missing = append(missing, name)
			fmt.Println(COLORS["RED"] + "[secheaders] Missing: " + name + COLORS["RESET"])
		}
	}
	return missing, present
}

func dnsLookup(domain string) map[string]string {
	records := map[string]string{}
	ips, err := net.LookupHost(domain)
	if err == nil { records["A"] = strings.Join(ips, ", "); fmt.Println(COLORS["GREEN"] + "[dns] A: " + strings.Join(ips, ", ") + COLORS["RESET"]) }
	cname, err := net.LookupCNAME(domain)
	if err == nil && cname != domain+"." { records["CNAME"] = cname; fmt.Println(COLORS["CYAN"] + "[dns] CNAME: " + cname + COLORS["RESET"]) }
	mxs, err := net.LookupMX(domain)
	if err == nil { for _, mx := range mxs { fmt.Println(COLORS["CYAN"] + "[dns] MX: " + mx.Host + COLORS["RESET"]) } }
	txts, err := net.LookupTXT(domain)
	if err == nil { for _, txt := range txts { fmt.Println(COLORS["CYAN"] + "[dns] TXT: " + txt + COLORS["RESET"]); records["TXT"] = txt } }
	nss, err := net.LookupNS(domain)
	if err == nil { for _, ns := range nss { fmt.Println(COLORS["CYAN"] + "[dns] NS: " + ns.Host + COLORS["RESET"]) } }
	return records
}

func fetchPage(targetURL string) (int, string, map[string]string) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil { return 0, "", map[string]string{} }
	req.Header.Set("User-Agent", "VroxScript/"+VERSION)
	for k, v := range globalHeaders { req.Header.Set(k, v) }
	for k, v := range globalCookies { req.AddCookie(&http.Cookie{Name: k, Value: v}) }
	start := time.Now()
	resp, err := httpClientFollow.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil { fmt.Println(COLORS["RED"] + "[fetch] " + targetURL + " -> failed" + COLORS["RESET"]); return 0, "", map[string]string{} }
	defer resp.Body.Close()
	for _, c := range resp.Cookies() { globalCookies[c.Name] = c.Value }
	buf := make([]byte, 10000)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	headers := map[string]string{}
	for k, v := range resp.Header { headers[k] = strings.Join(v, ", ") }
	fmt.Println(COLORS["GREEN"] + "[fetch] " + targetURL + " -> " + strconv.Itoa(resp.StatusCode) + " (" + strconv.FormatInt(elapsed, 10) + "ms)" + COLORS["RESET"])
	return resp.StatusCode, body, headers
}

func crawlLinks(targetURL string) []string {
	_, body, _ := fetchPage(targetURL)
	links := []string{}
	seen := map[string]bool{}
	re := regexp.MustCompile(`href="(https?://[^"]+)"`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		if !seen[m[1]] { seen[m[1]] = true; links = append(links, m[1]); fmt.Println(COLORS["CYAN"] + "[crawl] " + m[1] + COLORS["RESET"]) }
	}
	return links
}

func extractJSUrls(targetURL string) []string {
	_, body, _ := fetchPage(targetURL)
	results := []string{}
	seen := map[string]bool{}
	re1 := regexp.MustCompile(`["'](/[a-zA-Z0-9/_\-.]+)["']`)
	re2 := regexp.MustCompile(`src=["']([^"']+\.js)["']`)
	for _, m := range re1.FindAllStringSubmatch(body, -1) {
		if !seen[m[1]] { seen[m[1]] = true; results = append(results, m[1]); fmt.Println(COLORS["CYAN"] + "[js] " + m[1] + COLORS["RESET"]) }
	}
	for _, m := range re2.FindAllStringSubmatch(body, -1) {
		if !seen[m[1]] { seen[m[1]] = true; results = append(results, m[1]); fmt.Println(COLORS["CYAN"] + "[js] " + m[1] + COLORS["RESET"]) }
	}
	return results
}

func extractParams(rawURL string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil { return []string{} }
	results := []string{}
	for k, v := range parsed.Query() {
		result := k + "=" + strings.Join(v, ",")
		results = append(results, result)
		fmt.Println(COLORS["CYAN"] + "[params] " + result + COLORS["RESET"])
	}
	return results
}

func waybackLookup(domain string) []string {
	apiURL := "http://web.archive.org/cdx/search/cdx?url=" + domain + "/*&output=json&limit=30&fl=original"
	resp, err := httpClientFollow.Get(apiURL)
	if err != nil { fmt.Println(COLORS["RED"] + "[wayback] Failed" + COLORS["RESET"]); return []string{} }
	defer resp.Body.Close()
	var data [][]string
	json.NewDecoder(resp.Body).Decode(&data)
	results := []string{}
	if len(data) > 1 {
		for _, item := range data[1:] {
			results = append(results, item[0])
			fmt.Println(COLORS["CYAN"] + "[wayback] " + item[0] + COLORS["RESET"])
		}
	}
	return results
}

func grepSecrets(content string) map[string][]string {
	patterns := map[string]string{
		"API Key":      `(?i)api[_-]?key["'\s:=]+([a-zA-Z0-9_\-]{20,})`,
		"Secret":       `(?i)secret["'\s:=]+([a-zA-Z0-9_\-]{20,})`,
		"Token":        `(?i)token["'\s:=]+([a-zA-Z0-9_\-]{20,})`,
		"Password":     `(?i)password["'\s:=]+([a-zA-Z0-9_\-]{8,})`,
		"AWS Key":      `AKIA[0-9A-Z]{16}`,
		"Private Key":  `-----BEGIN (RSA |EC )?PRIVATE KEY-----`,
		"Email":        `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		"JWT":          `eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`,
		"Google API":   `AIza[0-9A-Za-z\-_]{35}`,
		"GitHub Token": `ghp_[a-zA-Z0-9]{36}`,
		"Slack Token":  `xox[baprs]-[0-9a-zA-Z\-]+`,
	}
	found := map[string][]string{}
	for name, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(content, -1)
		if len(matches) > 0 {
			found[name] = matches
			fmt.Println(COLORS["RED"] + "[secrets] Found " + name + ": " + strings.Join(matches, ", ") + COLORS["RESET"])
		}
	}
	return found
}

func checkSubdomainTakeover(domain string, subdomains []string) []string {
	cnames := map[string]string{
		"amazonaws.com":"AWS S3","github.io":"GitHub Pages","herokuapp.com":"Heroku",
		"azurewebsites.net":"Azure","ghost.io":"Ghost","myshopify.com":"Shopify",
		"webflow.io":"Webflow","netlify.app":"Netlify","vercel.app":"Vercel","surge.sh":"Surge",
	}
	vulnerable := []string{}
	vroxInfo("[takeover] Checking " + strconv.Itoa(len(subdomains)) + " subdomains...")
	for _, sub := range subdomains {
		cname, err := net.LookupCNAME(sub)
		if err == nil {
			for pattern, service := range cnames {
				if strings.Contains(cname, pattern) {
					resp, err := httpClientFollow.Get("https://" + sub)
					if err != nil || resp.StatusCode == 404 {
						result := sub + " -> VULNERABLE (" + service + ")"
						vulnerable = append(vulnerable, result)
						fmt.Println(COLORS["RED"] + "[takeover] " + result + COLORS["RESET"])
					}
				}
			}
		}
	}
	if len(vulnerable) == 0 { vroxSuccess("[takeover] No subdomain takeover found") }
	return vulnerable
}

func checkCORS(targetURL string) map[string]string {
	results := map[string]string{}
	origins := []string{"https://evil.com", "null"}
	vroxInfo("[cors] Testing CORS...")
	for _, origin := range origins {
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil { continue }
		req.Header.Set("Origin", origin)
		resp, err := httpClientFollow.Do(req)
		if err != nil { continue }
		defer resp.Body.Close()
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		if acao == "*" {
			fmt.Println(COLORS["RED"] + "[cors] VULNERABLE: Wildcard" + COLORS["RESET"])
			results["wildcard"] = "*"
		} else if acao == origin {
			fmt.Println(COLORS["RED"] + "[cors] VULNERABLE: Reflected " + origin + COLORS["RESET"])
			results[origin] = "Reflected"
			if acac == "true" {
				fmt.Println(COLORS["RED"] + "[cors] CRITICAL: Credentials allowed!" + COLORS["RESET"])
				results["credentials"] = "true"
			}
		} else {
			fmt.Println(COLORS["GREEN"] + "[cors] " + origin + " -> safe" + COLORS["RESET"])
		}
	}
	if len(results) == 0 { vroxSuccess("[cors] No CORS issues found") }
	return results
}

func checkSSL(targetURL string) map[string]string {
	results := map[string]string{}
	host := strings.Replace(strings.Replace(targetURL, "https://", "", 1), "http://", "", 1)
	host = strings.Split(host, "/")[0]
	vroxInfo("[ssl] Checking " + host + "...")
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{InsecureSkipVerify: false})
	if err != nil { fmt.Println(COLORS["RED"] + "[ssl] Error: " + err.Error() + COLORS["RESET"]); results["error"] = err.Error(); return results }
	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	results["subject"] = cert.Subject.CommonName
	results["issuer"] = cert.Issuer.CommonName
	results["expires"] = cert.NotAfter.Format("2006-01-02")
	results["days_left"] = strconv.Itoa(daysLeft)
	fmt.Println(COLORS["CYAN"] + "[ssl] Subject: " + cert.Subject.CommonName + COLORS["RESET"])
	fmt.Println(COLORS["CYAN"] + "[ssl] Issuer: " + cert.Issuer.CommonName + COLORS["RESET"])
	fmt.Println(COLORS["CYAN"] + "[ssl] Expires: " + cert.NotAfter.Format("2006-01-02") + COLORS["RESET"])
	if daysLeft < 30 { fmt.Println(COLORS["RED"] + "[ssl] WARNING: Expires in " + strconv.Itoa(daysLeft) + " days!" + COLORS["RESET"])
	} else { fmt.Println(COLORS["GREEN"] + "[ssl] Valid for " + strconv.Itoa(daysLeft) + " more days" + COLORS["RESET"]) }
	return results
}

func detectTech(targetURL string) []string {
	_, body, headers := fetchPage(targetURL)
	patterns := map[string]string{
		"WordPress":"wp-content|wp-includes","jQuery":"jquery","React":"react|__REACT",
		"Angular":"angular|ng-version","Vue.js":"vue|__VUE","Bootstrap":"bootstrap",
		"Laravel":"laravel","Django":"django|csrftoken","Rails":"rails",
		"ASP.NET":"aspnet|__VIEWSTATE","PHP":"\\.php","Nginx":"nginx",
		"Apache":"apache","Cloudflare":"cloudflare","Next.js":"__NEXT_DATA__",
		"Nuxt.js":"__NUXT__","Gatsby":"gatsby","Express":"express","Spring":"spring",
	}
	technologies := []string{}
	seen := map[string]bool{}
	vroxInfo("[techdetect] Detecting technologies...")
	for tech, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if re.MatchString(body) && !seen[tech] {
			seen[tech] = true; technologies = append(technologies, tech)
			fmt.Println(COLORS["GREEN"] + "[techdetect] Found: " + tech + COLORS["RESET"])
			continue
		}
		for _, v := range headers {
			if re.MatchString(v) && !seen[tech] {
				seen[tech] = true; technologies = append(technologies, tech)
				fmt.Println(COLORS["GREEN"] + "[techdetect] Found: " + tech + COLORS["RESET"])
				break
			}
		}
	}
	return technologies
}

func extractEmails(targetURL string) []string {
	_, body, _ := fetchPage(targetURL)
	re := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	seen := map[string]bool{}
	results := []string{}
	for _, m := range re.FindAllString(body, -1) {
		if !seen[m] { seen[m] = true; results = append(results, m); fmt.Println(COLORS["CYAN"] + "[emails] " + m + COLORS["RESET"]) }
	}
	return results
}

func whoisLookup(domain string) string {
	vroxInfo("[whois] Looking up " + domain + "...")
	resp, err := httpClientFollow.Get("https://api.whoisjson.com/v1/" + domain)
	if err != nil { fmt.Println(COLORS["RED"] + "[whois] Failed" + COLORS["RESET"]); return "" }
	defer resp.Body.Close()
	buf := make([]byte, 5000)
	n, _ := resp.Body.Read(buf)
	result := string(buf[:n])
	fmt.Println(COLORS["CYAN"] + "[whois] " + result + COLORS["RESET"])
	return result
}

func checkRateLimit(targetURL string) map[string]string {
	results := map[string]string{}
	vroxInfo("[ratelimit] Testing rate limiting...")
	codes := map[int]int{}
	for i := 0; i < 20; i++ {
		resp, err := httpClientFollow.Get(targetURL)
		if err == nil { codes[resp.StatusCode]++; resp.Body.Close() }
		time.Sleep(100 * time.Millisecond)
	}
	if codes[429] > 0 { vroxSuccess("[ratelimit] Rate limiting enforced"); results["status"] = "protected"
	} else if codes[200] == 20 { fmt.Println(COLORS["RED"] + "[ratelimit] No rate limiting!" + COLORS["RESET"]); results["status"] = "vulnerable"
	} else { vroxWarn("[ratelimit] Inconclusive"); results["status"] = "inconclusive" }
	return results
}

func checkOpenRedirect(targetURL string) []string {
	payloads := []string{"//evil.com", "https://evil.com", "/\\evil.com"}
	params := []string{"url","redirect","next","return","goto","dest","redir","redirect_uri","return_url"}
	vulnerable := []string{}
	vroxInfo("[openredirect] Testing...")
	parsed, err := url.Parse(targetURL)
	if err != nil { return vulnerable }
	for _, param := range params {
		for _, payload := range payloads {
			testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
			resp, err := httpClient.Get(testURL)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == 301 || resp.StatusCode == 302 {
					location := resp.Header.Get("Location")
					if strings.Contains(location, "evil.com") {
						result := param + "=" + payload + " -> VULNERABLE"
						vulnerable = append(vulnerable, result)
						fmt.Println(COLORS["RED"] + "[openredirect] " + result + COLORS["RESET"])
					}
				}
			}
		}
	}
	if len(vulnerable) == 0 { vroxSuccess("[openredirect] No open redirect found") }
	return vulnerable
}

func checkSQLi(targetURL string, param string) []string {
	payloads := []string{"'","''","' OR '1'='1","' OR 1=1--","\" OR 1=1--"}
	errors := []string{"sql syntax","mysql_fetch","ora-","sqlite_","warning: mysql","you have an error in your sql","sqlstate","syntax error"}
	vulnerable := []string{}
	vroxInfo("[sqli] Testing param: " + param + "...")
	parsed, err := url.Parse(targetURL)
	if err != nil { return vulnerable }
	for _, payload := range payloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 5000)
			n, _ := resp.Body.Read(buf)
			body := strings.ToLower(string(buf[:n]))
			for _, e := range errors {
				if strings.Contains(body, e) {
					result := param + "=" + payload + " -> SQL ERROR"
					vulnerable = append(vulnerable, result)
					fmt.Println(COLORS["RED"] + "[sqli] POSSIBLE: " + result + COLORS["RESET"])
					break
				}
			}
		}
	}
	if len(vulnerable) == 0 { vroxSuccess("[sqli] No SQL errors found") }
	return vulnerable
}

func checkXSS(targetURL string, param string) []string {
	payloads := []string{
		"<script>alert(1)</script>","<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>","'><script>alert(1)</script>",
	}
	vulnerable := []string{}
	vroxInfo("[xss] Testing param: " + param + "...")
	parsed, err := url.Parse(targetURL)
	if err != nil { return vulnerable }
	for _, payload := range payloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 5000)
			n, _ := resp.Body.Read(buf)
			if strings.Contains(string(buf[:n]), payload) {
				result := param + "=" + payload + " -> REFLECTED"
				vulnerable = append(vulnerable, result)
				fmt.Println(COLORS["RED"] + "[xss] POSSIBLE: " + result + COLORS["RESET"])
			}
		}
	}
	if len(vulnerable) == 0 { vroxSuccess("[xss] No XSS reflection found") }
	return vulnerable
}

func checkSSRF(targetURL string, param string) []string {
	payloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost/","http://127.0.0.1/",
	}
	vulnerable := []string{}
	vroxInfo("[ssrf] Testing param: " + param + "...")
	parsed, err := url.Parse(targetURL)
	if err != nil { return vulnerable }
	for _, payload := range payloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 1000)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])
			if strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") {
				result := param + "=" + payload + " -> VULNERABLE"
				vulnerable = append(vulnerable, result)
				fmt.Println(COLORS["RED"] + "[ssrf] VULNERABLE: " + result + COLORS["RESET"])
			}
		}
	}
	if len(vulnerable) == 0 { vroxSuccess("[ssrf] No obvious SSRF found") }
	return vulnerable
}

func checkLFI(targetURL string, param string) []string {
	payloads := []string{"../etc/passwd","../../etc/passwd","../../../etc/passwd","/etc/passwd"}
	vulnerable := []string{}
	vroxInfo("[lfi] Testing param: " + param + "...")
	parsed, err := url.Parse(targetURL)
	if err != nil { return vulnerable }
	for _, payload := range payloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + payload
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 2000)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])
			if strings.Contains(body, "root:") || strings.Contains(body, "bin:") {
				result := param + "=" + payload + " -> VULNERABLE"
				vulnerable = append(vulnerable, result)
				fmt.Println(COLORS["RED"] + "[lfi] VULNERABLE: " + result + COLORS["RESET"])
			}
		}
	}
	if len(vulnerable) == 0 { vroxSuccess("[lfi] No LFI found") }
	return vulnerable
}

func checkCRLF(targetURL string) []string {
	payloads := []string{"%0d%0aHeader:injected","%0aHeader:injected"}
	vulnerable := []string{}
	vroxInfo("[crlf] Testing CRLF...")
	for _, payload := range payloads {
		testURL := targetURL + "?" + payload
		resp, err := httpClient.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			for k := range resp.Header {
				if strings.ToLower(k) == "header" {
					result := payload + " -> VULNERABLE"
					vulnerable = append(vulnerable, result)
					fmt.Println(COLORS["RED"] + "[crlf] VULNERABLE: " + result + COLORS["RESET"])
					break
				}
			}
		}
	}
	if len(vulnerable) == 0 { vroxSuccess("[crlf] No CRLF found") }
	return vulnerable
}

func checkSSTI(targetURL string, param string) []string {
	payloads := []string{"{{7*7}}","${7*7}","<%= 7*7 %>"}
	vulnerable := []string{}
	vroxInfo("[ssti] Testing param: " + param + "...")
	parsed, err := url.Parse(targetURL)
	if err != nil { return vulnerable }
	for _, payload := range payloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 2000)
			n, _ := resp.Body.Read(buf)
			if strings.Contains(string(buf[:n]), "49") {
				result := param + "=" + payload + " -> VULNERABLE"
				vulnerable = append(vulnerable, result)
				fmt.Println(COLORS["RED"] + "[ssti] VULNERABLE: " + result + COLORS["RESET"])
			}
		}
	}
	if len(vulnerable) == 0 { vroxSuccess("[ssti] No SSTI found") }
	return vulnerable
}

func measureResponseTime(targetURL string, count int) map[string]string {
	results := map[string]string{}
	vroxInfo("[timing] Measuring response time...")
	var total int64; var min int64 = 99999; var max int64 = 0
	for i := 0; i < count; i++ {
		start := time.Now()
		resp, err := httpClientFollow.Get(targetURL)
		elapsed := time.Since(start).Milliseconds()
		if err == nil { resp.Body.Close(); total += elapsed; if elapsed < min { min = elapsed }; if elapsed > max { max = elapsed } }
	}
	avg := total / int64(count)
	results["min"] = strconv.FormatInt(min, 10) + "ms"
	results["max"] = strconv.FormatInt(max, 10) + "ms"
	results["avg"] = strconv.FormatInt(avg, 10) + "ms"
	fmt.Println(COLORS["CYAN"] + "[timing] Min: " + results["min"] + " Max: " + results["max"] + " Avg: " + results["avg"] + COLORS["RESET"])
	return results
}

func followRedirects(targetURL string) []string {
	chain := []string{}
	vroxInfo("[redirect] Following redirect chain...")
	current := targetURL
	for i := 0; i < 10; i++ {
		resp, err := httpClient.Get(current)
		if err != nil { break }
		resp.Body.Close()
		chain = append(chain, current+" -> "+strconv.Itoa(resp.StatusCode))
		fmt.Println(COLORS["CYAN"] + "[redirect] " + current + " -> " + strconv.Itoa(resp.StatusCode) + COLORS["RESET"])
		if resp.StatusCode != 301 && resp.StatusCode != 302 { break }
		location := resp.Header.Get("Location")
		if location == "" { break }
		current = location
	}
	return chain
}

func regexSearch(pattern string, content string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil { fmt.Println(COLORS["RED"] + "[regex] Invalid: " + err.Error() + COLORS["RESET"]); return []string{} }
	matches := re.FindAllString(content, -1)
	for _, m := range matches { fmt.Println(COLORS["CYAN"] + "[regex] " + m + COLORS["RESET"]) }
	return matches
}

func generateReport(target string, variables map[string]interface{}) string {
	now := time.Now().Format("2006-01-02 15:04:05")
	lines := []string{
		"============================================================",
		"VroxScript " + VERSION + " Security Report",
		"Target: " + target,
		"Generated: " + now,
		"============================================================",
	}
	sections := []struct{ key, title string }{
		{"resolved_ip","IP"},{"scan_results","Subdomains"},
		{"alive_results","Alive Hosts"},{"port_results","Open Ports"},
		{"tech_results","Technologies"},{"fuzz_results","Fuzz Results"},
		{"wayback_results","Wayback URLs"},{"missing_headers","Missing Security Headers"},
		{"cors_results","CORS Issues"},{"takeover_results","Subdomain Takeover"},
		{"openredirect_results","Open Redirect"},{"sqli_results","SQL Injection"},
		{"xss_results","XSS"},{"ssrf_results","SSRF"},{"lfi_results","LFI"},
		{"crlf_results","CRLF"},{"ssti_results","SSTI"},
		{"ssl_results","SSL"},{"ratelimit_results","Rate Limit"},
		{"email_results","Emails"},{"secrets_found","Secrets"},
		{"template_results","Template Scan Results"},
	}
	for _, s := range sections {
		if v, ok := variables[s.key]; ok {
			switch val := v.(type) {
			case []string:
				if len(val) > 0 {
					lines = append(lines, "\n["+s.title+": "+strconv.Itoa(len(val))+"]")
					for _, item := range val { lines = append(lines, "  "+item) }
				}
			case string:
				if val != "" { lines = append(lines, "\n["+s.title+"]\n  "+val) }
			case map[string]string:
				if len(val) > 0 {
					lines = append(lines, "\n["+s.title+"]")
					for k, v2 := range val { lines = append(lines, "  "+k+": "+v2) }
				}
			}
		}
	}
	lines = append(lines, "\n============================================================")
	lines = append(lines, "VroxScript "+VERSION)
	lines = append(lines, "github.com/InterviewCopilot350/vroxscript")
	lines = append(lines, "============================================================")
	return strings.Join(lines, "\n")
}

func saveToFile(filename string, content string) {
	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil { fmt.Println(COLORS["RED"] + "[save] Failed: " + err.Error() + COLORS["RESET"])
	} else { vroxInfo("[save] Written to " + filename) }
}

func importFile(filename string, variables map[string]interface{}, debug bool) {
	data, err := os.ReadFile(filename)
	if err != nil { fmt.Println(COLORS["RED"] + "[import] Cannot open: " + filename + COLORS["RESET"]); return }
	vroxInfo("[import] Loading: " + filename)
	runCode(string(data), variables, debug)
}

// ============================================================
// INTERPRETER
// ============================================================
func runCode(code string, variables map[string]interface{}, debug bool) {
	lines := strings.Split(code, "\n")
	i := 0
	for i < len(lines) {
		if breakSignal || continueSignal { break }
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") { i++; continue }
		if debug { fmt.Println(COLORS["YELLOW"] + "[debug] Line " + strconv.Itoa(i+1) + ": " + line + COLORS["RESET"]) }
		saveTo := ""
		if strings.Contains(line, ">>") {
			parts := strings.SplitN(line, ">>", 2)
			line = strings.TrimSpace(parts[0])
			saveTo = strings.TrimSpace(parts[1])
		}
		switch {
		case strings.HasPrefix(line, "if "):
			condition := strings.TrimSuffix(strings.TrimPrefix(line, "if "), " {")
			block, elseBlock := []string{}, []string{}
			i++; inElse := false
			for i < len(lines) {
				l := strings.TrimSpace(lines[i])
				if l == "}" && !inElse {
					if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "else") { inElse = true; i += 2; continue }
					break
				} else if l == "}" && inElse { break
				} else if inElse { elseBlock = append(elseBlock, lines[i])
				} else { block = append(block, lines[i]) }
				i++
			}
			if evalCondition(condition, variables) { runCode(strings.Join(block, "\n"), variables, debug)
			} else if len(elseBlock) > 0 { runCode(strings.Join(elseBlock, "\n"), variables, debug) }

		case strings.HasPrefix(line, "while "):
			condition := strings.TrimSuffix(strings.TrimPrefix(line, "while "), " {")
			block := []string{}; i++
			for i < len(lines) { if strings.TrimSpace(lines[i]) == "}" { break }; block = append(block, lines[i]); i++ }
			count := 0
			for evalCondition(condition, variables) && count < 10000 {
				continueSignal = false
				runCode(strings.Join(block, "\n"), variables, debug)
				if breakSignal { breakSignal = false; break }
				count++
			}

		case strings.HasPrefix(line, "repeat "):
			parts := strings.Fields(line)
			count, _ := strconv.Atoi(resolveValue(parts[1], variables))
			block := []string{}; i++
			for i < len(lines) { if strings.TrimSpace(lines[i]) == "}" { break }; block = append(block, lines[i]); i++ }
			for j := 0; j < count; j++ {
				continueSignal = false
				runCode(strings.Join(block, "\n"), variables, debug)
				if breakSignal { breakSignal = false; break }
			}

		case strings.HasPrefix(line, "for "):
			parts := strings.Fields(strings.TrimSuffix(line, " {"))
			varName, listName := parts[1], parts[3]
			block := []string{}; i++
			for i < len(lines) { if strings.TrimSpace(lines[i]) == "}" { break }; block = append(block, lines[i]); i++ }
			if items, ok := variables[listName].([]string); ok {
				for _, item := range items {
					continueSignal = false
					variables[varName] = item
					runCode(strings.Join(block, "\n"), variables, debug)
					if breakSignal { breakSignal = false; break }
				}
			}

		case strings.HasPrefix(line, "func "):
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "func "), " {"))
			block := []string{}; i++
			for i < len(lines) { if strings.TrimSpace(lines[i]) == "}" { break }; block = append(block, lines[i]); i++ }
			variables["__func_"+name] = strings.Join(block, "\n")

		case strings.HasPrefix(line, "call "):
			parts := strings.Fields(line)
			name := parts[1]; args := parts[2:]
			if code, ok := variables["__func_"+name].(string); ok {
				localVars := map[string]interface{}{}
				for k, v := range variables { localVars[k] = v }
				for idx, arg := range args { localVars["arg"+strconv.Itoa(idx+1)] = resolveValue(arg, variables) }
				runCode(code, localVars, debug)
				for k, v := range localVars {
					if !strings.HasPrefix(k, "__func_") { variables[k] = v }
				}
			} else { vroxError("Unknown function: "+name, i+1) }

		case strings.HasPrefix(line, "try"):
			tryBlock, catchBlock := []string{}, []string{}
			i++; inCatch := false
			for i < len(lines) {
				l := strings.TrimSpace(lines[i])
				if l == "}" && !inCatch {
					if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "catch") { inCatch = true; i += 2; continue }
					break
				} else if l == "}" && inCatch { break
				} else if inCatch { catchBlock = append(catchBlock, lines[i])
				} else { tryBlock = append(tryBlock, lines[i]) }
				i++
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						if len(catchBlock) > 0 { runCode(strings.Join(catchBlock, "\n"), variables, debug) }
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

	case line == "break": breakSignal = true
	case line == "continue": continueSignal = true

	// ---- API KEYS (NEW 2.2) ----
	case strings.HasPrefix(line, "setkey "):
		parts := strings.Fields(line[7:])
		if len(parts) == 2 {
			key := parts[0]
			val := resolveExpression(parts[1], variables)
			globalAPIKeys[key] = val
			vroxOrange("[apikey] Set " + key)
		}

	case strings.HasPrefix(line, "getkey "):
		key := strings.TrimSpace(line[7:])
		if v, ok := globalAPIKeys[key]; ok { fmt.Println(v) }

	case line == "listkeys":
		for k := range globalAPIKeys { vroxOrange("[key] " + k + " = ***") }

	// ---- COLOR SYSTEM ----
	case strings.HasPrefix(line, "setcolor "):
		parts := strings.SplitN(line[9:], " ", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			val = strings.ReplaceAll(val, "\\033", "\033")
			variables["__color_"+name] = val
			COLORS[name] = val
			vroxInfo("[color] Set " + name)
		}

	case strings.HasPrefix(line, "getcolor "):
		name := strings.TrimSpace(line[9:])
		if c, ok := COLORS[name]; ok { fmt.Println(c + name + COLORS["RESET"] + " = " + strconv.Quote(c)) }

	case line == "colors":
		for name, code := range COLORS { fmt.Println(code + name + COLORS["RESET"]) }

	case line == "banner":
		fmt.Println(COLORS["PURPLE"] + COLORS["BOLD"] + `
 __   __ ____   ___  __  __
 \ \ / /|  _ \ / _ \|  \/  |
  \ V / | |_) | | | | |\/| |
   | |  |  _ <| |_| | |  | |
   |_|  |_| \_\\___/|_|  |_|
` + COLORS["RESET"])
		fmt.Println(COLORS["CYAN"] + COLORS["BOLD"] + "  VroxScript " + VERSION + COLORS["RESET"])
		fmt.Println(COLORS["GREEN"] + "  github.com/InterviewCopilot350/vroxscript" + COLORS["RESET"])
		fmt.Println()

	// ---- VARIABLES ----
	case strings.HasPrefix(line, "let "):
		parts := strings.SplitN(line[4:], "=", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if strings.HasPrefix(val, "\"") { variables[name] = resolveExpression(val, variables)
			} else if val == "true" { variables[name] = true
			} else if val == "false" { variables[name] = false
			} else if val == "null" { variables[name] = nil
			} else if strings.ContainsAny(val, "+-*/%") { result := evalMath(val, variables)
				if result == float64(int(result)) { variables[name] = strconv.Itoa(int(result))
				} else { variables[name] = strconv.FormatFloat(result, 'f', 2, 64) }
			} else {
				if v, ok := variables[val]; ok { variables[name] = v
				} else { variables[name] = strings.Trim(val, "\"") }
			}
			if debug { fmt.Println(COLORS["BLUE"] + "[debug] Set " + name + " = " + fmt.Sprint(variables[name]) + COLORS["RESET"]) }
		}

	// ---- DICT ----
	case strings.HasPrefix(line, "dict "):
		parts := strings.SplitN(line[5:], "=", 2)
		variables[strings.TrimSpace(parts[0])] = map[string]string{}

	case strings.HasPrefix(line, "dictset "):
		parts := strings.Fields(line[8:])
		if len(parts) == 3 {
			if d, ok := variables[parts[0]].(map[string]string); ok {
				d[strings.Trim(parts[1], "\"")] = resolveExpression(parts[2], variables)
				variables[parts[0]] = d
			}
		}

	case strings.HasPrefix(line, "dictget "):
		parts := strings.Fields(line[8:])
		if len(parts) == 2 {
			if d, ok := variables[parts[0]].(map[string]string); ok {
				val := d[strings.Trim(parts[1], "\"")]
				variables["dictget_result"] = val
				fmt.Println(val)
			}
		}

	case strings.HasPrefix(line, "dictkeys "):
		dictName := strings.TrimSpace(line[9:])
		if d, ok := variables[dictName].(map[string]string); ok {
			keys := []string{}
			for k := range d { keys = append(keys, k) }
			variables["dictkeys_result"] = keys
			fmt.Println(keys)
		}

	// ---- OUTPUT ----
	case strings.HasPrefix(line, "out "):
		fmt.Println(resolveExpression(strings.TrimSpace(line[4:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "print "):
		fmt.Println(resolveExpression(strings.TrimSpace(line[6:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "warn "):
		fmt.Println(COLORS["YELLOW"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "error "):
		fmt.Println(COLORS["RED"] + resolveExpression(strings.TrimSpace(line[6:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "success "):
		fmt.Println(COLORS["GREEN"] + resolveExpression(strings.TrimSpace(line[8:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "info "):
		fmt.Println(COLORS["CYAN"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "bold "):
		fmt.Println(COLORS["BOLD"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "orange "):
		fmt.Println(COLORS["ORANGE"] + resolveExpression(strings.TrimSpace(line[7:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "pink "):
		fmt.Println(COLORS["PINK"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "gold "):
		fmt.Println(COLORS["GOLD"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "teal "):
		fmt.Println(COLORS["TEAL"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])

	case strings.HasPrefix(line, "lime "):
		fmt.Println(COLORS["LIME"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])

	// ---- INPUT ----
	case strings.HasPrefix(line, "input "):
		varName := strings.TrimSpace(line[6:])
		fmt.Print(COLORS["CYAN"] + varName + ": " + COLORS["RESET"])
		reader := bufio.NewReader(os.Stdin)
		val, _ := reader.ReadString('\n')
		variables[varName] = strings.TrimSpace(val)

	// ---- SYSTEM ----
	case strings.HasPrefix(line, "sleep "):
		ms, _ := strconv.Atoi(resolveValue(line[6:], variables))
		time.Sleep(time.Duration(ms) * time.Millisecond)

	case strings.HasPrefix(line, "exec "):
		cmd := resolveExpression(line[5:], variables)
		out, err := exec.Command("sh", "-c", cmd).Output()
		if err == nil { result := strings.TrimSpace(string(out)); variables["exec_result"] = result; fmt.Println(result)
		} else { fmt.Println(COLORS["RED"] + "[exec] Failed: " + err.Error() + COLORS["RESET"]) }

	case strings.HasPrefix(line, "env "):
		varName := strings.TrimSpace(line[4:])
		val := os.Getenv(varName)
		variables["env_"+varName] = val
		fmt.Println(val)

	case line == "args":
		variables["args"] = os.Args
		fmt.Println(os.Args)

	case line == "clear":
		fmt.Print("\033[2J\033[H")

	case strings.HasPrefix(line, "import "):
		importFile(strings.TrimSpace(line[7:]), variables, debug)

	// ---- HTTP SETTINGS ----
	case strings.HasPrefix(line, "setheader "):
		parts := strings.SplitN(line[10:], " ", 2)
		if len(parts) == 2 {
			globalHeaders[strings.Trim(parts[0], "\"")] = resolveExpression(parts[1], variables)
			vroxInfo("[header] Set " + parts[0])
		}

	case strings.HasPrefix(line, "setcookie "):
		parts := strings.SplitN(line[10:], " ", 2)
		if len(parts) == 2 {
			globalCookies[strings.Trim(parts[0], "\"")] = resolveExpression(parts[1], variables)
			vroxInfo("[cookie] Set " + parts[0])
		}

	case line == "clearcookies": globalCookies = map[string]string{}; vroxInfo("[cookies] Cleared")
	case line == "clearheaders": globalHeaders = map[string]string{}; vroxInfo("[headers] Cleared")

	// ---- SECURITY COMMANDS ----
	case strings.HasPrefix(line, "resolve "):
		domain := resolveValue(line[8:], variables)
		ips, err := net.LookupHost(domain)
		if err == nil {
			variables["resolved_ip"] = ips[0]
			vroxSuccess("[resolve] " + domain + " -> " + ips[0])
			if saveTo != "" { saveToFile(saveTo, ips[0]) }
		} else {
			variables["resolved_ip"] = ""
			fmt.Println(COLORS["RED"] + "[resolve] " + domain + " -> failed" + COLORS["RESET"])
		}

	// UPGRADED SCAN SUBDOMAINS (2.2)
	case strings.HasPrefix(line, "scan subdomains "):
		parts := strings.Fields(line[16:])
		domain := resolveValue(parts[0], variables)
		wordlistFile := ""
		passive := true // Default: use passive sources
		for idx, p := range parts {
			if p == "wordlist" && idx+1 < len(parts) { wordlistFile = resolveValue(parts[idx+1], variables) }
			if p == "nopassive" { passive = false }
		}
		vroxPurple("[scan] Starting reconnaissance for " + domain + "...")
		results := scanSubdomains(domain, wordlistFile, passive)
		variables["scan_results"] = results
		vroxSuccess("[scan] Total unique subdomains: " + strconv.Itoa(len(results)))
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	// UPGRADED ALIVE/PROBE (2.2)
	case strings.HasPrefix(line, "probe "):
		varName := strings.TrimSpace(line[6:])
		hosts := []string{}
		if h, ok := variables[varName].([]string); ok { hosts = h }
		results := probeHosts(hosts)
		alive := []string{}
		for _, r := range results {
			alive = append(alive, r.Host+" -> "+strconv.Itoa(r.StatusCode)+" | "+r.Title+" | "+strconv.FormatInt(r.ResponseMs, 10)+"ms")
		}
		variables["probe_results"] = alive
		variables["alive_results"] = alive
		if saveTo != "" { saveToFile(saveTo, strings.Join(alive, "\n")) }

	case strings.HasPrefix(line, "alive "):
		varName := strings.TrimSpace(line[6:])
		if hosts, ok := variables[varName].([]string); ok {
			results := checkAlive(hosts)
			variables["alive_results"] = results
			if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "ports "):
		parts := strings.Fields(line[6:])
		host := resolveValue(parts[0], variables)
		customPorts := []int{}
		if len(parts) > 1 {
			for _, p := range strings.Split(parts[1], ",") {
				port, _ := strconv.Atoi(p)
				if port > 0 { customPorts = append(customPorts, port) }
			}
		}
		vroxInfo("[ports] Scanning " + host + "...")
		results := scanPorts(host, customPorts)
		variables["port_results"] = results
		vroxSuccess("[ports] Found " + strconv.Itoa(len(results)) + " open ports")
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "headers "):
		targetURL := resolveValue(line[8:], variables)
		vroxInfo("[headers] Grabbing from " + targetURL + "...")
		results := grabHeaders(targetURL)
		variables["header_results"] = results
		if saveTo != "" {
			content := ""
			for k, v := range results { content += k + ": " + v + "\n" }
			saveToFile(saveTo, content)
		}

	case strings.HasPrefix(line, "secheaders "):
		targetURL := resolveValue(line[11:], variables)
		missing, present := checkSecHeaders(targetURL)
		variables["missing_headers"] = missing
		variables["present_headers"] = present
		if saveTo != "" { saveToFile(saveTo, "Missing: "+strings.Join(missing, ", ")) }

	case strings.HasPrefix(line, "dns "):
		domain := resolveValue(line[4:], variables)
		vroxInfo("[dns] Looking up " + domain + "...")
		results := dnsLookup(domain)
		variables["dns_results"] = results
		if saveTo != "" {
			content := ""
			for k, v := range results { content += k + ": " + v + "\n" }
			saveToFile(saveTo, content)
		}

	case strings.HasPrefix(line, "fetch get "):
		targetURL := resolveValue(line[10:], variables)
		status, body, _ := fetchPage(targetURL)
		variables["fetch_status"] = status
		variables["fetch_body"] = body
		variables["fetch_status_str"] = strconv.Itoa(status)
		if saveTo != "" { saveToFile(saveTo, strconv.Itoa(status)) }

	case strings.HasPrefix(line, "fetch post "):
		parts := strings.SplitN(line[11:], " ", 2)
		targetURL := resolveValue(parts[0], variables)
		data := url.Values{}
		if len(parts) > 1 {
			for _, p := range strings.Split(parts[1], "&") {
				kv := strings.SplitN(p, "=", 2)
				if len(kv) == 2 { data.Set(resolveValue(kv[0], variables), resolveValue(kv[1], variables)) }
			}
		}
		resp, err := httpClientFollow.PostForm(targetURL, data)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 5000)
			n, _ := resp.Body.Read(buf)
			variables["fetch_status"] = resp.StatusCode
			variables["fetch_body"] = string(buf[:n])
			vroxSuccess("[post] " + targetURL + " -> " + strconv.Itoa(resp.StatusCode))
		}

	case strings.HasPrefix(line, "crawl "):
		targetURL := resolveValue(line[6:], variables)
		vroxInfo("[crawl] Crawling " + targetURL + "...")
		results := crawlLinks(targetURL)
		variables["crawl_results"] = results
		vroxSuccess("[crawl] Found " + strconv.Itoa(len(results)) + " links")
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "js "):
		targetURL := resolveValue(line[3:], variables)
		vroxInfo("[js] Extracting from " + targetURL + "...")
		results := extractJSUrls(targetURL)
		variables["js_results"] = results
		vroxSuccess("[js] Found " + strconv.Itoa(len(results)) + " endpoints")
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "params "):
		targetURL := resolveValue(line[7:], variables)
		results := extractParams(targetURL)
		variables["param_results"] = results
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "wayback "):
		domain := resolveValue(line[8:], variables)
		vroxInfo("[wayback] Looking up " + domain + "...")
		results := waybackLookup(domain)
		variables["wayback_results"] = results
		vroxSuccess("[wayback] Found " + strconv.Itoa(len(results)) + " URLs")
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	// UPGRADED FUZZ (2.2)
	case strings.HasPrefix(line, "fuzz "):
		parts := strings.Fields(line[5:])
		targetURL := resolveValue(parts[0], variables)
		wordlistFile := ""
		filterStatus := []int{}
		filterSize := 0
		threads := 50
		for idx, p := range parts {
			if p == "wordlist" && idx+1 < len(parts) { wordlistFile = resolveValue(parts[idx+1], variables) }
			if p == "filter-status" && idx+1 < len(parts) {
				for _, s := range strings.Split(parts[idx+1], ",") {
					code, _ := strconv.Atoi(s)
					if code > 0 { filterStatus = append(filterStatus, code) }
				}
			}
			if p == "filter-size" && idx+1 < len(parts) { filterSize, _ = strconv.Atoi(parts[idx+1]) }
			if p == "threads" && idx+1 < len(parts) { threads, _ = strconv.Atoi(parts[idx+1]) }
		}
		results := fuzzAdvanced(targetURL, wordlistFile, filterStatus, filterSize, threads)
		fuzzStrings := []string{}
		for _, r := range results {
			fuzzStrings = append(fuzzStrings, r.URL+" ["+strconv.Itoa(r.StatusCode)+"] [size:"+strconv.Itoa(r.Size)+"]")
		}
		variables["fuzz_results"] = fuzzStrings
		if saveTo != "" { saveToFile(saveTo, strings.Join(fuzzStrings, "\n")) }

	// TEMPLATE ENGINE (NEW 2.2)
	case strings.HasPrefix(line, "template "):
		parts := strings.Fields(line[9:])
		if len(parts) >= 2 {
			templateFile := resolveValue(parts[0], variables)
			target := resolveValue(parts[1], variables)
			tmpl, err := loadTemplate(templateFile)
			if err != nil { vroxError("Cannot load template: "+templateFile, lineNum); return }
			matched, extracted := runTemplate(tmpl, target)
			if matched {
				vroxSuccess("[template] MATCH: " + tmpl.Name)
				variables["template_match"] = "true"
				variables["template_extracted"] = extracted
			} else {
				vroxInfo("[template] No match: " + tmpl.Name)
				variables["template_match"] = "false"
			}
		}

	case strings.HasPrefix(line, "templates "):
		parts := strings.Fields(line[10:])
		if len(parts) >= 2 {
			dir := resolveValue(parts[0], variables)
			target := resolveValue(parts[1], variables)
			results := runTemplatesDir(dir, target)
			variables["template_results"] = results
			vroxSuccess("[templates] Found " + strconv.Itoa(len(results)) + " vulnerabilities")
			if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "secrets "):
		varName := strings.TrimSpace(line[8:])
		content := fmt.Sprint(variables[varName])
		vroxInfo("[secrets] Scanning...")
		results := grepSecrets(content)
		variables["secrets_found"] = results
		if saveTo != "" { saveToFile(saveTo, fmt.Sprint(results)) }

	case strings.HasPrefix(line, "takeover "):
		domain := resolveValue(line[9:], variables)
		subdomains := []string{}
		if s, ok := variables["scan_results"].([]string); ok { subdomains = s
		} else { subdomains, _ = scanSubdomains(domain, "", true), nil }
		results := checkSubdomainTakeover(domain, subdomains)
		variables["takeover_results"] = results
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "corscheck "):
		results := checkCORS(resolveValue(line[10:], variables))
		variables["cors_results"] = results
		if saveTo != "" {
			content := ""
			for k, v := range results { content += k + ": " + v + "\n" }
			saveToFile(saveTo, content)
		}

	case strings.HasPrefix(line, "ssl "):
		results := checkSSL(resolveValue(line[4:], variables))
		variables["ssl_results"] = results
		if saveTo != "" {
			content := ""
			for k, v := range results { content += k + ": " + v + "\n" }
			saveToFile(saveTo, content)
		}

	case strings.HasPrefix(line, "techdetect "):
		results := detectTech(resolveValue(line[11:], variables))
		variables["tech_results"] = results
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "emails "):
		results := extractEmails(resolveValue(line[7:], variables))
		variables["email_results"] = results
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "whois "):
		result := whoisLookup(resolveValue(line[6:], variables))
		variables["whois_result"] = result
		if saveTo != "" { saveToFile(saveTo, result) }

	case strings.HasPrefix(line, "ratelimit "):
		results := checkRateLimit(resolveValue(line[10:], variables))
		variables["ratelimit_results"] = results

	case strings.HasPrefix(line, "openredirect "):
		results := checkOpenRedirect(resolveValue(line[13:], variables))
		variables["openredirect_results"] = results
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "sqli "):
		parts := strings.Fields(line[5:])
		if len(parts) >= 2 {
			results := checkSQLi(resolveValue(parts[0], variables), resolveValue(parts[1], variables))
			variables["sqli_results"] = results
			if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "xsscheck "):
		parts := strings.Fields(line[9:])
		if len(parts) >= 2 {
			results := checkXSS(resolveValue(parts[0], variables), resolveValue(parts[1], variables))
			variables["xss_results"] = results
			if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "ssrf "):
		parts := strings.Fields(line[5:])
		if len(parts) >= 2 {
			results := checkSSRF(resolveValue(parts[0], variables), resolveValue(parts[1], variables))
			variables["ssrf_results"] = results
			if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "lfi "):
		parts := strings.Fields(line[4:])
		if len(parts) >= 2 {
			results := checkLFI(resolveValue(parts[0], variables), resolveValue(parts[1], variables))
			variables["lfi_results"] = results
			if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "crlf "):
		results := checkCRLF(resolveValue(line[5:], variables))
		variables["crlf_results"] = results
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "ssti "):
		parts := strings.Fields(line[5:])
		if len(parts) >= 2 {
			results := checkSSTI(resolveValue(parts[0], variables), resolveValue(parts[1], variables))
			variables["ssti_results"] = results
			if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "timing "):
		parts := strings.Fields(line[7:])
		targetURL := resolveValue(parts[0], variables)
		count := 5
		if len(parts) > 1 { count, _ = strconv.Atoi(parts[1]) }
		results := measureResponseTime(targetURL, count)
		variables["timing_results"] = results

	case strings.HasPrefix(line, "redirectchain "):
		results := followRedirects(resolveValue(line[14:], variables))
		variables["redirect_chain"] = results
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "grep "):
		parts := strings.SplitN(line[5:], " ", 2)
		if len(parts) == 2 {
			content := fmt.Sprint(variables[parts[0]])
			keyword := resolveExpression(parts[1], variables)
			if strings.Contains(strings.ToLower(content), strings.ToLower(keyword)) {
				vroxSuccess("[grep] Found: " + keyword)
				variables["grep_result"] = "true"
			} else {
				fmt.Println(COLORS["RED"] + "[grep] Not found: " + keyword + COLORS["RESET"])
				variables["grep_result"] = "false"
			}
		}

	case strings.HasPrefix(line, "regex "):
		parts := strings.SplitN(line[6:], " ", 2)
		if len(parts) == 2 {
			pattern := strings.Trim(parts[0], "\"")
			content := fmt.Sprint(variables[strings.TrimSpace(parts[1])])
			results := regexSearch(pattern, content)
			variables["regex_result"] = results
			if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "report "):
		target := resolveValue(line[7:], variables)
		vroxInfo("[report] Generating for " + target + "...")
		content := generateReport(target, variables)
		fmt.Println(content)
		if saveTo != "" { saveToFile(saveTo, content); vroxSuccess("[report] Saved to " + saveTo) }

	// ---- FILE COMMANDS ----
	case strings.HasPrefix(line, "save "):
		parts := strings.SplitN(line[5:], " ", 2)
		if len(parts) == 2 { saveToFile(parts[0], resolveExpression(parts[1], variables)) }

	case strings.HasPrefix(line, "show "):
		filename := resolveValue(line[5:], variables)
		data, err := os.ReadFile(filename)
		if err == nil { fmt.Println(string(data))
		} else { fmt.Println(COLORS["RED"] + "[show] Cannot open: " + filename + COLORS["RESET"]) }

	case strings.HasPrefix(line, "read "):
		filename := resolveValue(line[5:], variables)
		data, err := os.ReadFile(filename)
		if err == nil { variables["read_result"] = string(data); fmt.Println(string(data))
		} else { vroxError("Cannot read: "+filename, lineNum) }

	case strings.HasPrefix(line, "append "):
		parts := strings.SplitN(line[7:], " ", 2)
		if len(parts) == 2 {
			f, err := os.OpenFile(parts[0], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil { f.WriteString(resolveExpression(parts[1], variables) + "\n"); f.Close(); vroxInfo("[append] Written to " + parts[0]) }
		}

	case strings.HasPrefix(line, "delete "):
		os.Remove(resolveValue(line[7:], variables))
		vroxSuccess("[delete] Removed: " + line[7:])

	case strings.HasPrefix(line, "exists "):
		filename := resolveValue(line[7:], variables)
		if _, err := os.Stat(filename); err == nil { vroxSuccess("[exists] " + filename + " -> yes"); variables["exists_result"] = "true"
		} else { fmt.Println(COLORS["RED"] + "[exists] " + filename + " -> no" + COLORS["RESET"]); variables["exists_result"] = "false" }

	case strings.HasPrefix(line, "lines "):
		filename := resolveValue(line[6:], variables)
		data, err := os.ReadFile(filename)
		if err == nil {
			linesList := strings.Split(strings.TrimSpace(string(data)), "\n")
			variables["lines_result"] = linesList
			fmt.Println(len(linesList), "lines")
		}

	case strings.HasPrefix(line, "mkdir "):
		dirName := resolveValue(line[6:], variables)
		err := os.MkdirAll(dirName, 0755)
		if err == nil { vroxSuccess("[mkdir] Created: " + dirName)
		} else { fmt.Println(COLORS["RED"] + "[mkdir] Failed: " + err.Error() + COLORS["RESET"]) }

	case strings.HasPrefix(line, "listdir "):
		dirName := resolveValue(line[8:], variables)
		entries, err := os.ReadDir(dirName)
		if err == nil {
			files := []string{}
			for _, e := range entries { files = append(files, e.Name()); fmt.Println(COLORS["CYAN"] + "[listdir] " + e.Name() + COLORS["RESET"]) }
			variables["listdir_result"] = files
		}

	case strings.HasPrefix(line, "copyfile "):
		parts := strings.Fields(line[9:])
		if len(parts) == 2 {
			data, err := os.ReadFile(resolveValue(parts[0], variables))
			if err == nil { os.WriteFile(resolveValue(parts[1], variables), data, 0644); vroxSuccess("[copyfile] Done") }
		}

	case strings.HasPrefix(line, "movefile "):
		parts := strings.Fields(line[9:])
		if len(parts) == 2 { os.Rename(resolveValue(parts[0], variables), resolveValue(parts[1], variables)); vroxSuccess("[movefile] Done") }

	case strings.HasPrefix(line, "filesize "):
		filename := resolveValue(line[9:], variables)
		info, err := os.Stat(filename)
		if err == nil { size := strconv.FormatInt(info.Size(), 10) + " bytes"; variables["filesize_result"] = size; fmt.Println(size) }

	case strings.HasPrefix(line, "compress "):
		parts := strings.Fields(line[9:])
		if len(parts) == 2 {
			src := resolveValue(parts[0], variables)
			dst := resolveValue(parts[1], variables)
			zipFile, err := os.Create(dst)
			if err == nil {
				w := zip.NewWriter(zipFile)
				filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() { return nil }
					f, _ := w.Create(path); data, _ := os.ReadFile(path); f.Write(data); return nil
				})
				w.Close(); zipFile.Close(); vroxSuccess("[compress] Created: " + dst)
			}
		}

	case strings.HasPrefix(line, "decompress "):
		parts := strings.Fields(line[11:])
		if len(parts) == 2 {
			src := resolveValue(parts[0], variables)
			dst := resolveValue(parts[1], variables)
			r, err := zip.OpenReader(src)
			if err == nil {
				os.MkdirAll(dst, 0755)
				for _, f := range r.File {
					rc, _ := f.Open(); outPath := dst + "/" + f.Name
					outFile, _ := os.Create(outPath); io.Copy(outFile, rc); outFile.Close(); rc.Close()
				}
				r.Close(); vroxSuccess("[decompress] Extracted to: " + dst)
			}
		}

	// ---- CSV ----
	case strings.HasPrefix(line, "csvread "):
		filename := resolveValue(line[8:], variables)
		f, err := os.Open(filename)
		if err == nil {
			defer f.Close()
			reader := csv.NewReader(f)
			records, _ := reader.ReadAll()
			rows := []string{}
			for _, record := range records { rows = append(rows, strings.Join(record, ",")); fmt.Println(COLORS["CYAN"] + strings.Join(record, " | ") + COLORS["RESET"]) }
			variables["csv_result"] = rows
		}

	case strings.HasPrefix(line, "csvwrite "):
		parts := strings.SplitN(line[9:], " ", 2)
		if len(parts) == 2 {
			f, err := os.Create(resolveValue(parts[0], variables))
			if err == nil {
				w := csv.NewWriter(f)
				for _, row := range strings.Split(resolveExpression(parts[1], variables), "\n") { w.Write(strings.Split(row, ",")) }
				w.Flush(); f.Close(); vroxSuccess("[csvwrite] Written")
			}
		}

	// ---- JSON ----
	case strings.HasPrefix(line, "jsonparse "):
		varName := strings.TrimSpace(line[10:])
		content := fmt.Sprint(variables[varName])
		var result interface{}
		err := json.Unmarshal([]byte(content), &result)
		if err == nil {
			variables["json_result"] = result
			formatted, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(formatted))
		} else { fmt.Println(COLORS["RED"] + "[json] Parse error: " + err.Error() + COLORS["RESET"]) }

	case strings.HasPrefix(line, "jsonget "):
		parts := strings.Fields(line[8:])
		if len(parts) == 2 {
			content := fmt.Sprint(variables[parts[0]])
			var result map[string]interface{}
			err := json.Unmarshal([]byte(content), &result)
			if err == nil {
				val := fmt.Sprint(result[strings.Trim(parts[1], "\"")])
				variables["jsonget_result"] = val
				fmt.Println(val)
			}
		}

	// ---- STRING OPERATIONS ----
	case strings.HasPrefix(line, "upper "):
		val := resolveExpression(line[6:], variables)
		variables["upper_result"] = strings.ToUpper(val); fmt.Println(strings.ToUpper(val))

	case strings.HasPrefix(line, "lower "):
		val := resolveExpression(line[6:], variables)
		variables["lower_result"] = strings.ToLower(val); fmt.Println(strings.ToLower(val))

	case strings.HasPrefix(line, "trim "):
		val := resolveExpression(line[5:], variables)
		variables["trim_result"] = strings.TrimSpace(val); fmt.Println(strings.TrimSpace(val))

	case strings.HasPrefix(line, "strlen "):
		val := resolveExpression(line[7:], variables)
		variables["strlen_result"] = strconv.Itoa(len(val)); fmt.Println(len(val))

	case strings.HasPrefix(line, "contains "):
		parts := strings.SplitN(line[9:], " ", 2)
		if len(parts) == 2 {
			result := strings.Contains(resolveExpression(parts[0], variables), resolveExpression(parts[1], variables))
			variables["contains_result"] = strconv.FormatBool(result); fmt.Println(result)
		}

	case strings.HasPrefix(line, "startswith "):
		parts := strings.SplitN(line[11:], " ", 2)
		if len(parts) == 2 {
			result := strings.HasPrefix(resolveExpression(parts[0], variables), resolveExpression(parts[1], variables))
			variables["startswith_result"] = strconv.FormatBool(result); fmt.Println(result)
		}

	case strings.HasPrefix(line, "endswith "):
		parts := strings.SplitN(line[9:], " ", 2)
		if len(parts) == 2 {
			result := strings.HasSuffix(resolveExpression(parts[0], variables), resolveExpression(parts[1], variables))
			variables["endswith_result"] = strconv.FormatBool(result); fmt.Println(result)
		}

	case strings.HasPrefix(line, "split "):
		parts := strings.SplitN(line[6:], " by ", 2)
		if len(parts) == 2 {
			val := resolveExpression(parts[0], variables)
			result := strings.Split(val, strings.Trim(parts[1], "\""))
			variables["split_result"] = result; fmt.Println(result)
		}

	case strings.HasPrefix(line, "replace "):
		parts := strings.Fields(line[8:])
		if len(parts) == 3 {
			val := resolveExpression(parts[0], variables)
			result := strings.ReplaceAll(val, strings.Trim(parts[1], "\""), strings.Trim(parts[2], "\""))
			variables["replace_result"] = result; fmt.Println(result)
		}

	case strings.HasPrefix(line, "join "):
		parts := strings.SplitN(line[5:], " with ", 2)
		if len(parts) == 2 {
			varName := strings.TrimSpace(parts[0])
			if items, ok := variables[varName].([]string); ok {
				result := strings.Join(items, strings.Trim(strings.TrimSpace(parts[1]), "\""))
				variables["join_result"] = result; fmt.Println(result)
			}
		}

	case strings.HasPrefix(line, "index "):
		parts := strings.Fields(line[6:])
		if len(parts) == 2 {
			idx, _ := strconv.Atoi(resolveValue(parts[1], variables))
			if items, ok := variables[parts[0]].([]string); ok && idx < len(items) {
				variables["index_result"] = items[idx]; fmt.Println(items[idx])
			}
		}

	case strings.HasPrefix(line, "slice "):
		parts := strings.Fields(line[6:])
		if len(parts) == 3 {
			val := resolveExpression(parts[0], variables)
			start, _ := strconv.Atoi(resolveValue(parts[1], variables))
			end, _ := strconv.Atoi(resolveValue(parts[2], variables))
			if end > len(val) { end = len(val) }
			result := val[start:end]
			variables["slice_result"] = result; fmt.Println(result)
		}

	case strings.HasPrefix(line, "find "):
		parts := strings.SplitN(line[5:], " in ", 2)
		if len(parts) == 2 {
			needle := resolveExpression(parts[0], variables)
			haystack := resolveExpression(parts[1], variables)
			idx := strings.Index(haystack, needle)
			variables["find_result"] = strconv.Itoa(idx); fmt.Println(idx)
		}

	case strings.HasPrefix(line, "pad "):
		parts := strings.Fields(line[4:])
		if len(parts) == 2 {
			val := resolveExpression(parts[0], variables)
			length, _ := strconv.Atoi(resolveValue(parts[1], variables))
			for len(val) < length { val = val + " " }
			variables["pad_result"] = val; fmt.Println(val)
		}

	// ---- ENCODING ----
	case strings.HasPrefix(line, "encode "):
		val := resolveExpression(line[7:], variables)
		result := base64.StdEncoding.EncodeToString([]byte(val))
		variables["encode_result"] = result; fmt.Println(result)

	case strings.HasPrefix(line, "decode "):
		val := resolveExpression(line[7:], variables)
		decoded, err := base64.StdEncoding.DecodeString(val)
		if err == nil { variables["decode_result"] = string(decoded); fmt.Println(string(decoded))
		} else { fmt.Println(COLORS["RED"] + "[decode] Failed" + COLORS["RESET"]) }

	case strings.HasPrefix(line, "urlencode "):
		val := resolveExpression(line[10:], variables)
		result := url.QueryEscape(val)
		variables["urlencode_result"] = result; fmt.Println(result)

	case strings.HasPrefix(line, "urldecode "):
		val := resolveExpression(line[10:], variables)
		result, _ := url.QueryUnescape(val)
		variables["urldecode_result"] = result; fmt.Println(result)

	case strings.HasPrefix(line, "md5 "):
		val := resolveExpression(line[4:], variables)
		hash := md5.Sum([]byte(val))
		result := fmt.Sprintf("%x", hash)
		variables["md5_result"] = result; fmt.Println(result)

	case strings.HasPrefix(line, "sha256 "):
		val := resolveExpression(line[7:], variables)
		hash := sha256.Sum256([]byte(val))
		result := fmt.Sprintf("%x", hash)
		variables["sha256_result"] = result; fmt.Println(result)

	case strings.HasPrefix(line, "tonum "):
		val := resolveExpression(line[6:], variables)
		num, err := strconv.ParseFloat(val, 64)
		if err == nil { variables["tonum_result"] = num; fmt.Println(num) }

	case strings.HasPrefix(line, "tostr "):
		val := resolveValue(line[6:], variables)
		variables["tostr_result"] = fmt.Sprint(val); fmt.Println(val)

	// ---- LIST OPERATIONS ----
	case strings.HasPrefix(line, "sort "):
		varName := strings.TrimSpace(line[5:])
		if items, ok := variables[varName].([]string); ok {
			sorted := make([]string, len(items)); copy(sorted, items); sort.Strings(sorted)
			variables[varName] = sorted; variables["sort_result"] = sorted; fmt.Println(sorted)
		}

	case strings.HasPrefix(line, "reverse "):
		varName := strings.TrimSpace(line[8:])
		if items, ok := variables[varName].([]string); ok {
			reversed := make([]string, len(items))
			for i, v := range items { reversed[len(items)-1-i] = v }
			variables[varName] = reversed; variables["reverse_result"] = reversed; fmt.Println(reversed)
		}

	case strings.HasPrefix(line, "unique "):
		varName := strings.TrimSpace(line[7:])
		if items, ok := variables[varName].([]string); ok {
			seen := map[string]bool{}; unique := []string{}
			for _, item := range items { if !seen[item] { seen[item] = true; unique = append(unique, item) } }
			variables[varName] = unique; variables["unique_result"] = unique; fmt.Println(unique)
		}

	case strings.HasPrefix(line, "count "):
		varName := strings.TrimSpace(line[6:])
		switch v := variables[varName].(type) {
		case []string: variables["count_result"] = strconv.Itoa(len(v)); fmt.Println(len(v))
		case string: variables["count_result"] = strconv.Itoa(len(v)); fmt.Println(len(v))
		default: variables["count_result"] = "0"; fmt.Println(0)
		}

	case strings.HasPrefix(line, "push "):
		parts := strings.SplitN(line[5:], " ", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := resolveExpression(parts[1], variables)
			if items, ok := variables[name].([]string); ok { variables[name] = append(items, val)
			} else { variables[name] = []string{val} }
		}

	case strings.HasPrefix(line, "pop "):
		name := strings.TrimSpace(line[4:])
		if items, ok := variables[name].([]string); ok && len(items) > 0 { variables[name] = items[:len(items)-1] }

	case strings.HasPrefix(line, "list "):
		parts := strings.SplitN(line[5:], "=", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := strings.Trim(strings.TrimSpace(parts[1]), "[]")
			items := strings.Split(val, ",")
			result := []string{}
			for _, item := range items { result = append(result, strings.TrimSpace(strings.Trim(item, "\""))) }
			variables[name] = result
		}

	// ---- MATH ----
	case strings.HasPrefix(line, "math "):
		result := evalMath(line[5:], variables)
		variables["math_result"] = strconv.FormatFloat(result, 'f', -1, 64); fmt.Println(result)

	case strings.HasPrefix(line, "randint "):
		parts := strings.Fields(line[8:])
		if len(parts) == 2 {
			min, _ := strconv.Atoi(resolveValue(parts[0], variables))
			max, _ := strconv.Atoi(resolveValue(parts[1], variables))
			result := rand.Intn(max-min+1) + min
			variables["randint_result"] = strconv.Itoa(result); fmt.Println(result)
		}

	case line == "random":
		result := rand.Float64()
		variables["random_result"] = fmt.Sprint(result); fmt.Println(result)

	case strings.HasPrefix(line, "timestamp"):
		now := time.Now().Format("2006-01-02 15:04:05")
		variables["timestamp_result"] = now; fmt.Println(now)

	case strings.HasPrefix(line, "type "):
		varName := strings.TrimSpace(line[5:])
		if v, ok := variables[varName]; ok {
			t := fmt.Sprintf("%T", v)
			variables["type_result"] = t; fmt.Println(t)
		}
	}
}

func showBanner() {
	fmt.Println(COLORS["PURPLE"] + COLORS["BOLD"] + `
 __   __ ____   ___  __  __
 \ \ / /|  _ \ / _ \|  \/  |
  \ V / | |_) | | | | |\/| |
   | |  |  _ <| |_| | |  | |
   |_|  |_| \_\\___/|_|  |_|
` + COLORS["RESET"])
	fmt.Println(COLORS["CYAN"] + COLORS["BOLD"] + "  VroxScript " + VERSION + " — Security Scripting Language" + COLORS["RESET"])
	fmt.Println(COLORS["GREEN"] + "  github.com/InterviewCopilot350/vroxscript" + COLORS["RESET"])
	fmt.Println(COLORS["ORANGE"] + "  Built by Prince, India" + COLORS["RESET"])
	fmt.Println()
}

func showHelp() {
	showBanner()
	fmt.Println(COLORS["YELLOW"] + "USAGE:" + COLORS["RESET"])
	fmt.Println("  vrox file.vs            Run script")
	fmt.Println("  vrox --debug file.vs    Debug mode")
	fmt.Println("  vrox --version          Version")
	fmt.Println("  vrox --help             Help")
	fmt.Println("  vrox                    Interactive")

	fmt.Println(COLORS["TEAL"] + "\nNEW IN 2.2 — PASSIVE RECON:" + COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  scan subdomains domain        "+COLORS["RESET"]+"Uses 6 passive sources + brute force")
	fmt.Println(COLORS["TEAL"]+"  scan subdomains domain nopassive "+COLORS["RESET"]+"Brute force only")
	fmt.Println(COLORS["TEAL"]+"  probe alive_results           "+COLORS["RESET"]+"httpx-like probing with title+tech")

	fmt.Println(COLORS["PURPLE"] + "\nNEW IN 2.2 — ADVANCED FUZZ:" + COLORS["RESET"])
	fmt.Println(COLORS["PURPLE"]+"  fuzz https://url              "+COLORS["RESET"]+"ffuf-like fuzzer")
	fmt.Println(COLORS["PURPLE"]+"  fuzz https://url wordlist f.txt "+COLORS["RESET"]+"Custom wordlist")
	fmt.Println(COLORS["PURPLE"]+"  fuzz https://url filter-status 200,301 "+COLORS["RESET"]+"Filter by status")
	fmt.Println(COLORS["PURPLE"]+"  fuzz https://url threads 100  "+COLORS["RESET"]+"Custom threads")

	fmt.Println(COLORS["ORANGE"] + "\nNEW IN 2.2 — TEMPLATE ENGINE:" + COLORS["RESET"])
	fmt.Println(COLORS["ORANGE"]+"  template file.vstemplate url  "+COLORS["RESET"]+"Run single template")
	fmt.Println(COLORS["ORANGE"]+"  templates ./templates/ url    "+COLORS["RESET"]+"Run all templates")
	fmt.Println(COLORS["ORANGE"]+"  setkey VIRUSTOTAL your_key    "+COLORS["RESET"]+"Set API key")
	fmt.Println(COLORS["ORANGE"]+"  getkey VIRUSTOTAL             "+COLORS["RESET"]+"Get API key")
	fmt.Println(COLORS["ORANGE"]+"  listkeys                      "+COLORS["RESET"]+"List all keys")

	fmt.Println(COLORS["PINK"] + "\nNEW COLORS:" + COLORS["RESET"])
	fmt.Println(COLORS["ORANGE"]+"  orange "+COLORS["RESET"]+"  "+COLORS["PINK"]+"pink "+COLORS["RESET"]+"  "+COLORS["GOLD"]+"gold "+COLORS["RESET"]+"  "+COLORS["TEAL"]+"teal "+COLORS["RESET"]+"  "+COLORS["LIME"]+"lime"+COLORS["RESET"])

	fmt.Println(COLORS["GREEN"] + "\nPASSIVE SOURCES (no API key needed):" + COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  crt.sh, HackerTarget, RapidDNS, URLScan, AlienVault"+COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  + VirusTotal (needs API key: setkey VIRUSTOTAL key)"+COLORS["RESET"])

	fmt.Println(COLORS["CYAN"] + "\nTEMPLATE FORMAT (.vstemplate):" + COLORS["RESET"])
	fmt.Println(`  name: Template Name
  severity: critical/high/medium/low/info
  method: GET
  path: /admin
  match: Admin Panel
  match: status:200
  match: regex:password[=:]
  extract: [a-zA-Z0-9]+@[a-z]+\.com
  header: Authorization: Bearer token`)
}

func showVersion() {
	showBanner()
}

func interactive() {
	showBanner()
	fmt.Println(COLORS["CYAN"] + "Interactive Mode — Type 'exit' to quit\n" + COLORS["RESET"])
	variables := map[string]interface{}{}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(COLORS["GREEN"] + "vrox> " + COLORS["RESET"])
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "exit" { fmt.Println(COLORS["CYAN"] + "Bye!" + COLORS["RESET"]); break }
		if line != "" { interpretLine(line, 1, variables, false, "") }
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	if len(os.Args) < 2 { interactive(); return }
	switch os.Args[1] {
	case "--help": showHelp()
	case "--version": showVersion()
	case "--debug":
		if len(os.Args) < 3 { fmt.Println(COLORS["RED"] + "Error: No file" + COLORS["RESET"]); return }
		data, err := os.ReadFile(os.Args[2])
		if err != nil { fmt.Println(COLORS["RED"] + "Error: Cannot open file" + COLORS["RESET"]); return }
		runCode(string(data), map[string]interface{}{}, true)
	default:
		data, err := os.ReadFile(os.Args[1])
		if err != nil { fmt.Println(COLORS["RED"] + "Error: " + os.Args[1] + COLORS["RESET"]); return }
		runCode(string(data), map[string]interface{}{}, false)
	}
}
