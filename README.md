# VroxScript 🔐
> Security Scripting Language — Full recon in 6 lines

**Built by Prince, India**

[![GitHub stars](https://img.shields.io/github/stars/InterviewCopilot350/vroxscript?style=social)](https://github.com/InterviewCopilot350/vroxscript)
[![Version](https://img.shields.io/badge/version-2.3-green)](https://github.com/InterviewCopilot350/vroxscript)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Language](https://img.shields.io/badge/built%20with-Go-cyan)](https://golang.org)

---

## What is VroxScript?

VroxScript (.vs) is a security scripting language built for bug hunters and penetration testers. What takes 200 lines in Python takes 6 lines in VroxScript. No imports. No setup. Just write and run.

Built entirely on an Android phone using Termux with no laptop.

---

## Quick Example

```vs
# Full recon in 6 lines
scan subdomains target.com >> subs.txt
alive scan_results >> alive.txt
ports target.com >> ports.txt
fuzz https://target.com >> fuzz.txt
secrets fetch_body >> secrets.txt
report target.com >> report.txt
```

---

## Installation

**Android (Termux):**
```bash
pkg install golang git
git clone https://github.com/InterviewCopilot350/vroxscript
cd vroxscript
go build -o vrox main.go
cp vrox $PREFIX/bin/vrox
chmod +x $PREFIX/bin/vrox
```

**Linux / Kali / Ubuntu:**
```bash
git clone https://github.com/InterviewCopilot350/vroxscript
cd vroxscript
go build -o vrox main.go
sudo cp vrox /usr/local/bin/vrox
```

**One command:**
```bash
curl -sL https://raw.githubusercontent.com/InterviewCopilot350/vroxscript/main/install.sh | bash
```

**Syntax highlighting (micro editor):**
```bash
mkdir -p ~/.config/micro/syntax
cp vrox.yaml ~/.config/micro/syntax/vrox.yaml
```

---

## Usage

```bash
vrox file.vs            # Run a script
vrox --debug file.vs    # Debug mode (shows each line)
vrox --version          # Show version
vrox --help             # Show help
vrox                    # Interactive mode
```

---

## Security Commands

### Subdomain Scanning
```vs
# Basic scan (uses 8 passive sources + brute force)
scan subdomains target.com

# Save results to file
scan subdomains target.com >> subs.txt

# Brute force only (skip passive sources)
scan subdomains target.com nopassive

# Custom wordlist
scan subdomains target.com wordlist mylist.txt
```

**Passive sources used automatically (no API key needed):**
- crt.sh, HackerTarget, RapidDNS, URLScan.io, AlienVault OTX, CertSpotter, ThreatBook
- VirusTotal (optional — set your key with `setkey VIRUSTOTAL your_key`)

### Host Probing
```vs
# Check which hosts are alive (httpx-like)
alive scan_results

# Probe with full details — status, title, tech, response time
probe scan_results >> probed.txt
```

### Port Scanning
```vs
# Default ports
ports target.com

# Custom ports
ports target.com 80,443,8080,8443

# Save results
ports target.com >> ports.txt
```

### Directory Fuzzing
```vs
# Basic fuzz (ffuf-like)
fuzz https://target.com

# Custom wordlist
fuzz https://target.com wordlist mylist.txt

# Filter by status codes
fuzz https://target.com filter-status 200,301,403

# Filter by response size
fuzz https://target.com filter-size 1234

# Custom threads
fuzz https://target.com threads 100

# POST fuzzing
fuzz https://target.com method POST data "user=admin"

# Combined
fuzz https://target.com wordlist list.txt filter-status 200 threads 50 >> fuzz.txt
```

### HTTP Requests
```vs
# GET request
fetch get https://target.com

# POST request
fetch post https://target.com user=admin&pass=test

# After fetch, use these variables:
out fetch_status      # Status code (200, 403, etc)
out fetch_body        # Response body
```

### Headers
```vs
# Grab all headers
headers https://target.com

# Check for missing security headers
secheaders https://target.com

# Missing headers saved to variable: missing_headers
```

### DNS Lookup
```vs
# Full DNS lookup (A, MX, TXT, CNAME, NS)
dns target.com >> dns.txt
```

### SSL Certificate
```vs
# Check SSL cert — expiry, issuer, days left
ssl https://target.com >> ssl.txt
```

### Technology Detection
```vs
# Detect WordPress, React, Angular, PHP, Nginx etc
techdetect https://target.com >> tech.txt
```

### CDN Detection
```vs
# Detect Cloudflare, Akamai, Fastly, AWS, Azure etc
cdn target.com
out cdn_result
```

### Favicon Hash
```vs
# Get favicon hash (use on Shodan: http.favicon.hash:value)
favicon https://target.com
out favicon_hash
```

### Service Banners
```vs
# Grab service banner from specific port
banner_grab target.com 22
out banner_result
```

### Wayback Machine
```vs
# Get all archived URLs
wayback target.com >> wayback.txt
```

### Crawling
```vs
# Find all links on a page
crawl https://target.com >> links.txt
```

### JS Endpoint Extraction
```vs
# Extract URLs and endpoints from JS files
js https://target.com >> js.txt
```

### Parameter Mining
```vs
# Automatically discover parameters from a page
mineParams https://target.com >> params.txt
```

### Secret Detection
```vs
# Scan any variable for API keys, tokens, passwords
fetch get https://target.com
secrets fetch_body >> secrets.txt

# Detects: API Keys, Secrets, Tokens, Passwords, AWS Keys,
# Private Keys, JWTs, GitHub Tokens, Google API Keys etc
```

### Grep and Regex
```vs
# Search for keyword in any variable
grep fetch_body "admin"
out grep_result       # true or false

# Search with regex pattern
regex "[a-z]+@[a-z]+\.[a-z]+" fetch_body
out regex_result
```

### Vulnerability Testing
```vs
# SQL Injection (error-based, time-based, union-based)
sqli https://target.com?id=1 id >> sqli.txt

# XSS (reflected, parameter mining, blind XSS)
xsscheck https://target.com?q=test q >> xss.txt

# SSRF
ssrf https://target.com url >> ssrf.txt

# Local File Inclusion
lfi https://target.com?page=home page >> lfi.txt

# CRLF Injection
crlf https://target.com >> crlf.txt

# Server Side Template Injection
ssti https://target.com?name=test name >> ssti.txt

# CORS Misconfiguration
corscheck https://target.com >> cors.txt

# Open Redirect
openredirect https://target.com >> redirect.txt

# Subdomain Takeover
takeover target.com >> takeover.txt

# Rate Limit Check
ratelimit https://target.com
```

### Network Tools
```vs
# Ping a host
ping target.com
out ping_result       # true or false

# Expand CIDR range
cidr 192.168.1.0/24
out cidr_result       # list of all IPs

# Resolve domain to IP
resolve target.com
out resolved_ip
```

### Report Generation
```vs
# Generate full security report
report target.com >> final_report.txt
show final_report.txt
```

### Template Engine
```vs
# Run a single template
template my_template.vstemplate https://target.com
out template_match       # true or false
out template_extracted   # extracted data

# Run all templates in a directory
templates ./templates/ https://target.com >> results.txt
```

**Template format (.vstemplate):**
```
name: Admin Panel Check
severity: high
method: GET
path: /admin
match: status:200
match: Admin
extract: [a-zA-Z0-9]+@[a-z]+\.com
```

---

## HTTP Settings

```vs
# Set headers for all requests
setheader "Authorization" "Bearer token123"
setheader "User-Agent" "MyScanner/1.0"

# Set cookies
setcookie "session" "abc123"

# Clear all headers/cookies
clearheaders
clearcookies

# Set API keys for passive sources
setkey VIRUSTOTAL "your_key_here"
setkey SHODAN "your_key_here"

# View set keys
listkeys
```

---

## Language

### Variables
```vs
let name = "VroxScript"     # String
let count = 42               # Number
let flag = true              # Boolean
let empty = null             # Null

# String interpolation
print "Hello {name}! Count: {count}"
```

### Multiline Strings
```vs
let message = """
This is line 1
This is line 2
This is line 3
"""
```

### Output Commands
```vs
out variable          # Plain output
print "message"       # Colored output
success "done!"       # Green
warn "careful"        # Yellow
error "failed"        # Red
info "note"           # Cyan
bold "important"      # Bold
orange "text"         # Orange
pink "text"           # Pink
gold "text"           # Gold
teal "text"           # Teal
lime "text"           # Lime
violet "text"         # Violet
coral "text"          # Coral
silver "text"         # Silver
divider               # Print a line separator
newline               # Print empty line
```

### Color System
```vs
# Use built in colors in any string
print "{RED}Error!{RESET}"
print "{GREEN}Success!{RESET}"
print "{CYAN}Info{RESET}"
print "{YELLOW}Warning{RESET}"
print "{BOLD}Bold text{RESET}"
print "{UNDERLINE}Underlined{RESET}"

# Define your own colors
setcolor MYCOLOR "\033[91m"
print "{MYCOLOR}Custom color!{RESET}"

# Show all available colors
colors
```

### User Input
```vs
input target
print "You entered: {target}"

# Yes/No prompt
ask "Continue with scan?"
out ask_result        # y or n
out ask_yes           # true or false
```

### Conditions
```vs
if score > 80 {
    success "High score!"
} else {
    warn "Low score"
}

# Unless (opposite of if)
unless error == "none" {
    error "Something went wrong"
}

# Switch/case
switch status {
    case "200" {
        success "OK"
    }
    case "403" {
        warn "Forbidden"
    }
    default {
        info "Other status"
    }
}

# Combine conditions
if score > 80 and passed == true {
    success "Passed!"
}

if error == "timeout" or error == "refused" {
    warn "Connection issue"
}

if not flag == true {
    info "Flag is false"
}
```

### Loops
```vs
# While loop
let x = 0
while x < 5 {
    let x = x + 1
    out x
}

# For loop over list
list targets = ["github.com", "google.com"]
for target in targets {
    resolve target
    out resolved_ip
}

# Repeat loop
repeat 3 {
    info "Hello"
}

# Loop with index
loop 5 as i {
    print "Step {i}"
}

# Break and continue
while x < 100 {
    let x = x + 1
    if x == 50 { break }
    if x == 25 { continue }
    out x
}
```

### Functions
```vs
# Define a function
func scanAndReport {
    info "Scanning {arg1}..."
    resolve arg1
    ports arg1
    report arg1
}

# Call with arguments
call scanAndReport "github.com"

# arg1, arg2, arg3... are the arguments
func greet {
    print "Hello {arg1} from {arg2}!"
}
call greet "Prince" "India"
```

### Error Handling
```vs
try {
    fetch get https://target.com
    success "Request worked"
} catch {
    error "Request failed"
}

# Assert a condition (stops script if false)
assert score > 0 "Score must be positive"

# Raise an error manually
raise "Something went wrong"
```

### Import
```vs
# Run another .vs file
import scanner.vs
import reporter.vs
```

---

## Lists

```vs
# Create a list
list targets = ["github.com", "google.com", "amazon.com"]

# Add item
push targets "microsoft.com"

# Remove last item
pop targets

# Remove specific item
remove targets "google.com"

# Get item by index (0-based)
index targets 0
out index_result

# Count items
count targets
out count_result

# Filter list by keyword
filter targets "git"
out filter_result

# Sort alphabetically
sort targets

# Reverse order
reverse targets

# Remove duplicates
unique targets

# Join list into string
join targets with ", "
out join_result

# Check if item exists in list
contains_all targets "github.com"
out contains_all_result
```

---

## Dictionary

```vs
# Create a dictionary
dict mydict =

# Set values
dictset mydict "name" "VroxScript"
dictset mydict "version" "2.3"

# Get a value
dictget mydict "name"
out dictget_result

# List all keys
dictkeys mydict
out dictkeys_result
```

---

## String Operations

```vs
let str = "Hello World"

upper str               # HELLO WORLD
lower str               # hello world
trim "  hello  "        # hello
strlen str              # 11
contains str "World"    # true
startswith str "Hello"  # true
endswith str "World"    # true
replace str "World" "VroxScript"
slice str 0 5           # Hello
find "World" in str     # 6
pad str 20              # Hello World         (padded)
reverse_str str         # dlroW olleH
repeat_str "ha" 3       # hahaha
count_str "l" in str    # 3
between str "H" "d"     # ello Worl
```

---

## Type Checking

```vs
let x = 42
let name = "Prince"
let items = ["a", "b"]

isnum x          # true
isstr name       # true
islist items     # true
isnull nothing   # true/false
isbool flag      # true/false
isdict mydict    # true/false
isnumber "42"    # true
isalpha "abc"    # true (only letters)
isempty "  "     # true
isip "1.2.3.4"  # true
isdomain "github.com"  # true
type x           # string/int/bool etc
```

---

## Math

```vs
math 100 + 50       # 150
math 10 * 5         # 50
math 200 / 4        # 50
math 17 % 5         # 2

abs -5              # 5
floor 3.9           # 3
ceil 3.1            # 4
round 3.567 2       # 3.57
sqrt 16             # 4
power 2 10          # 1024
max 1 5 3           # 5
min 1 5 3           # 1
randint 1 100       # random number
random              # random 0.0-1.0

# Sum and average of a list
list nums = ["10", "20", "30"]
sum nums            # 60
avg nums            # 20
```

---

## Encoding and Hashing

```vs
encode "hello"          # Base64 encode -> aGVsbG8=
decode encode_result    # Base64 decode -> hello

urlencode "hello world" # hello+world
urldecode "hello+world" # hello world

md5 "password"          # MD5 hash
sha256 "password"       # SHA256 hash
```

---

## File Operations

```vs
save file.txt "Hello VroxScript"   # Write to file
read file.txt                       # Read file
append file.txt "More content"      # Add to file
show file.txt                       # Print file contents
delete file.txt                     # Delete file
exists file.txt                     # Check if exists
lines file.txt                      # Read as list of lines

mkdir newfolder                     # Create directory
listdir .                           # List directory contents
copyfile src.txt dst.txt            # Copy file
movefile old.txt new.txt            # Move/rename file
filesize file.txt                   # Get file size
filetype file.txt                   # Get extension (.txt)
filename "/path/to/file.txt"        # Get filename (file.txt)
dirname "/path/to/file.txt"         # Get directory (/path/to)
currentdir                          # Current working directory
homedir                             # Home directory

compress myfolder output.zip        # Create ZIP
decompress archive.zip output/      # Extract ZIP

csvread data.csv                    # Read CSV file
csvwrite output.csv "a,b\n1,2"     # Write CSV file
```

---

## JSON

```vs
let data = "{\"name\":\"VroxScript\",\"version\":\"2.3\"}"

# Parse JSON
jsonparse data

# Get a value by key
jsonget data "name"
out jsonget_result    # VroxScript
```

---

## UI Features

```vs
# Show a table
list headers = ["Host", "Status", "Title"]
list rows = ["github.com|200|GitHub", "google.com|200|Google"]
table headers rows

# Show progress bar
progress 50 100 "Scanning..."
progress 100 100 "Done!"

# Show loading spinner
spinner "Loading..." 2000

# Ask yes/no question
ask "Continue?"
if ask_yes == true {
    success "Continuing"
}
```

---

## Time

```vs
now           # 2026-03-23 10:30:45
date          # 2026-03-23
time          # 10:30:45
timestamp     # Same as now
elapsed       # Seconds since script started
sleep 1000    # Sleep 1 second (1000ms)
```

---

## System

```vs
# Run a system command
exec "ls -la"
out exec_result

# Read environment variable
env HOME
out env_HOME

# Get command line arguments
args
out args

# Clear terminal
clear
```

---

## Complete Recon Script

```vs
# Bug Bounty Full Recon
banner
input target
timestamp

print "{CYAN}Phase 1: Recon{RESET}"
resolve target >> resolve.txt
dns target >> dns.txt
scan subdomains target >> subs.txt
probe scan_results >> probed.txt
ports target >> ports.txt
cdn target
favicon https://target

print "{CYAN}Phase 2: Fingerprint{RESET}"
techdetect https://target >> tech.txt
ssl https://target >> ssl.txt
secheaders https://target >> secheaders.txt
emails https://target >> emails.txt

print "{CYAN}Phase 3: Vulnerabilities{RESET}"
corscheck https://target >> cors.txt
openredirect https://target >> redirect.txt
takeover target >> takeover.txt
ratelimit https://target
fuzz https://target filter-status 200,301,403 >> fuzz.txt

print "{CYAN}Phase 4: Deep Analysis{RESET}"
fetch get https://target
secrets fetch_body >> secrets.txt
mineParams https://target >> params.txt
js https://target >> js.txt
wayback target >> wayback.txt

print "{CYAN}Phase 5: Report{RESET}"
report target >> final_report.txt
show final_report.txt

elapsed
print "Scan completed in {elapsed} seconds"
```

---

## Changelog

### VroxScript 2.3
- 8 passive subdomain sources
- DNS permutation generation
- Favicon hash detection
- CDN detection
- Service banner grabbing
- Ping and CIDR expansion
- POST fuzzing
- Advanced SQLi (error, time-based, union-based)
- Advanced XSS (reflected, parameter mining, blind)
- Parameter mining
- switch/case/default
- unless statement
- loop with index
- assert and raise
- Table output
- Progress bar
- Spinner
- Math functions (abs, floor, ceil, round, sqrt, power, max, min, sum, avg)
- New string functions (reverse_str, repeat_str, count_str, between)
- Type checking functions
- List filter, remove, contains_all
- File path functions
- New colors (violet, coral, silver, maroon, navy)
- Rich syntax highlighting with 15 color categories

### VroxScript 2.2
- 6 passive subdomain sources
- httpx-like probing
- ffuf-like fuzzing with filters
- Template engine
- API key management

### VroxScript 2.1
- SSRF, LFI, CRLF, SSTI testing
- Response timing
- Redirect chain following
- Dictionary type
- JSON parsing
- CSV read/write
- Base64, URL encoding
- MD5/SHA256 hashing
- Sort, reverse, unique
- File operations
- Break/continue
- Global HTTP headers and cookies

### VroxScript 2.0
- XSS, SQLi, CORS, open redirect, subdomain takeover
- Technology detection
- SSL certificate checker
- Rate limit checker
- WHOIS lookup
- Email extraction
- String interpolation
- Custom color system

### VroxScript 1.0
- Initial release
- Core language
- Basic security recon

---

## Why VroxScript?

- **Simple** — English-like syntax, learn in minutes
- **Powerful** — Security tools built into the language
- **Fast** — Written in Go with concurrent scanning
- **Portable** — Single binary, runs anywhere including Android
- **No dependencies** — No pip install, no npm, just run
- **Open Source** — Free forever

---

## Legal

For legitimate security research and bug bounty hunting only. Always get written permission before testing. The author is not responsible for misuse.

---

## License

MIT — Free to use, modify and distribute.

---

## Contributing

Star the repo, suggest commands, submit pull requests, share your .vs scripts.

---

*Built with ❤️ by Prince, India*

*"They said get 85%. I built a programming language instead."*
