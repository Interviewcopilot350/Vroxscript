VroxScript 🔐
Security Scripting Language — Full recon in 6 lines
Built by Prince, India
What is VroxScript?
VroxScript (.vs) is an open source security scripting language built specifically for bug hunters, penetration testers and security researchers.
What takes 200 lines in Python takes 6 lines in VroxScript.
⚡ Quick Example
# Full recon in 6 lines
scan subdomains target.com >> subs.txt
alive scan_results >> alive.txt
ports target.com >> ports.txt
fuzz https://target.com >> fuzz.txt
secrets fetch_body >> secrets.txt
report target.com >> report.txt
🚀 Installation
Termux (Android):
pkg install golang git
git clone https://github.com/InterviewCopilot350/vroxscript
cd vroxscript
go build -o vrox main.go
cp vrox $PREFIX/bin/vrox
chmod +x $PREFIX/bin/vrox
Linux / Kali / Ubuntu:
git clone https://github.com/InterviewCopilot350/vroxscript
cd vroxscript
go build -o vrox main.go
sudo cp vrox /usr/local/bin/vrox
One command install:
curl -sL https://raw.githubusercontent.com/InterviewCopilot350/vroxscript/main/install.sh | bash
📖 Security Commands
Recon
Command
Description
scan subdomains domain
Find subdomains
scan subdomains domain wordlist file.txt
Custom wordlist
alive scan_results
Check live hosts
ports domain
Scan open ports
ports domain 80,443,8080
Custom ports
headers https://url
Grab HTTP headers
secheaders https://url
Check security headers
dns domain
DNS lookup (A, MX, TXT, CNAME, NS)
crawl https://url
Find all links
js https://url
Extract JS endpoints
params url
Extract URL parameters
wayback domain
Wayback Machine URLs
fuzz https://url
Directory fuzzing
fuzz https://url wordlist file.txt
Custom wordlist
resolve domain
Resolve IP address
whois domain
WHOIS lookup
emails https://url
Extract emails
techdetect https://url
Detect technologies
ssl https://url
SSL certificate check
timing https://url 5
Response time measurement
redirectchain https://url
Follow redirect chain
Vulnerability Testing
Command
Description
corscheck https://url
CORS misconfiguration
sqli https://url param
SQL injection detection
xsscheck https://url param
XSS detection
ssrf https://url param
SSRF testing
lfi https://url param
Local file inclusion
crlf https://url
CRLF injection
ssti https://url param
Server side template injection
openredirect https://url
Open redirect testing
takeover domain
Subdomain takeover check
ratelimit https://url
Rate limit check
secrets variable
Scan for API keys and secrets
grep variable keyword
Search in results
HTTP
Command
Description
fetch get https://url
HTTP GET request
fetch post url data
HTTP POST request
setheader key value
Set global header
setcookie key value
Set cookie
clearcookies
Clear all cookies
clearheaders
Clear all headers
Report
Command
Description
report target
Generate full report
command >> file.txt
Save output to file
📖 Language
Variables & Types
let name = "VroxScript"
let version = 2.1
let flag = true
let nothing = null
String Interpolation
print "{GREEN}Hello {name}!{RESET}"
Control Flow
if score > 80 and passed == true {
    success "Passed!"
} else {
    error "Failed"
}

while x < 10 {
    let x = x + 1
    if x == 5 { break }
}

for target in targets {
    resolve target
}

repeat 3 {
    info "repeating..."
}
Functions
func scanTarget {
    resolve arg1
    ports arg1
    report arg1
}
call scanTarget "github.com"
Error Handling
try {
    fetch get https://target.com
} catch {
    error "Request failed"
}
🎨 Color System
# Use built in colors
print "{RED}Error!{RESET}"
print "{GREEN}Success!{RESET}"
print "{CYAN}Info{RESET}"
print "{YELLOW}Warning{RESET}"
print "{PURPLE}Cool{RESET}"
print "{BOLD}Bold{RESET}"

# Define custom colors
setcolor MYCOLOR "\033[91m"
print "{MYCOLOR}Custom!{RESET}"

# Show all colors
colors
🔧 Encoding & Hashing
encode "hello"          # Base64 encode
decode encode_result    # Base64 decode
urlencode "hello world" # URL encode
urldecode encoded       # URL decode
md5 "password"          # MD5 hash
sha256 "password"       # SHA256 hash
📊 Data Operations
# Dictionary
dict mydict =
dictset mydict "key" "value"
dictget mydict "key"

# JSON
jsonparse jsonvariable
jsonget jsonvariable "key"

# CSV
csvread data.csv
csvwrite output.csv "name,age\nPrince,14"

# Lists
list targets = ["a.com", "b.com"]
sort targets
reverse targets
unique targets
📁 File Operations
save file.txt "content"
read file.txt
append file.txt "more content"
show file.txt
delete file.txt
exists file.txt
lines file.txt
mkdir newfolder
listdir folder
copyfile src dst
movefile src dst
filesize file.txt
compress folder output.zip
decompress file.zip folder
🛠️ Usage
vrox file.vs            # Run a script
vrox --debug file.vs    # Debug mode
vrox --version          # Show version
vrox --help             # Show help
vrox                    # Interactive mode
📝 Real World Example
# Bug Bounty Recon Script
banner
input target
timestamp

print "{CYAN}Phase 1: Recon{RESET}"
scan subdomains target >> subs.txt
alive scan_results >> alive.txt
dns target >> dns.txt
wayback target >> wayback.txt

print "{CYAN}Phase 2: Fingerprint{RESET}"
techdetect https://target >> tech.txt
ssl https://target >> ssl.txt
secheaders https://target >> secheaders.txt
emails https://target >> emails.txt

print "{CYAN}Phase 3: Vulnerabilities{RESET}"
corscheck https://target >> cors.txt
openredirect https://target >> redirect.txt
takeover target >> takeover.txt
fuzz https://target >> fuzz.txt

print "{CYAN}Phase 4: Secrets{RESET}"
fetch get https://target
secrets fetch_body >> secrets.txt
js https://target >> js.txt

print "{CYAN}Phase 5: Report{RESET}"
report target >> final_report.txt
show final_report.txt
🌟 Why VroxScript?
Simple — English-like syntax anyone learns in minutes
Powerful — Built-in security tools, no external dependencies
Fast — Written in Go with concurrent scanning
Portable — Single binary, runs anywhere including Android Termux
Open Source — Free forever, community driven
🤝 Contributing
VroxScript grows with its community:
Open issues for bugs
Suggest new commands
Submit pull requests
Share your .vs scripts
⚠️ Legal
VroxScript is built for legitimate security research and bug bounty hunting only. Always get written permission before testing any target. The author is not responsible for misuse.
📜 License
MIT License — Free to use, modify and distribute.
📊 Changelog
VroxScript 2.1
Added SSRF, LFI, CRLF, SSTI testing
Added response timing measurement
Added redirect chain following
Added custom wordlists for scan and fuzz
Added custom port specification
Added Dictionary type
Added JSON parsing
Added CSV read/write
Added Base64 encode/decode
Added URL encode/decode
Added MD5/SHA256 hashing
Added sort/reverse/unique list operations
Added file operations (mkdir, listdir, copyfile, movefile, filesize, compress, decompress)
Added break/continue in loops
Added true/false/null types
Added and/or/not conditions
Added global HTTP headers and cookies
Added color palette command
Improved syntax highlighting
VroxScript 2.0
Added XSS, SQLi, CORS, open redirect, subdomain takeover testing
Added technology detection
Added SSL certificate checker
Added rate limit checker
Added WHOIS lookup
Added email extraction
Added string interpolation
Added optional banner
Added custom color system
VroxScript 1.0
Initial release
Core language features
Basic security recon commands
Built with ❤️ by Prince, India
"They said get 85%. I built a programming language instead."
