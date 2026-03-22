# VroxScript 🔐
> The Security Scripting Language

Built by **Prince, India**

VroxScript is a scripting language designed specifically for bug hunters and security researchers. What takes 50 lines in Python takes 5 lines in VroxScript.

---

## ⚡ Quick Example

```vs
# Full recon in 5 lines
scan subdomains target.com >> subs.txt
alive scan_results >> alive.txt
fuzz https://target.com >> fuzz.txt
secrets fetch_body
report target.com >> report.txt
🚀 Installation
git clone https://github.com/princeaswal00/vroxscript
cd vroxscript
go build -o vrox main.go
cp vrox /usr/local/bin/vrox
Termux (Android):
pkg install golang git
git clone https://github.com/princeaswal00/vroxscript
cd vroxscript
go build -o vrox main.go
cp vrox $PREFIX/bin/vrox
📖 Commands
Security
Command
Description
scan subdomains domain
Find subdomains
alive scan_results
Check live hosts
ports domain
Scan open ports
headers https://url
Grab HTTP headers
secheaders https://url
Check security headers
dns domain
DNS lookup (A, MX, TXT, CNAME)
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
secrets variable
Scan for API keys and secrets
regex pattern variable
Regex search
grep variable keyword
Search in results
fetch get https://url
HTTP GET request
fetch post url data
HTTP POST request
resolve domain
Resolve IP address
report target
Generate full report
Language
Command
Description
let x = 5
Variable
out x
Print output
print/warn/error x
Colored output
if condition { }
Condition
while condition { }
While loop
repeat 5 { }
Repeat loop
for item in list { }
For loop
func name { }
Function
call name arg1 arg2
Call function with args
try { } catch { }
Error handling
import file.vs
Import .vs file
command >> file.txt
Save output to file
math 10 + 5
Math operations
randint 1 100
Random integer
timestamp
Current time
🛠️ Usage
vrox file.vs            # Run a script
vrox --debug file.vs    # Debug mode
vrox --help             # Show help
vrox --version          # Show version
vrox                    # Interactive mode
📝 Full Recon Example
# Full Bug Bounty Recon Script
input target

print "Starting recon..."

resolve target >> resolve.txt
dns target >> dns.txt
scan subdomains target >> subs.txt
alive scan_results >> alive.txt
ports target >> ports.txt
headers https://target >> headers.txt
secheaders https://target >> secheaders.txt
crawl https://target >> links.txt
js https://target >> js.txt
fuzz https://target >> fuzz.txt
wayback target >> wayback.txt
fetch get https://target
secrets fetch_body >> secrets.txt
report target >> report.txt

print "Done! Check report.txt"
🌟 Why VroxScript?
Simple — English-like syntax anyone can learn in minutes
Powerful — Built-in security tools, no external dependencies
Fast — Written in Go, concurrent scanning
Portable — Single binary, runs anywhere including Android Termux
Open Source — Free forever
🤝 Contributing
VroxScript grows with its community. Feel free to:
Open issues for bugs
Suggest new commands
Submit pull requests
Share your .vs scripts
⚠️ Legal
VroxScript is built for legitimate security research and bug bounty hunting only. Always get written permission before testing any target. The author is not responsible for misuse.
📜 License
MIT License — Free to use, modify and distribute.
Built with ❤️ by Prince, India
