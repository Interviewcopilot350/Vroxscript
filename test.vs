# VroxScript 2.2 Complete Test
# Tests all new 2.2 features

banner

# ============================================================
# NEW COLORS (2.2)
# ============================================================
print "{CYAN}=== New Colors ==={RESET}"
orange "This is orange output"
pink "This is pink output"
gold "This is gold output"
teal "This is teal output"
lime "This is lime output"

# ============================================================
# API KEYS (2.2)
# ============================================================
print "{CYAN}=== API Keys ==={RESET}"
setkey TESTKEY "my-secret-key-123"
getkey TESTKEY
listkeys

# ============================================================
# PASSIVE SUBDOMAIN SCAN (2.2)
# ============================================================
print "{TEAL}=== Passive Recon (2.2) ==={RESET}"
teal "Scanning with passive sources..."
# Full scan with passive + brute force
scan subdomains github.com >> subs.txt
count scan_results
out count_result
show subs.txt

# Brute force only (no passive)
teal "Brute force only scan..."
scan subdomains github.com nopassive >> subs_bf.txt

# ============================================================
# PROBE — httpx-like (2.2)
# ============================================================
print "{CYAN}=== Probe (2.2) ==={RESET}"
list toprobe = ["github.com", "google.com"]
probe toprobe >> probe.txt
show probe.txt

# ============================================================
# ADVANCED FUZZ — ffuf-like (2.2)
# ============================================================
print "{PURPLE}=== Advanced Fuzz (2.2) ==={RESET}"

# Basic fuzz
fuzz https://github.com >> fuzz_basic.txt

# With filter status
fuzz https://github.com filter-status 200,301 >> fuzz_filtered.txt

# With threads
fuzz https://github.com threads 30 >> fuzz_threaded.txt

show fuzz_basic.txt

# ============================================================
# TEMPLATE ENGINE (2.2)
# ============================================================
print "{ORANGE}=== Template Engine (2.2) ==={RESET}"

# Run single template
template example.vstemplate https://github.com
out template_match
out template_extracted

# Run all templates from directory
# templates ./templates/ https://github.com

# ============================================================
# ALL EXISTING FEATURES (unchanged)
# ============================================================
print "{CYAN}=== Variables ==={RESET}"
let name = "VroxScript"
let version = "2.2"
let flag = true
let nothing = null
print "Running {name} {version}"

print "{CYAN}=== Math ==={RESET}"
math 100 + 50
out math_result
randint 1 100
out randint_result

print "{CYAN}=== Strings ==={RESET}"
let domain = "github.com"
upper domain
out upper_result
lower upper_result
out lower_result
strlen domain
out strlen_result
contains domain "github"
out contains_result
encode "VroxScript 2.2"
out encode_result
md5 "VroxScript"
out md5_result
sha256 "VroxScript"
out sha256_result

print "{CYAN}=== Lists ==={RESET}"
list targets = ["github.com", "google.com", "github.com"]
unique targets
out unique_result
sort targets
out sort_result
count targets
out count_result

print "{CYAN}=== Dictionary ==={RESET}"
dict mydict =
dictset mydict "name" "VroxScript"
dictset mydict "version" "2.2"
dictget mydict "name"
out dictget_result
dictkeys mydict
out dictkeys_result

print "{CYAN}=== Loops ==={RESET}"
let x = 0
while x < 5 {
    let x = x + 1
    if x == 3 {
        warn "Skipping 3"
        continue
    }
    out x
    if x == 4 {
        success "Breaking at 4"
        break
    }
}

print "{CYAN}=== Functions ==={RESET}"
func recon {
    info "Recon on: {arg1}"
    resolve arg1
    print "IP: {resolved_ip}"
}
call recon "github.com"

print "{CYAN}=== HTTP Settings ==={RESET}"
setheader "User-Agent" "VroxScript/2.2"
fetch get https://github.com
out fetch_status
grep fetch_body "github"
out grep_result
clearheaders

print "{CYAN}=== Security ==={RESET}"
secheaders https://github.com >> secheaders.txt
ssl https://github.com >> ssl.txt
techdetect https://github.com >> tech.txt
emails https://github.com >> emails.txt
corscheck https://github.com >> cors.txt

print "{CYAN}=== Files ==={RESET}"
save test.txt "VroxScript 2.2 test"
exists test.txt
out exists_result
read test.txt
append test.txt "Second line"
lines test.txt
out lines_result
delete test.txt

print "{CYAN}=== JSON ==={RESET}"
let jsondata = "{\"name\":\"VroxScript\",\"version\":\"2.2\"}"
jsonparse jsondata
jsonget jsondata "name"
out jsonget_result

print "{CYAN}=== Timing ==={RESET}"
timing https://github.com 3
out timing_results

print "{CYAN}=== Full Recon ==={RESET}"
input target
timestamp
out timestamp_result

resolve target >> resolve.txt
dns target >> dns.txt
scan subdomains target >> subs.txt
probe scan_results >> probed.txt
ports target >> ports.txt
ssl https://target >> ssl.txt
techdetect https://target >> tech.txt
secheaders https://target >> secheaders.txt
emails https://target >> emails.txt
corscheck https://target >> cors.txt
fuzz https://target filter-status 200,301,403 >> fuzz.txt
wayback target >> wayback.txt
fetch get https://target
secrets fetch_body >> secrets.txt
js https://target >> js.txt
report target >> report.txt
show report.txt

print "{GREEN}================================{RESET}"
print "{GREEN}  VroxScript 2.2 Test Complete!{RESET}"
print "{GREEN}================================{RESET}"
