#!/bin/bash
# zone-tester.sh — Mail domain/MX security scanner (macOS/Bash 3 compatible)

set -euo pipefail

# ────────────────────────────────────────────────────────────────────────────
# UI / icons
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
BOLD='\033[1m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'; DIM='\033[2m'
OK="✅"; FAIL="❌"; WARN="⚠️"; INFO="ℹ️"; SHIELD="🛡️"; LOCK="🔒"; CERT="📜"

# ────────────────────────────────────────────────────────────────────────────
# Defaults / globals
HOSTS=()
DOMAINS=()
POSITIONALS=()
SERVICE_MAP="25:smtp,587:smtp,465:smtps,993:imaps"
FORCE_V4=true
DEBUG=0
HTTP_TIMEOUT=8
TCP_TIMEOUT=10
OUTPUT_FORMAT="text"
PARALLEL=false
CHECK_RELAY=false
VERBOSE=false
INCLUDE_CLOUD=false
DO_MX=false
EXTRA_HOSTS=()         # e.g. "imap.example.com%993:imaps" or "mail.example.com%25:smtp,587:smtp,465:smtps"
EXTRA_ENDPOINTS=()     # normalized: "host port type"
RAW_ENDPOINTS=()       # original "--endpoint host:port:type" strings (for passing to parallel)
SINGLE_HOST=""
NO_DEFAULT_SERVICES=false

# Kill child processes on Ctrl-C
trap 'pkill -P $$ >/dev/null 2>&1 || true; exit 130' INT

# ────────────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage:
  $0 [-H host]... [-D domain]... [--mx]
     [-S "25:smtp,587:smtp,465:smtps,993:imaps"] [--ipv6] [--debug]
     [--format text|json|csv] [--parallel] [--check-relay] [--verbose]
     [--include-cloud] [--smtp-host HOST] [--imap-host HOST]
     [--endpoint host:port:type] [--no-default-services]
     [domain_or_host]...

Options:
  -H, --host          Host to test
  -D, --domain        Domain to test
  --mx                Test MX records for domains
  -S, --services      Service map (default: 25:smtp,587:smtp,465:smtps,993:imaps)
  --ipv6              Enable IPv6 testing (IPv4 only is default)
  --debug             Enable debug output
  --format            Output format: text, json, csv
  --parallel          Run tests in parallel (stable)
  --check-relay       Perform safe open relay detection (port 25)
  --verbose           Show additional details
  --include-cloud     Include Microsoft 365 / Google / hosted MX in host-level checks
  --smtp-host HOST    Add a dedicated SMTP host (25,587,465 on that host)
  --imap-host HOST    Add a dedicated IMAP host (993 on that host)
  --endpoint H:P:T    Add a custom endpoint (e.g. mail.example.com:2525:smtp)
  --no-default-services
                      Do not run the default service map for hosts (only endpoints/overrides)
  -h, --help          Show this help

Advanced:
  --single-host HOST  (internal) Run checks for exactly one host; used by --parallel

Examples:
  $0 -D example.com --mx
  $0 -H mail.example.com -S "25:smtp,465:smtps"
  $0 example.com --format json > report.json
  $0 --smtp-host mail.example.com --imap-host imap.example.com example.com
  $0 --endpoint mail.example.com:2525:smtp example.com
  $0 --no-default-services --endpoint mail.example.com:2525:smtp example.com
EOF
}

# ────────────────────────────────────────────────────────────────────────────
# utils
die(){ echo -e "${RED}Error:${NC} $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Required tool not found: $1"; }
log_verbose(){ [ "$VERBOSE" = true ] && echo -e "${DIM}  └─ $*${NC}" >&2; }
dedup_lines(){ awk '!x[$0]++'; }

print_header() {
  [ "$OUTPUT_FORMAT" != "text" ] && return 0
  if [[ -n "${SINGLE_HOST:-}" ]]; then return 0; fi
  echo
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${CYAN}  $SHIELD  ${BOLD}Mail Security Scanner${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_section() {
  [ "$OUTPUT_FORMAT" != "text" ] && return 0
  local title="$1"
  echo
  echo -e "${BLUE}┌─────────────────────────────────────────────────────────────────────────────${NC}"
  echo -e "${BLUE}│ ${BOLD}$title${NC}"
  echo -e "${BLUE}└─────────────────────────────────────────────────────────────────────────────${NC}"
}

print_subsection() {
  [ "$OUTPUT_FORMAT" != "text" ] && return 0
  local title="$1"
  echo
  echo -e "  ${CYAN}▶ ${BOLD}$title${NC}"
  echo -e "  ${DIM}─────────────────────────────────────${NC}"
}

print_item(){ [ "$OUTPUT_FORMAT" = "text" ] && echo -e "  $1 $2"; }
print_detail(){ [ "$OUTPUT_FORMAT" = "text" ] && echo -e "     ${DIM}│${NC} $1"; }
print_footer(){ [ "$OUTPUT_FORMAT" = "text" ] && echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# ────────────────────────────────────────────────────────────────────────────
# Cloud MX detection
is_microsoft365_host(){ echo "$1" | grep -qE "(mail\.protection\.outlook\.com|mail\.eo\.outlook\.com)$"; }
is_google_workspace_host(){ echo "$1" | grep -qE "(aspmx.*\.googlemail\.com|alt[1-4]\.aspmx.*\.googlemail\.com|smtp\.google\.com)$"; }
is_other_cloud_host(){ echo "$1" | grep -qE "(pphosted\.com|secureserver\.net|mimecast\.com|pepipost\.mx|authsmtp\.com|mailanyone\.net)$"; }
is_cloud_managed_host(){ is_microsoft365_host "$1" || is_google_workspace_host "$1" || is_other_cloud_host "$1"; }

# ────────────────────────────────────────────────────────────────────────────
# required tools
OPENSSL="$(command -v openssl || true)"; [ -z "$OPENSSL" ] && die "openssl not found"
need dig
HAVE_NC=false; command -v nc >/dev/null 2>&1 && HAVE_NC=true
HAVE_CURL=false; command -v curl >/dev/null 2>&1 && HAVE_CURL=true
HAVE_JQ=false; command -v jq >/dev/null 2>&1 && HAVE_JQ=true

if command -v xxd >/dev/null 2>&1; then HEXDUMP_CMD='xxd -p -c 256'
elif command -v hexdump >/dev/null 2>&1; then HEXDUMP_CMD='hexdump -ve "1/1 \"%02x\""'
else die "xxd or hexdump not found"; fi

TIMEOUT_CMD=''
if command -v timeout >/dev/null 2>&1; then TIMEOUT_CMD="timeout $TCP_TIMEOUT"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_CMD="gtimeout $TCP_TIMEOUT"
fi

# Silence GNU Parallel citation prompt (non-interactive)
if command -v parallel >/dev/null 2>&1; then
  PARALLEL_HOME="${HOME}/.parallel"
  mkdir -p "$PARALLEL_HOME" 2>/dev/null || true
  : > "${PARALLEL_HOME}/will-cite" 2>/dev/null || true
fi

# Bash 3-safe readarray wrapper
readarray_compat() {
  local __n="$1"; shift
  local __a=() __l
  while IFS= read -r __l; do
    [ -n "$__l" ] && __a+=("$__l")
  done < <("$@")
  if [ ${#__a[@]:-0} -eq 0 ]; then
    eval "$__n=()"
  else
    eval "$__n=(\"\${__a[@]}\")"
  fi
}

# Helper: require next argument
need_arg() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" || "${2:0:1}" == "-" ]]; then
    die "Missing value for $flag"
  fi
}

# ────────────────────────────────────────────────────────────────────────────
# args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -H|--host)         need_arg "$1" "$2"; HOSTS+=("$2"); shift 2;;
    -D|--domain)       need_arg "$1" "$2"; DOMAINS+=("$2"); shift 2;;
    --mx)              DO_MX=true; shift;;
    -S|--services)     need_arg "$1" "$2"; SERVICE_MAP="$2"; shift 2;;
    --ipv6)            FORCE_V4=false; shift;;
    --debug)           DEBUG=1; shift;;
    --format)          need_arg "$1" "$2"; OUTPUT_FORMAT="$2"; shift 2;;
    --parallel)        PARALLEL=true; shift;;
    --check-relay)     CHECK_RELAY=true; shift;;
    --verbose)         VERBOSE=true; shift;;
    --include-cloud)   INCLUDE_CLOUD=true; shift;;
    --smtp-host)       need_arg "$1" "$2"; h="$2"; shift 2; EXTRA_HOSTS+=("${h}%25:smtp,587:smtp,465:smtps");;
    --imap-host)       need_arg "$1" "$2"; h="$2"; shift 2; EXTRA_HOSTS+=("${h}%993:imaps");;
    --endpoint)
      need_arg "$1" "${2:-}"; ep="$2"; shift 2
      RAW_ENDPOINTS+=("$ep")
      host="${ep%%:*}"; rest="${ep#*:}"; port="${rest%%:*}"; type="${rest##*:}"
      EXTRA_ENDPOINTS+=("$host $port $type")
      ;;
    --no-default-services)
      NO_DEFAULT_SERVICES=true; shift;;
    --single-host)
      need_arg "$1" "$2"; SINGLE_HOST="$2"; shift 2;;
    -h|--help)         usage; exit 0;;
    --)                shift; while [[ $# -gt 0 ]]; do POSITIONALS+=("$1"); shift; done;;
    -*)                die "Unknown argument: $1";;
    *)                 POSITIONALS+=("$1"); shift;;
  esac
done

if [[ ${#POSITIONALS[@]} -gt 0 && ${#HOSTS[@]} -eq 0 && ${#DOMAINS[@]} -eq 0 ]]; then
  DOMAINS+=("${POSITIONALS[@]}"); DO_MX=true
fi

# ────────────────────────────────────────────────────────────────────────────
# helpers
expand_services(){
  local IFS=','
  for p in $1; do
    local port="${p%%:*}" type="${p##*:}"
    [ -z "$port" ] || [ -z "$type" ] && die "Invalid service pair: '$p'"
    echo "$port $type"
  done
}
mx_hosts_for_domain(){ dig +short MX "$1" | sort -n -k1 | awk '{print $2}' | sed 's/\.$//' | awk 'NF'; }
fallback_hosts_for_domain(){ printf "%s\n" "mail.$1" "smtp.$1" "imap.$1" "$1"; }
has_a_record(){
  dig +short A "$1" | grep -qE '^[0-9]+' && return 0
  dig +short AAAA "$1" | grep -q ':' && return 0
  return 1
}
join_txt(){ sed -e 's/^"//' -e 's/"$//' -e 's/" "[ ]*//g'; }

dnssec_ad_flag(){ local n="$1" t="$2"; local out hdr; out="$(dig +dnssec "$t" "$n" @1.1.1.1 2>/dev/null || true)"; hdr="$(printf "%s" "$out" | awk '/;; flags:/ {print $0}')"; echo "$hdr" | grep -q ' ad[; ]' && echo "YES" || echo "NO"; }
dnssec_ds_present(){ dig +short DS "$1" @1.1.1.1 | awk 'NF{print; exit}' >/dev/null && echo "YES" || echo "NO"; }
dnssec_rrsig_present(){ dig "$1" "$2" +dnssec @1.1.1.1 | awk '/RRSIG/ {f=1} END{print (f?"YES":"NO")}'; }

check_reverse_dns() {
  local host="$1"; local ip="$(dig +short A "$host" | head -1)"
  if [ -n "$ip" ]; then local rdns="$(dig +short -x "$ip" | sed 's/\.$//')"; [ -n "$rdns" ] && echo "$rdns" && return 0; fi
  return 1
}
check_caa_records(){ local d="$1"; local caa="$(dig +short CAA "$d" 2>/dev/null || true)"; [ -n "$caa" ] && echo "$caa" && return 0 || return 1; }
check_txt_exists(){ local name="$1"; dig +short TXT "$name" | tr -d '\r' | join_txt; }

kv_get_txt() {
  local key="$1"; shift
  printf "%s" "$*" | tr -d '\r' \
  | sed -e 's/^"//' -e 's/"$//' -e 's/"[ ]*"[ ]*//g' \
  | sed 's/;[[:space:]]*/;\n/g' \
  | awk -F= -v k="$(echo "$key" | tr '[:upper:]' '[:lower:]')" '
      {gsub(/^[ \t]+|[ \t]+$/,"",$1); kl=tolower($1);
       if (kl==k) { $1=""; sub(/^=/,""); v=$0; gsub(/^[ \t]+|[ \t]+$/,"",v); print v; exit }}' \
  | sed 's/[[:space:]]*;.*$//'
}
kv_get_policy(){
  local key="$1"; shift
  echo "$*" \
  | awk -F: -v k="$(echo "$key" | tr '[:upper:]' '[:lower:]')" '
      {h=tolower($1);
       if (h==k){$1=""; sub(/^:/,""); sub(/^[ \t]+/,""); gsub(/[ \t]+$/,""); print; exit}}'
}

# ────────────────────────────────────────────────────────────────────────────
# networking
port_open() {
  local host="$1" port="$2" force4flag=""
  [ "$FORCE_V4" = true ] && force4flag="-4"
  if $HAVE_NC; then
    if $TIMEOUT_CMD nc $force4flag -z -G 3 "$host" "$port" >/dev/null 2>&1 \
       || $TIMEOUT_CMD nc $force4flag -z -w 3 "$host" "$port" >/dev/null 2>&1; then
      return 0; else return 1; fi
  elif $HAVE_CURL; then
    $TIMEOUT_CMD curl --silent --output /dev/null --connect-timeout 3 "telnet://$host:$port" >/dev/null 2>&1
  else
    if [ -n "$TIMEOUT_CMD" ]; then eval "$TIMEOUT_CMD bash -c 'cat < /dev/null > /dev/tcp/$host/$port' " >/dev/null 2>&1; else (exec 3<>"/dev/tcp/$host/$port") >/dev/null 2>&1; fi
  fi
}

run_s_client() {
  local target="$1" port="$2" sni="$3" stype="$4" tlsver="$5" force4="$6"
  local starttls=""; case "$stype" in smtp) starttls="-starttls smtp";; smtps|imaps) starttls="";; *) return 1;; esac
  local vflag=""; [ -n "$tlsver" ] && vflag="$tlsver"
  local force4flag=""; [ "$force4" = "1" ] && force4flag="-4"
  local cmd
  if [ -n "$TIMEOUT_CMD" ]; then
    cmd="$TIMEOUT_CMD $OPENSSL s_client $force4flag $vflag -connect ${target}:${port} -servername $sni -showcerts $starttls"
  else
    cmd="$OPENSSL s_client $force4flag $vflag -connect ${target}:${port} -servername $sni -showcerts $starttls"
  fi
  printf '\n' | eval $cmd 2>&1
}

fetch_cert_chain() {
  local host="$1" port="$2" stype="$3"
  local sni="$host"
  local ip4 ip6; ip4="$(dig +short A "$host" | head -1 || true)"; ip6="$(dig +short AAAA "$host" | head -1 || true)"
  local targets=()
  [[ -n "$ip4" ]] && targets+=("$ip4")
  if [[ "$FORCE_V4" = false && -n "$ip6" ]]; then targets+=("$ip6"); fi
  targets+=("$host")
  local out
  for t in "${targets[@]}"; do
    for ver in "" "-tls1_2"; do
      out="$(run_s_client "$t" "$port" "$sni" "$stype" "$ver" "$([[ "$FORCE_V4" = true && "$t" != "$ip6" ]] && echo 1 || echo 0)")"
      [[ "$DEBUG" -eq 1 ]] && { echo "--- DEBUG s_client: target=$t port=$port stype=$stype ver=${ver:-auto} ---" 1>&2; echo "$out" 1>&2; echo "-----" 1>&2; }
      echo "$out" | grep -q "BEGIN CERTIFICATE" && { printf "%s" "$out"; return 0; }
    done
  done
  return 1
}

spki_sha256() {
  local pem="$1"
  echo "$pem" \
    | "$OPENSSL" x509 -noout -pubkey 2>/dev/null \
    | "$OPENSSL" pkey -pubin -outform DER 2>/dev/null \
    | "$OPENSSL" dgst -sha256 -binary 2>/dev/null \
    | eval "$HEXDUMP_CMD" | tr -d '\n' | tr '[:upper:]' '[:lower:]'
}

calculate_expected_tlsa() {
  local hostname="$1" port="$2" service_type="$3"
  if is_cloud_managed_host "$hostname" && [ "$INCLUDE_CLOUD" = false ]; then
    echo "PROVIDER_SKIP"; return 0
  fi
  local rr usage selector mtype want
  rr=$(dig +short TLSA "_${port}._tcp.${hostname}" | head -1 || true)
  [ -z "$rr" ] && { echo "NO_RR"; return 0; }

  usage=$(awk '{print $1}' <<<"$rr")
  selector=$(awk '{print $2}' <<<"$rr")
  mtype=$(awk '{print $3}' <<<"$rr")
  want=$(awk '{for(i=4;i<=NF;i++) printf "%s", $i}' <<<"$rr" | tr -d ' ' | tr '[:upper:]' '[:lower:]')

  local chain
  chain="$(fetch_cert_chain "$hostname" "$port" "$service_type")" || { echo "HANDSHAKE_ERR"; return 0; }
  echo "$chain" | grep -q "BEGIN CERTIFICATE" || { echo "HANDSHAKE_ERR"; return 0; }

  local cert="" in=0
  while IFS= read -r line; do
    [[ "$line" == *"-----BEGIN CERTIFICATE-----"* ]] && { in=1; cert=""; }
    [ $in -eq 1 ] && cert+="$line"$'\n'
    if [[ "$line" == *"-----END CERTIFICATE-----"* ]] && [ $in -eq 1 ]; then
      in=0
      local test_hash=""
      if   [ "$selector" = "1" ] && [ "$mtype" = "1" ]; then
        test_hash="$(spki_sha256 "$cert")"
      elif [ "$selector" = "0" ] && [ "$mtype" = "1" ]; then
        test_hash=$(echo "$cert" | "$OPENSSL" x509 -outform DER 2>/dev/null | "$OPENSSL" dgst -sha256 -binary | eval "$HEXDUMP_CMD" | tr -d '\n' | tr '[:upper:]' '[:lower:]')
      elif [ "$selector" = "0" ] && [ "$mtype" = "2" ]; then
        test_hash=$(echo "$cert" | "$OPENSSL" x509 -outform DER 2>/dev/null | "$OPENSSL" dgst -sha512 -binary | eval "$HEXDUMP_CMD" | tr -d '\n' | tr '[:upper:]' '[:lower:]')
      elif [ "$selector" = "1" ] && [ "$mtype" = "2" ]; then
        test_hash=$(echo "$cert" | "$OPENSSL" x509 -noout -pubkey 2>/dev/null | "$OPENSSL" pkey -pubin -outform DER 2>/dev/null | "$OPENSSL" dgst -sha512 -binary | eval "$HEXDUMP_CMD" | tr -d '\n' | tr '[:upper:]' '[:lower:]')
      fi
      if [ -n "$test_hash" ] && [ "$test_hash" = "$want" ]; then
        echo "MATCH ${usage} ${selector} ${mtype}"; return 0
      fi
      cert=""
    fi
  done <<< "$chain"

  echo "NO_MATCH ${usage} ${selector} ${mtype}"
  return 0
}

tls_versions_summary() {
  local host="$1" port="$2" stype="$3"
  local vers=( "-tls1" "-tls1_1" "-tls1_2" "-tls1_3" )
  local ok10=0 ok11=0 ok12=0 ok13=0

  for v in "${vers[@]}"; do
    out="$(run_s_client "$host" "$port" "$host" "$stype" "$v" "$([[ "$FORCE_V4" = true ]] && echo 1 || echo 0)" || true)"
    if echo "$out" | grep -q "BEGIN CERTIFICATE"; then
      case "$v" in
        -tls1)   ok10=1;;
        -tls1_1) ok11=1;;
        -tls1_2) ok12=1;;
        -tls1_3) ok13=1;;
      esac
    fi
  done

  local acc=()
  [ $ok10 -eq 1 ] && acc+=("1.0")
  [ $ok11 -eq 1 ] && acc+=("1.1")
  [ $ok12 -eq 1 ] && acc+=("1.2")
  [ $ok13 -eq 1 ] && acc+=("1.3")

  if [ ${#acc[@]} -gt 0 ]; then
    print_detail "${LOCK} TLS: ${BOLD}${acc[*]}${NC}"
  else
    print_detail "${FAIL} No TLS detected"
  fi

  if [ $ok12 -eq 1 ] && [ $ok13 -eq 1 ] && [ $ok10 -eq 0 ] && [ $ok11 -eq 0 ]; then
    print_detail "${GREEN}✓ Modern TLS only (1.2/1.3)${NC}"
  elif [ $ok12 -eq 1 ] || [ $ok13 -eq 1 ]; then
    if [ $ok10 -eq 1 ] || [ $ok11 -eq 1 ]; then
      print_detail "${YELLOW}⚠ Legacy TLS 1.0/1.1 enabled${NC}"
    fi
    [ $ok13 -eq 0 ] && print_detail "${YELLOW}⚠ TLS 1.3 not supported${NC}"
  else
    print_detail "${RED}✗ No modern TLS detected${NC}"
  fi
}

check_smtp_banner() {
  local host="$1" port="$2"
  if [[ "$port" == "25" || "$port" == "587" ]] && [ "$VERBOSE" = true ]; then
    local banner
    if $HAVE_NC; then
      banner="$(echo "QUIT" | nc -w 3 "$host" "$port" 2>/dev/null | head -1 || true)"
    else
      banner="$(echo "QUIT" | $TIMEOUT_CMD telnet "$host" "$port" 2>/dev/null | grep "220 " | head -1 || true)"
    fi
    if [ -n "$banner" ]; then
      log_verbose "Banner: ${DIM}$banner${NC}"
      if echo "$banner" | grep -qE "(Postfix|Exim|Exchange|sendmail|qmail).*[0-9]+\.[0-9]+"; then
        log_verbose "${YELLOW}Banner reveals software version${NC}"
      fi
    fi
  fi
}

check_open_relay() {
  local host="$1" port="$2"
  if [ "$CHECK_RELAY" = true ] && [[ "$port" == "25" ]]; then
    local test_result
    if $HAVE_NC; then
      test_result="$(printf "EHLO test\nMAIL FROM:<test@example.com>\nRCPT TO:<test@example.org>\nQUIT\n" | \
        nc -w 5 "$host" "$port" 2>/dev/null | grep -E "(550|554|553|551|Relay|relay)" || true)"
    fi
    if [ -n "$test_result" ]; then
      if echo "$test_result" | grep -qiE "(denied|reject|refuse|not permitted)"; then
        log_verbose "${GREEN}Open relay properly denied${NC}"
      else
        log_verbose "${YELLOW}Check relay config manually${NC}"
      fi
    fi
  fi
}

check_cert_expiry() {
  local host="$1" port="$2" stype="$3"
  local cert_info
  cert_info="$(fetch_cert_chain "$host" "$port" "$stype" 2>/dev/null | \
    openssl x509 -noout -dates 2>/dev/null || true)"
  if [ -n "$cert_info" ]; then
    local not_after="$(echo "$cert_info" | grep notAfter | cut -d= -f2)"
    if [ -n "$not_after" ]; then
      local exp_epoch=$(date -j -f "%b %d %T %Y %Z" "$not_after" "+%s" 2>/dev/null || \
                        date -d "$not_after" "+%s" 2>/dev/null || echo "0")
      local now_epoch=$(date "+%s")
      if [ "$exp_epoch" -gt 0 ]; then
        local days_left=$(( ($exp_epoch - $now_epoch) / 86400 ))
        if [ $days_left -lt 7 ]; then
          print_detail "${RED}$FAIL Certificate expires in $days_left days!${NC}"
        elif [ $days_left -lt 30 ]; then
          print_detail "${YELLOW}$WARN Certificate expires in $days_left days${NC}"
        else
          print_detail "${GREEN}$CERT Certificate valid for $days_left days${NC}"
        fi
      fi
    fi
  fi
}

analyze_ciphers() {
  local host="$1" port="$2" stype="$3"
  if [ "$VERBOSE" = true ]; then
    local starttls=""
    case "$stype" in
      smtp) starttls="-starttls smtp";;
    esac
    local weak_ciphers
    weak_ciphers="$(echo | openssl s_client -connect "${host}:${port}" $starttls -cipher "EXPORT:LOW:DES:RC4:MD5" 2>&1 | grep -i "cipher is" || true)"
    [ -n "$weak_ciphers" ] && print_detail "${RED}$WARN Weak ciphers supported!${NC}"
    local pref_cipher
    pref_cipher="$(echo | openssl s_client -connect "${host}:${port}" $starttls 2>&1 | grep "Cipher.*:" | head -1 | sed 's/.*Cipher.*: *//' || true)"
    [ -n "$pref_cipher" ] && log_verbose "Cipher: $pref_cipher"
  fi
}

# ────────────────────────────────────────────────────────────────────────────
# MTA-STS / TLS-RPT / SPF / DMARC / BIMI / ARC / CAA / DNSSEC
check_mta_sts() {
  local domain="$1"
  local txt_name="_mta-sts.${domain}"
  local txt_val; txt_val="$(check_txt_exists "$txt_name" || true)"
  if [[ -z "$txt_val" ]]; then
    print_item "$WARN" "No MTA-STS TXT record"
  else
    local v id; v="$(kv_get_txt v "$txt_val")"; id="$(kv_get_txt id "$txt_val")"
    if [[ "$(echo "$v" | tr '[:lower:]' '[:upper:]')" == "STSV1" ]]; then
      print_item "$OK" "MTA-STS configured"; [ -n "$id" ] && print_detail "Version: ${BOLD}STSv1${NC}, ID: ${DIM}$id${NC}"
    else
      print_item "$WARN" "Invalid MTA-STS version in TXT"
    fi
  fi
  if $HAVE_CURL; then
    local url="https://mta-sts.${domain}/.well-known/mta-sts.txt"
    local policy; policy="$(
      curl -m "$HTTP_TIMEOUT" -fsS "$url" 2>/dev/null \
      | sed '1s/^\xEF\xBB\xBF//' | tr -d '\r'
    )"
    if [[ -z "$policy" ]]; then
      print_detail "${YELLOW}Policy fetch failed${NC}"
    else
      local pv pmode pmax pmx
      pv="$(kv_get_policy version "$policy" | tr -d ' ')"
      pmode="$(kv_get_policy mode "$policy" | tr -d ' ')"
      pmax="$(kv_get_policy max_age "$policy" | tr -d ' ')"
      pmx="$(echo "$policy" | awk -F: 'BEGIN{IGNORECASE=1} /^[[:space:]]*mx[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/,""); gsub(/^[ \t]+|[ \t]+$/,""); print}' | paste -sd, -)"
      if [[ "$(echo "$pv" | tr '[:lower:]' '[:upper:]')" == "STSV1" ]]; then
        print_detail "${GREEN}✓ Policy active${NC} - Mode: ${BOLD}${pmode:-unknown}${NC}${pmax:+, max_age: ${pmax}}"
        [ -n "$pmx" ] && print_detail "Policy MX: ${DIM}$pmx${NC}"
        [[ "$pmode" == "testing" ]] && print_detail "${INFO} Testing mode only"
      else
        print_detail "${YELLOW}Invalid policy version${NC}"
      fi
    fi
  fi
}
check_tls_rpt() {
  local domain="$1"; local name="_smtp._tls.${domain}"
  local val; val="$(check_txt_exists "$name" || true)"
  if [[ -z "$val" ]]; then print_item "$INFO" "No TLS-RPT configured"
  else
    local v rua; v="$(kv_get_txt v "$val")"; rua="$(kv_get_txt rua "$val")"
    local vnorm="$(echo "$v" | tr '[:lower:]' '[:upper:]')"
    if [[ "$vnorm" == "TLSRPTV1" || -z "$v" ]]; then
      print_item "$OK" "TLS-RPT configured"; [ -n "$rua" ] && print_detail "Reports to: ${DIM}$rua${NC}"
    else print_item "$WARN" "Invalid TLS-RPT version"; fi
  fi
}
check_spf() {
  local domain="$1"
  local out; out="$(dig +short TXT "$domain" | tr -d '\r' | join_txt | grep -i 'v=spf1' || true)"
  if [[ -z "$out" ]]; then print_item "$WARN" "No SPF record"
  else
    print_item "$OK" "SPF configured"; print_detail "${DIM}$out${NC}"
    if [ "$VERBOSE" = true ]; then
      if echo "$out" | grep -q "+all"; then log_verbose "${RED}Dangerous: +all allows anyone!${NC}"
      elif echo "$out" | grep -q "~all"; then log_verbose "Softfail mode (~all)"
      elif echo "$out" | grep -q "-all"; then log_verbose "${GREEN}Hardfail mode (-all)${NC}"; fi
      local lookups=$(echo "$out" | grep -oE "(include:|a:|mx:|ptr:|exists:|redirect=)" | wc -l)
      [ $lookups -gt 10 ] && log_verbose "${YELLOW}$lookups DNS lookups (limit: 10)${NC}"
    fi
  fi
}
check_dmarc() {
  local domain="$1"; local name="_dmarc.${domain}"
  local val; val="$(check_txt_exists "$name" || true)"
  if [[ -z "$val" ]]; then print_item "$WARN" "No DMARC record"
  else
    local v p rua sp pct; v="$(kv_get_txt v "$val")"; p="$(kv_get_txt p "$val")"; sp="$(kv_get_txt sp "$val")"
    rua="$(kv_get_txt rua "$val")"; pct="$(kv_get_txt pct "$val")"
    local policy_icon="$INFO"; local policy_color=""
    case "${p:-none}" in
      none) policy_icon="$INFO"; policy_color="${YELLOW}";;
      quarantine) policy_icon="$WARN"; policy_color="${YELLOW}";;
      reject) policy_icon="$OK"; policy_color="${GREEN}";;
    esac
    print_item "$policy_icon" "DMARC: ${policy_color}${BOLD}p=$p${NC}"
    [ -n "$sp" ] && print_detail "Subdomain: ${BOLD}sp=$sp${NC}"
    [ -n "$pct" ] && [ "$pct" != "100" ] && print_detail "${YELLOW}Coverage: $pct%${NC}"
    [ -n "$rua" ] && print_detail "Reports: ${DIM}$rua${NC}"
  fi
}
check_bimi() {
  local domain="$1"; local selector="default"; local name="${selector}._bimi.${domain}"
  local val; val="$(dig +short TXT "$name" 2>/dev/null | tr -d '\r' | join_txt || true)"
  if [[ -z "$val" ]]; then print_item "$INFO" "No BIMI record configured"
  else
    local v l a; v="$(echo "$val" | sed -n 's/.*v=\([^;]*\).*/\1/p' || true)"
    l="$(echo "$val" | sed -n 's/.*l=\([^;]*\).*/\1/p' || true)"
    a="$(echo "$val" | sed -n 's/.*a=\([^;]*\).*/\1/p' || true)"
    if [[ "$v" == "BIMI1" ]]; then
      print_item "$OK" "BIMI configured${l:+ with logo}"
      [ -n "$l" ] && print_detail "Logo: ${DIM}$l${NC}"
      [ -n "$a" ] && print_detail "Cert: ${DIM}$a${NC}"
    else print_item "$WARN" "Invalid BIMI version"; fi
  fi
}
check_arc() {
  local domain="$1"; local name="_domainkey.${domain}"
  local keys="$(dig +short TXT "$name" 2>/dev/null | grep -i "arc" || true)"
  [ -n "$keys" ] && print_item "$OK" "ARC authentication configured" || print_item "$INFO" "No ARC configuration (optional)"
}
check_caa() {
  local domain="$1"; local caa_records="$(check_caa_records "$domain" || true)"
  if [ -n "$caa_records" ]; then
    print_item "$OK" "CAA records configured"
    if [ "$VERBOSE" = true ]; then while read -r line; do log_verbose "$line"; done <<< "$caa_records"; fi
  else print_item "$INFO" "No CAA records"; fi
}
check_dnssec_signals() {
  local domain="$1"; local ds rr mxad
  ds="$(dnssec_ds_present "$domain" || echo "ERROR")"
  rr="$(dnssec_rrsig_present "$domain" MX || echo "ERROR")"
  mxad="$(dnssec_ad_flag "$domain" MX || echo "ERROR")"
  [ "$ds" = "ERROR" ] && ds="NO"; [ "$rr" = "ERROR" ] && rr="NO"; [ "$mxad" = "ERROR" ] && mxad="NO"
  local status="$INFO"; local message="DNSSEC: "
  if [[ "$ds" == "YES" && "$rr" == "YES" && "$mxad" == "YES" ]]; then status="$OK"; message="${message}${GREEN}Fully validated${NC}"
  elif [[ "$ds" == "YES" && "$rr" == "YES" && "$mxad" == "NO" ]]; then status="$WARN"; message="${message}${YELLOW}Signed but validation failed${NC}"
  elif [[ "$ds" == "NO" && "$rr" == "NO" ]]; then status="$INFO"; message="${message}Not signed"
  else status="$WARN"; message="${message}${YELLOW}Partial/Invalid configuration${NC}"; fi
  print_item "$status" "$message"
  if [ "$VERBOSE" = true ]; then log_verbose "DS at parent: $ds, RRSIG in zone: $rr, AD flag: $mxad"; fi
}

# ────────────────────────────────────────────────────────────────────────────
# Per-host tests
test_one(){
  local host="$1" port="$2" stype="$3"

  if [ "$VERBOSE" = true ]; then
    local rdns="$(check_reverse_dns "$host")"
    [ -n "$rdns" ] && log_verbose "PTR: $rdns"
  fi

  local service_name="$stype"
  case "$stype" in
    smtp) service_name="SMTP";;
    smtps) service_name="SMTPS";;
    imaps) service_name="IMAPS";;
  esac

  echo
  if ! port_open "$host" "$port"; then
    echo -e "  ${DIM}┌─ Port $port ($service_name)${NC}"
    echo -e "  ${DIM}└─${NC} ${YELLOW}Connection failed${NC} - port not reachable"
    return 0
  fi

  echo -e "  ${BOLD}Port $port${NC} ${DIM}($service_name)${NC}"

  check_smtp_banner "$host" "$port"
  check_open_relay "$host" "$port"

  local res; res="$(calculate_expected_tlsa "$host" "$port" "$stype")"
  case "$res" in
    PROVIDER_SKIP)
      print_detail "${INFO} Cloud provider host (TLSA not supported)"
      tls_versions_summary "$host" "$port" "$stype"
      check_cert_expiry "$host" "$port" "$stype"
      ;;
    NO_RR)
      print_detail "${INFO} No TLSA record"
      tls_versions_summary "$host" "$port" "$stype"
      check_cert_expiry "$host" "$port" "$stype"
      analyze_ciphers "$host" "$port" "$stype"
      ;;
    HANDSHAKE_ERR)
      print_detail "${FAIL} TLS handshake failed"
      ;;
    MATCH*)
      local params="${res#MATCH }"
      print_detail "${GREEN}✓ TLSA validated${NC} ${DIM}($params)${NC}"
      tls_versions_summary "$host" "$port" "$stype"
      check_cert_expiry "$host" "$port" "$stype"
      analyze_ciphers "$host" "$port" "$stype"
      ;;
    NO_MATCH*)
      local params="${res#NO_MATCH }"
      print_detail "${RED}✗ TLSA mismatch${NC} ${DIM}($params)${NC}"
      tls_versions_summary "$host" "$port" "$stype"
      check_cert_expiry "$host" "$port" "$stype"
      analyze_ciphers "$host" "$port" "$stype"
      ;;
    *)
      print_detail "${RED}✗ Unexpected error${NC}"
      ;;
  esac
}

run_tests() {
  local hfull="$1"
  local h="${hfull%%\%*}"
  local override_map=""
  if [[ "$hfull" == *%* ]]; then override_map="${hfull#*%}"; fi

  # Build per-host service list
  local svc_pairs=()
  if [[ -n "$override_map" ]]; then
    readarray_compat svc_pairs expand_services "$override_map"
  else
    readarray_compat svc_pairs expand_services "$SERVICE_MAP"
  fi

  print_subsection "$h"

  if is_cloud_managed_host "$h" && [ "$INCLUDE_CLOUD" = false ]; then
    echo -e "  ${DIM}Cloud provider detected (skipping port/TLS/TLSA checks). Use --include-cloud to force.${NC}"
    return 0
  fi

  # Optionally skip default service map
  if [ "$NO_DEFAULT_SERVICES" != true ]; then
    local row port stype
    for row in "${svc_pairs[@]}"; do
      port="${row%% *}"; stype="${row##* }"
      test_one "$h" "$port" "$stype" || overall_rc=1
    done
  fi

  # Explicit endpoints for this host
  if [[ ${#EXTRA_ENDPOINTS[@]} -gt 0 ]]; then
    local line eh ep et
    for line in "${EXTRA_ENDPOINTS[@]}"; do
      set -- $line
      eh="$1"; ep="$2"; et="$3"
      if [[ "$eh" == "$h" ]]; then
        test_one "$h" "$ep" "$et" || overall_rc=1
      fi
    done
  fi
}

# ────────────────────────────────────────────────────────────────────────────
# Orchestration
[[ ${#DOMAINS[@]} -eq 0 && ${#HOSTS[@]} -eq 0 && -z "${SINGLE_HOST:-}" ]] && { usage; exit 1; }

print_header

# If --single-host (internal, used by --parallel) -> bypass MX/domain discovery
if [[ -n "${SINGLE_HOST:-}" ]]; then
  HOSTS=("$SINGLE_HOST")
else
  if ${DO_MX:-false}; then
    for d in "${DOMAINS[@]}"; do
      local_mx=(); readarray_compat local_mx mx_hosts_for_domain "$d"
      if [[ ${#local_mx[@]} -eq 0 ]]; then
        [ "$OUTPUT_FORMAT" = "text" ] && echo -e "\n  ${YELLOW}${WARN} No MX records for ${BOLD}${d}${NC}"
        while IFS= read -r fh; do has_a_record "$fh" && HOSTS+=("$fh"); done < <(fallback_hosts_for_domain "$d")
      else
        if [ "$OUTPUT_FORMAT" = "text" ]; then
          echo
          echo -e "  ${CYAN}Domain:${NC} ${BOLD}${d}${NC}"
          echo -e "  ${DIM}MX Records:${NC}"
          for mx in "${local_mx[@]}"; do
            if is_cloud_managed_host "$mx" && [ "$INCLUDE_CLOUD" = false ]; then
              echo -e "    ${DIM}→ $mx (skipped: cloud provider)${NC}"
            else
              echo -e "    ${DIM}→${NC} $mx"
            fi
          done
        fi
        for mx in "${local_mx[@]}"; do
          if is_cloud_managed_host "$mx" && [ "$INCLUDE_CLOUD" = false ]; then
            continue
          fi
          HOSTS+=("$mx")
        done
      fi
    done
  fi

  if [[ ${#DOMAINS[@]} -gt 0 && ${DO_MX:-false} == false ]]; then
    for d in "${DOMAINS[@]}"; do
      local_mx=(); readarray_compat local_mx mx_hosts_for_domain "$d"
      if [[ ${#local_mx[@]} -gt 0 ]]; then
        for mx in "${local_mx[@]}"; do
          if is_cloud_managed_host "$mx" && [ "$INCLUDE_CLOUD" = false ]; then
            [ "$OUTPUT_FORMAT" = "text" ] && echo -e "    ${DIM}→ $mx (skipped: cloud provider)${NC}"
            continue
          fi
          HOSTS+=("$mx")
        done
      else
        while IFS= read -r fh; do has_a_record "$fh" && HOSTS+=("$fh"); done < <(fallback_hosts_for_domain "$d")
      fi
    done
  fi

  # Add explicit per-host service maps and endpoints (hosts with % override)
  if [[ ${#EXTRA_HOSTS[@]} -gt 0 ]]; then
    for x in "${EXTRA_HOSTS[@]}"; do HOSTS+=("$x"); done
  fi
fi

# Dedup hosts (preserve %maps)
if [[ ${#HOSTS[@]} -gt 0 ]]; then
  HOSTS=($(printf "%s\n" "${HOSTS[@]}" \
    | sed 's/\.$//' \
    | awk 'NF' \
    | dedup_lines))
fi

overall_rc=0
have_hosts=true
[[ ${#HOSTS[@]} -eq 0 ]] && have_hosts=false

# Host Security Checks
if [ "$OUTPUT_FORMAT" = "text" ] && $have_hosts; then
  print_section "Host Security Checks"
fi

if $have_hosts; then
  if [ "$PARALLEL" = true ] && command -v parallel >/dev/null 2>&1; then
    # Build the command as an array to avoid empty-arg bugs on Bash 3
    CMD=( parallel --will-cite -j 4 "$0" --single-host {} )
    [ "$FORCE_V4" = false ] && CMD+=( --ipv6 )
    [ "$DEBUG" -eq 1 ] && CMD+=( --debug )
    CMD+=( --format "$OUTPUT_FORMAT" --services "$SERVICE_MAP" )
    ${CHECK_RELAY} && CMD+=( --check-relay ) || true
    ${VERBOSE} && CMD+=( --verbose ) || true
    ${INCLUDE_CLOUD} && CMD+=( --include-cloud ) || true
    ${NO_DEFAULT_SERVICES} && CMD+=( --no-default-services ) || true
    # pass endpoints down to children — GUARD AGAINST EMPTY
    if [[ ${#RAW_ENDPOINTS[@]} -gt 0 ]]; then
      for r in "${RAW_ENDPOINTS[@]}"; do
        [[ -n "$r" ]] || continue
        CMD+=( --endpoint "$r" )
      done
    fi
    # Separator for input list
    CMD+=( ::: )
    # Hosts
    for h in "${HOSTS[@]}"; do CMD+=( "$h" ); done

    # Execute
    "${CMD[@]}"

    have_hosts=false
  fi
  if $have_hosts; then
    for h in "${HOSTS[@]}"; do
      run_tests "$h"
    done
  fi
fi

# Domain policy checks always run if domains were provided
if [[ ${#DOMAINS[@]} -gt 0 && -z "${SINGLE_HOST:-}" ]]; then
  print_section "Domain Security Policies"
  for d in "${DOMAINS[@]}"; do
    print_subsection "$d"
    check_mta_sts "$d" || true
    check_tls_rpt "$d" || true
    check_spf "$d" || true
    check_dmarc "$d" || true
    check_bimi "$d" || true
    check_arc "$d" || true
    check_caa "$d" || true
    check_dnssec_signals "$d" || true
  done
fi

# Outputs
output_json() {
  echo "{"
  echo "  \"scan_date\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"hosts\": ["
  local first=true; for h in "${HOSTS[@]}"; do
    [ "$first" = false ] && echo ","
    echo -n "    \"${h}\""; first=false
  done; echo
  echo "  ],"
  echo "  \"domains\": ["
  first=true; for d in "${DOMAINS[@]}"; do
    [ "$first" = false ] && echo ","
    echo -n "    \"${d}\""; first=false
  done; echo
  echo "  ],"
  echo "  \"services\": \"$SERVICE_MAP\""
  echo "}"
}
output_csv(){ echo "Host,Port,Service,Status,TLSA,TLS_Versions,Certificate_Days,DNSSEC"; }

case "$OUTPUT_FORMAT" in
  json) output_json;;
  csv) output_csv;;
  text)
    print_footer
    echo
    if [[ $overall_rc -eq 0 ]]; then
      echo -e "  ${GREEN}${OK} Scan complete${NC} - No critical issues found"
    else
      echo -e "  ${YELLOW}${WARN} Scan complete${NC} - Review issues above"
    fi
    echo
    ;;
esac

exit $overall_rc
