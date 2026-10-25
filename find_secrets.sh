#!/bin/bash
# find_secrets.sh - quick hardcoded-secrets triage for APK / IPA / any binary
set -u

OUTPUT="secrets_findings.txt"
URLS_OUT="urls_found.txt"
HTML_OUT=""
USER_EXCLUDE=""
ALL=0

usage() {
  cat <<'EOF'
find_secrets.sh - hardcoded secrets scanner for mobile apps and binaries

USAGE
  ./find_secrets.sh [options] <file.apk | file.ipa | binary>

OPTIONS
  -o <file>   Report output file         (default: secrets_findings.txt)
  -u <file>   Full URL list output file  (default: urls_found.txt)
  -H <file>   Also write an HTML report (dark theme, attention panel, clickable links)
  -x <regex>  Skip files whose path matches this extended regex
              (e.g. -x 'VendorSDK|Frameworks/Realm')
  -a          Disable noise filters (scan third-party libs/SDKs too)
  -h          Show this help

EXAMPLES
  ./find_secrets.sh app.apk
  ./find_secrets.sh -o report.txt -u urls.txt app.ipa
  ./find_secrets.sh -H report.html app.apk
  ./find_secrets.sh -a libnative.so

REPORT SECTIONS
  0. Hits inside the app's own package (only if the package name is detected)
  1. Keyword + assignment + value  (e.g. api_key = "abc12345...")
  2. Known token formats (AWS, Google, Stripe, GitHub, Slack, JWT, PRIVATE KEY)
  3. URLs with embedded credentials (user:pass@host)
  4. Unique HTTP/HTTPS hosts (full URL list goes to the URLs file)

REQUIREMENTS
  bash 4+, unzip, strings, grep, awk, sed, base64  (plutil is optional, used for IPA bundle id)
EOF
}

while getopts ":o:u:H:x:ah" opt; do
  case "$opt" in
    o) OUTPUT="$OPTARG" ;;
    u) URLS_OUT="$OPTARG" ;;
    H) HTML_OUT="$OPTARG" ;;
    x) USER_EXCLUDE="$OPTARG" ;;
    a) ALL=1 ;;
    h) usage; exit 0 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage >&2; exit 1 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage >&2; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

INPUT="${1:-}"

if [ -z "$INPUT" ]; then
  usage
  exit 1
fi
if [ ! -f "$INPUT" ]; then
  echo "File not found: $INPUT" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
ALLSTR="$WORKDIR/all_strings.txt"
extract_dir="$WORKDIR/extracted"
SECDIR="$WORKDIR/sections"
mkdir -p "$extract_dir" "$SECDIR"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

# Well-known native libs / third-party frameworks - skipped by default
EXCLUDE_LIBS_REGEX='lib(c\+\+_shared|ssl|crypto|sqlite|sqlcipher|png|jpeg|webp|gif|yoga|hermes|jsc|v8|fbjni|reactnativejni|flipper|barhopper|gpu|tensorflowlite|mlkit)\.so$|^(GoogleMobileAds|FirebaseCore|FirebaseAnalytics|GoogleUtilities|FBLPromises|GTMSessionFetcher|Realm|SDWebImage|Alamofire|Kingfisher|Lottie|SwiftyJSON)\.framework$'

# Third-party SDK noise that lives INSIDE the same classes.dex/binary
NOISE_REGEX='(Lkotlin|Lkotlinx|Landroidx|Landroid/support|Lcom/google/(android|firebase|gson|protobuf)|Lokhttp3|Lokio|Lretrofit2|Lcom/squareup|Lio/reactivex|Lcom/facebook|Lorg/chromium|Lcom/bumptech/glide|Lcom/airbnb/lottie|Lio/netty|Lio/grpc)/|(^|[^a-zA-Z0-9_.])(kotlin|kotlinx|androidx|com\.google\.(android|firebase|gson|protobuf)|okhttp3|okio|retrofit2|com\.squareup|io\.reactivex|com\.facebook|org\.chromium|com\.bumptech\.glide|com\.airbnb\.lottie|io\.netty|io\.grpc)\.'

# Context that indicates a TLS library (mbedTLS/PolarSSL) - only used to ANNOTATE PRIVATE KEY hits
MBEDTLS_NOISE='TLS-EC(DHE?|DH)-(ECDSA|RSA|PSK)-WITH-|Usage does not match the (extendedKeyUsage|nsCertType) extension|The certificate (is signed with an unacceptable|has expired|has been revoked)'

# XML namespace / license / schema URLs (pure noise)
URL_NOISE='https?://(schemas\.android\.com|schemas\.xmlsoap\.org|www\.w3\.org|www\.apache\.org/licenses|xmlpull\.org|ns\.adobe\.com|java\.sun\.com|www\.apple\.com/DTDs|apache\.org/xml|xml\.org/sax)'

# Values that are placeholders / resource references, not real secrets
PLACEHOLDER='[=:>][[:space:]]*["'"'"']?(@string/|@\{|%[sd@]|\$\{|\{\{)'

if [ "$ALL" -eq 1 ]; then
  EXCLUDE_LIBS_REGEX='^$'
  NOISE_REGEX='^$'
  URL_NOISE='^$'
fi

# Section 0 keywords (broad, but only applied inside the app's own package)
KEYWORDS="secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key|[a-z_]*token|bearer|private[_-]?key|client[_-]?secret|aws[_-]?(access|secret)|firebase|db[_-]?(pass|password)|encryption[_-]?key|signing[_-]?key|jwt|oauth|credential|webhook"

# Section 1: keyword + assignment (= : =>) + value of 8+ chars, or XML <string name="..key..">value</string>
SECRET_NAMES="secret|password|passwd|pwd|api[_-]?key|apikey|access[_-]?key|[a-z0-9_]*token|bearer|private[_-]?key|client[_-]?secret|aws[_-]?(access|secret)[a-z_]*|db[_-]?pass(word)?|encryption[_-]?key|signing[_-]?key|credential"
# Value characters allowed in a "secret-looking" value (no spaces, parens, braces, '?', quotes...)
VALUE_CLASS='[A-Za-z0-9+/_=.@!#$%^&*~-]'
# keyword + (=|:|=>) + value of 8+ chars, and the value must be the END of the string
# (so log lines like "token: success? {}" or "Password: dropping request, ..." do not match)
ASSIGN_REGEX="($SECRET_NAMES)[\"']?[[:space:]]*(=>|=|:)[[:space:]]*[\"']?${VALUE_CLASS}{8,}[\"';,)]*\$"
# ...and the value must contain a digit or a symbol (letters-only values are almost always
# identifiers or log text, e.g. "push token: onPushTokenRegistrationSuccess")
ASSIGN_HASVAL="(=>|=|:)[[:space:]]*[\"']?[A-Za-z_.-]*[0-9+/=@#!\$%^&*~]${VALUE_CLASS}*[\"';,)]*\$"
# Android XML: <string name="..key..">value</string>, value without spaces (UI labels have spaces)
XML_REGEX="name=\"[a-z0-9_.]*($SECRET_NAMES)[a-z0-9_.]*\"[^>]*>[^<[:space:]]{8,}</"
XML_HASVAL=">[^<[:space:]]*[0-9+/=@#!\$%^&*~][^<[:space:]]*</"

# Cleartext-HTTP hosts that are known to be benign: captive-portal / connectivity checks
# (must be HTTP by design) and project/license pages from bundled libraries. Edit as needed.
BENIGN_HTTP_HOSTS='^(captive\.apple\.com|connectivitycheck\.(gstatic|android)\.com|clients3\.google\.com|detectportal\.firefox\.com|www\.msftconnecttest\.com|www\.msftncsi\.com|asm\.ow2\.(io|org)|bytebuddy\.net|www\.gnu\.org|opensource\.org|www\.eclipse\.org|creativecommons\.org|www\.mozilla\.org|www\.slf4j\.org|www\.json\.org)$'

# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------

emit() {
  # usage: <producer> | emit "Section title"
  local title="$1" body n
  body=$(cat)
  n=$(printf '%02d' $(( $(ls "$SECDIR"/*.title 2>/dev/null | wc -l) + 1 )))
  printf '%s' "$title" > "$SECDIR/$n.title"
  printf '%s' "$body"  > "$SECDIR/$n.body"
  {
    echo "### $title ###"
    if [ -n "$body" ]; then printf '%s\n' "$body"; else echo "(none)"; fi
    echo ""
  } >> "$OUTPUT"
}

# ---------------------------------------------------------------------------
# JWT helpers: decode header/payload to tell credentials from signed configs
# ---------------------------------------------------------------------------

b64url_decode() {
  local s="$1"
  s="${s//-/+}"; s="${s//_//}"
  case $(( ${#s} % 4 )) in 2) s="${s}==" ;; 3) s="${s}=" ;; esac
  printf '%s' "$s" | { base64 -d 2>/dev/null || base64 -D 2>/dev/null; }
}

# Annotates lines that contain a JWT with: alg, whether the header carries an x5c certificate
# chain (signed policy/config, not a credential), claim names and expiry. Very long tokens are
# shortened in the displayed line.
annotate_jwt() {
  local line tok hdr pld rest alg claims exp now note short preview
  now=$(date +%s)
  while IFS= read -r line; do
    tok=$(printf '%s' "$line" | grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}(\.[A-Za-z0-9_-]*)?' | head -1)
    if [ -z "$tok" ]; then printf '%s\n' "$line"; continue; fi
    hdr=$(b64url_decode "${tok%%.*}")
    rest="${tok#*.}"
    pld=$(b64url_decode "${rest%%.*}")
    alg=$(printf '%s' "$hdr" | grep -oE '"alg" *: *"[^"]*"' | head -1 | sed -E 's/.*: *"([^"]*)"/\1/')
    note="JWT alg=${alg:-?}"
    if printf '%s' "$hdr" | grep -q '"x5c"'; then
      note="$note, x5c certificate chain: signed JWS (policy/config), not a credential"
    fi
    claims=$(printf '%s' "$pld" | grep -oE '"[A-Za-z0-9_:./-]+" *:' | tr -d '": ' | sort -u | head -12 | paste -sd, -)
    [ -n "$claims" ] && note="$note, claims: $claims"
    if ! printf '%s' "$hdr" | grep -q '"x5c"'; then
      preview=$(printf '%s' "$pld" | tr -d '\r\n\t' | cut -c1-160)
      [ -n "$preview" ] && note="$note, payload: $preview"
    fi
    exp=$(printf '%s' "$pld" | grep -oE '"exp" *: *[0-9]+' | head -1 | grep -oE '[0-9]+$')
    if [ -n "$exp" ]; then
      if [ "$exp" -lt "$now" ] 2>/dev/null; then note="$note, EXPIRED"; else note="$note, not expired"; fi
    fi
    if [ "${#tok}" -gt 300 ]; then
      short="${tok:0:60}...[${#tok} chars]"
      line="${line/"$tok"/$short}"
    fi
    printf '%s  <-- [%s]\n' "$line" "$note"
  done
}

# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

{
  echo "=== Hardcoded Secrets Scan: $INPUT ==="
  echo "Date: $(date)"
  echo ""
} > "$OUTPUT"
: > "$ALLSTR"

PKG=""
FILES=""
case "${INPUT,,}" in
  *.apk)
    echo "[*] APK detected, extracting..." >&2
    unzip -qq -o "$INPUT" -d "$extract_dir"
    FILES=$(find "$extract_dir" \( \
      -name "*.dex" -o \
      \( -path "*/lib/*" -name "*.so" \) -o \
      -path "*/assets/*" -o \
      -path "*/res/*" \
      \) -type f | grep -v -E "/($EXCLUDE_LIBS_REGEX)")
    PKG=$(strings -n 6 "$extract_dir/AndroidManifest.xml" 2>/dev/null | grep -m1 -E '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){2,}$' || true)
    ;;
  *.ipa)
    echo "[*] IPA detected, extracting..." >&2
    unzip -qq -o "$INPUT" -d "$extract_dir"
    FILES=$(find "$extract_dir/Payload" \( \
      \( -path "*.app/*" -type f ! -name "*.png" ! -name "*.storyboardc*" ! -name "*.nib" \) -o \
      -name "*.plist" \
      \) -type f 2>/dev/null | grep -v -E "/($EXCLUDE_LIBS_REGEX)/")
    PLIST=$(find "$extract_dir/Payload" -maxdepth 2 -name "Info.plist" | head -1)
    if [ -n "$PLIST" ]; then
      PKG=$(plutil -extract CFBundleIdentifier raw "$PLIST" 2>/dev/null || strings "$PLIST" | grep -A1 CFBundleIdentifier | tail -1 || true)
    fi
    ;;
  *)
    echo "[*] Generic file, treating it as a single binary" >&2
    FILES="$INPUT"
    ;;
esac

# User-supplied exclusions (-x): drop matching files before extracting strings
if [ -n "$USER_EXCLUDE" ] && [ -n "${FILES:-}" ]; then
  FILES=$(printf '%s\n' "$FILES" | grep -v -E "$USER_EXCLUDE" || true)
fi

[ -n "$PKG" ] && echo "[*] Package/bundle detected: $PKG" >&2

if [ -z "${FILES:-}" ]; then
  echo "[!] No relevant files found to scan." >&2
  echo "No relevant files found inside the package." >> "$OUTPUT"
  exit 0
fi

# Extract strings, prefixing each with its RELATIVE path inside the package
while IFS= read -r f; do
  rel="${f#"$extract_dir"/}"
  [ "$f" = "$INPUT" ] && rel="$(basename "$INPUT")"
  strings -a -n 6 "$f" | sed "s#^#[$rel] #" >> "$ALLSTR"
done <<< "$FILES"

# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

# 0. Hits inside the app's own package
if [ -n "$PKG" ]; then
  PKG_SMALI=$(echo "$PKG" | tr '.' '/')
  grep -E "($PKG|$PKG_SMALI)" "$ALLSTR" | grep -i -E "$KEYWORDS" | sort -u \
    | emit "0. Hits inside the app's own package ($PKG)"
fi

# 1. Keyword + assignment + value
{
  grep -i -E -e "$ASSIGN_REGEX" "$ALLSTR" | grep -i -E -e "$ASSIGN_HASVAL"
  grep -i -E -e "$XML_REGEX" "$ALLSTR" | grep -i -E -e "$XML_HASVAL"
} | grep -v -E "$NOISE_REGEX" \
  | grep -v -i -E "$PLACEHOLDER" \
  | sort -u | emit "1. Keyword + assignment + value (8+ chars)"

# 2. Known token formats + PRIVATE KEY (annotated)
{
  grep -E \
    -e "AKIA[0-9A-Z]{16}" \
    -e "ASIA[0-9A-Z]{16}" \
    -e "AIza[0-9A-Za-z_-]{35}" \
    -e "sk_live_[0-9a-zA-Z]{24,}" \
    -e "sk_test_[0-9a-zA-Z]{24,}" \
    -e "ghp_[0-9a-zA-Z]{36}" \
    -e "github_pat_[0-9a-zA-Z_]{22,}" \
    -e "xox[baprs]-[0-9a-zA-Z-]{10,}" \
    -e "eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}" \
    "$ALLSTR" | grep -v -E "$NOISE_REGEX" | annotate_jwt

  grep -n -E "BEGIN (RSA |EC |DSA )?PRIVATE KEY-----" "$ALLSTR" | while IFS=: read -r lineno _; do
    header=$(sed -n "${lineno}p" "$ALLSTR")
    origin=$(echo "$header" | grep -oE '^\[[^]]+\]')
    ctx=$(sed -n "${lineno},$((lineno+15))p" "$ALLSTR")
    if echo "$ctx" | grep -q -E "$MBEDTLS_NOISE"; then
      echo "$header  <-- [likely mbedTLS/PolarSSL constant, not a real key - confirm manually]"
    elif echo "$ctx" | grep -qE "^\[.*\] *[A-Za-z0-9+/]{40,}"; then
      echo "$header  <-- [WARNING: long base64 body after marker - may be a real key, extract and validate with openssl]"
    else
      echo "$header  <-- [inconclusive, check manually: $origin]"
    fi
  done
} | sort -u | emit "2. Known token formats"

# 3. URLs with embedded credentials
grep -E "https?://[^:/[:space:]]+:[^@/[:space:]]+@" "$ALLSTR" | sort -u \
  | emit "3. URLs with embedded credentials (user:pass@host)"

# Findings count (sections 0-3): report lines that start with an origin marker
TOTAL=$(grep -c '^\[' "$OUTPUT" 2>/dev/null || true)
TOTAL=${TOTAL:-0}

# 4. HTTP/HTTPS: full list -> separate file, unique hosts -> report
URLS_TMP="$WORKDIR/urls.txt"
awk '
BEGIN { pat = "https?://[^] \t\"<>)\047\\\\]+" }
{
  origin = ""
  if (match($0, /^\[[^]]+\]/)) origin = substr($0, RSTART, RLENGTH)
  rest = $0
  while (match(rest, pat)) {
    print origin " " substr(rest, RSTART, RLENGTH)
    rest = substr(rest, RSTART + RLENGTH)
  }
}' "$ALLSTR" \
  | sed -E 's/[.,;:]+$//' \
  | grep -v -E "$URL_NOISE" \
  | sort -u > "$URLS_TMP"

# Triples: host <TAB> url <TAB> file (deduplicated). Only syntactically valid hosts are kept;
# junk like https://token, https://:%d or https://{host} goes to the "invalid" list.
TRIPLES="$WORKDIR/url_triples.txt"
INVALID="$WORKDIR/url_invalid.txt"
: > "$INVALID"
sed -E "s#^\[([^]]*)\] (.*)\$#\1$(printf '\t')\2#" "$URLS_TMP" \
  | awk -F'\t' -v inv="$INVALID" '
    function valid_host(h,   n, parts, i, l, tld) {
      if (h == "" || length(h) > 253) return 0
      if (h == "localhost") return 1
      if (h ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {          # IPv4
        split(h, parts, ".")
        for (i = 1; i <= 4; i++) if (length(parts[i]) > 3 || parts[i] + 0 > 255) return 0
        return 1
      }
      n = split(h, parts, ".")                                 # domain name
      if (n < 2) return 0                                      # "token", "host" -> invalid
      for (i = 1; i <= n; i++) {
        l = parts[i]
        if (length(l) < 1 || length(l) > 63) return 0
        if (l !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) return 0   # no %, {, $, _, spaces...
      }
      tld = parts[n]
      if (tld !~ /^[a-z]+$/ || length(tld) < 2 || length(tld) > 24) return 0
      if (tld ~ bad_tld) return 0                              # file extensions, not TLDs
      return 1
    }
    BEGIN {
      bad_tld = "^(java|kt|kts|class|xml|json|png|jpg|jpeg|gif|webp|svg|dex|js|css|html|htm|txt|properties|plist|smali|cpp|swift|jar|aar|apk|ipa|gz|bin|dat|log|yml|yaml|ttf|otf|woff|mp3|mp4|pdf)$"
    }
    {
      file = $1; url = $2
      match(url, /^https?:\/\//)
      scheme = substr(url, 1, RLENGTH)
      r = substr(url, RLENGTH + 1)
      sub(/^[^\/@]*@/, "", r)                                  # drop user:pass@
      sub(/[\/?#].*$/, "", r)                                  # keep host[:port]
      r = tolower(r)
      if (r ~ /^\[/) {                                         # IPv6 literal
        if (r !~ /^\[[0-9a-f:.]+\]/) { print url "\t" file > inv; next }
        sub(/\].*$/, "]", r); host = r; ok = 1
      } else {
        host = r; sub(/:.*$/, "", host)                        # drop :port
        sub(/\.$/, "", host)                                   # trailing dot
        ok = valid_host(host)
        if (ok && index(r, ":") > 0) {                         # port must be numeric (rejects :%d, :{port})
          port = substr(r, index(r, ":") + 1)
          if (port !~ /^[0-9]+$/ || port + 0 > 65535) ok = 0
        }
      }
      if (ok) print scheme host "\t" url "\t" file
      else    print url "\t" file > inv
    }' \
  | sort -t "$(printf '\t')" -k1,1 -k2,2 -k3,3 -u > "$TRIPLES"

INVALID_COUNT=$(cut -f1 "$INVALID" | sort -u | wc -l | tr -d ' ')

# URL file: grouped by host, each URL once, followed by the files it appears in
{
  echo "# HTTP/HTTPS URLs found in: $INPUT"
  echo "# Grouped by host. Each URL appears once, with the files that contain it."
  echo "# Invalid/placeholder URLs discarded (e.g. https://token, https://:%d): $INVALID_COUNT"
  echo ""
  awk -F'\t' '
    $1 != host { if (NR > 1) print ""; host = $1; print "=== " host " ===" }
    $2 != url  { url = $2; print url }
    { print "    - " $3 }
  ' "$TRIPLES"
} > "$URLS_OUT"

# Report section: one line per host with URL and file counts
awk -F'\t' '
  { if (!(($1 SUBSEP $2) in u)) { u[$1, $2] = 1; nu[$1]++ }
    if (!(($1 SUBSEP $3) in f)) { f[$1, $3] = 1; nf[$1]++ }
    hosts[$1] = 1 }
  END { for (h in hosts) printf "%s  (%d URL%s, %d file%s)\n", h, nu[h], (nu[h]==1?"":"s"), nf[h], (nf[h]==1?"":"s") }
' "$TRIPLES" | sort | emit "4. Unique HTTP/HTTPS hosts (full URLs and files in $URLS_OUT)"

URL_COUNT=$(cut -f2 "$TRIPLES" | sort -u | wc -l | tr -d ' ')
HOST_COUNT=$(cut -f1 "$TRIPLES" | sort -u | wc -l | tr -d ' ')

# ---------------------------------------------------------------------------
# Optional HTML report (-H)
# ---------------------------------------------------------------------------

html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

# Shared awk helpers: HTML-escape + auto-link http(s) URLs
AWK_LIB='
function esc(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); return s }
function linkify(s,   out, rest, url, pat) {
  out = ""; rest = s
  pat = "https?://[^ \t\"<>\047]+"
  while (match(rest, pat)) {
    url = substr(rest, RSTART, RLENGTH)
    while (url ~ /[.,;:)]$/) url = substr(url, 1, length(url) - 1)
    out = out esc(substr(rest, 1, RSTART - 1)) "<a href=\"" esc(url) "\" target=\"_blank\" rel=\"noopener noreferrer\">" esc(url) "</a>"
    rest = substr(rest, RSTART + length(url))
  }
  return out esc(rest)
}
function render_matches(m, cap,   n, parts, i, out, hid) {
  n = split(m, parts, "\037"); out = ""; hid = ""
  for (i = 1; i <= n; i++) {
    if (i <= cap) out = out (i > 1 ? "<br>" : "") linkify(parts[i])
    else hid = hid (i > cap + 1 ? "<br>" : "") linkify(parts[i])
  }
  if (n > cap) out = out "<details class=\"more\"><summary><span class=\"m-closed\">+ " (n - cap) " more</span><span class=\"m-open\">&minus; less</span></summary>" hid "</details>"
  return out
}
'

FINDINGS_RAW="$WORKDIR/findings_raw.tsv"
FINDINGS="$WORKDIR/findings.tsv"
HOST_FLAGS="$WORKDIR/host_flags.tsv"
SECTION_ROWS="$WORKDIR/section_rows.tsv"
TAB="$(printf '\t')"

# Classify everything into: rank, severity, category, origin, match (worst first)
build_findings() {
  local t n title body sec
  : > "$FINDINGS_RAW"
  : > "$HOST_FLAGS"
  : > "$SECTION_ROWS"

  # Sections 0-3 -> severity + category
  for t in "$SECDIR"/*.title; do
    n="${t%.title}"; title=$(cat "$t"); body=$(cat "$n.body")
    case "$title" in
      0.*) sec=0 ;; 1.*) sec=1 ;; 2.*) sec=2 ;; 3.*) sec=3 ;; *) continue ;;
    esac
    { [ -z "$body" ] || [ "$body" = "(none)" ]; } && continue
    printf '%s\n' "$body" | sed -E "s/^\[([^]]*)\] (.*)\$/\1${TAB}\2/" | awk -F'\t' -v sec="$sec" -v sr="$SECTION_ROWS" '
      {
        dup = 0
        origin = $1; m = $0; sub(/^[^\t]*\t/, "", m)
        if (NF < 2) { origin = "-"; m = $0 }
        lm = tolower(m); sev = "medium"; cat = "Finding"
        if (sec == "0") { sev = "low"; cat = "Keyword inside app package" }
        else if (sec == "1") {
          # already reported by section 2 (known token formats): do not list twice
          if (m ~ /(AKIA|ASIA)[0-9A-Z]|AIza|sk_live_|sk_test_|ghp_|github_pat_|xox[baprs]-|eyJ/) dup = 1
          cat = "Secret-like assignment"
          if (lm ~ /(password|passwd|pwd|private[_-]?key|client[_-]?secret|aws[_-]?(access|secret))/) sev = "high"
        }
        else if (sec == "2") {
          if (m ~ /PRIVATE KEY/) {
            if (m ~ /WARNING: long base64/)      { sev = "critical"; cat = "Possible real private key" }
            else if (m ~ /likely mbedTLS/)       { sev = "low";      cat = "Private key marker (TLS library constant)" }
            else                                 { sev = "medium";   cat = "Private key marker (inconclusive)" }
          }
          else if (m ~ /sk_live_/)               { sev = "critical"; cat = "Stripe live secret key" }
          else if (m ~ /(ghp_|github_pat_)/)     { sev = "critical"; cat = "GitHub token" }
          else if (m ~ /(AKIA|ASIA)[0-9A-Z]/)    { sev = "high";     cat = "AWS access key ID" }
          else if (m ~ /AIza/)                   { sev = "high";     cat = "Google API key" }
          else if (m ~ /xox[baprs]-/)            { sev = "high";     cat = "Slack token" }
          else if (m ~ /sk_test_/)               { sev = "medium";   cat = "Stripe test key" }
          else if (m ~ /eyJ/) {
            cl = ""
            if (match(m, /claims: [A-Za-z0-9_:.\/,-]+/)) cl = "," substr(m, RSTART + 8, RLENGTH - 8) ","
            if (m ~ /x5c certificate chain/)  { sev = "low"; cat = "Signed JWS with certificate chain (not a credential)" }
            else if (m ~ /, EXPIRED\]/)       { sev = "low"; cat = "JWT (expired)" }
            else if (cl ~ /,(key|secret|password|passwd|pwd|apikey|api_key|client_secret|access_token|refresh_token|credential),/) { sev = "high"; cat = "JWT carrying a secret-like claim" }
            else                              { sev = "medium"; cat = "JWT" }
          }
          else                                   { cat = "Token pattern" }
        }
        else if (sec == "3") { sev = "high"; cat = "Credentials embedded in URL" }
        o2 = origin; sub(/^lib\/(arm64-v8a|armeabi-v7a|armeabi|x86_64|x86|mips64|mips)\//, "lib/*/", o2)
        print sec "\t" sev "\t" cat "\t" o2 "\t" m >> sr
        if (!dup) print sev "\t" cat "\t" origin "\t" m
      }' >> "$FINDINGS_RAW"
  done

  # Hosts -> internal / non-prod / cleartext HTTP (known-benign cleartext hosts are skipped,
  # loopback/localhost is ignored: hybrid apps use https://localhost/ to serve bundled assets)
  if [ -s "$TRIPLES" ]; then
    BENIGN="$BENIGN_HTTP_HOSTS" awk -F'\t' -v ff="$HOST_FLAGS" '
      function emit(sev, cat, host, origin, m) {
        print sev "\t" cat "\t" origin "\t" m
        print host "\t" sev "\t" cat > ff
      }
      BEGIN { benign = ENVIRON["BENIGN"] }
      {
        if (!($1 in firstfile)) { firstfile[$1] = $3; firsturl[$1] = $2 }
        if ($2 ~ /^http:\/\// && !($1 in httpurl)) { httpurl[$1] = $2; httpfile[$1] = $3 }
      }
      END {
        for (host in firstfile) {
          h = host; sub(/^https?:\/\//, "", h)
          if (h == "localhost" || h ~ /^127\./) continue
          if (h ~ /^(10\.|192\.168\.|169\.254\.)/ || h ~ /^172\.(1[6-9]|2[0-9]|3[01])\./)
            emit("medium", "Internal/private address", host, firstfile[host], firsturl[host])
          else if (h ~ /(^|[.-])(dev|stg|stage|staging|test|qa|uat|sandbox|internal|intranet|admin|preprod|beta|corp|lan)([.-]|$)/ || h ~ /\.(local|internal|corp|lan|intranet)$/)
            emit("medium", "Non-production or internal-looking host", host, firstfile[host], firsturl[host])
          if ((host in httpurl) && h !~ benign)
            emit("medium", "Cleartext HTTP endpoint", host, httpfile[host], httpurl[host])
        }
      }' "$TRIPLES" >> "$FINDINGS_RAW"
  fi

  # Group duplicates: same finding across files/ABIs -> one row; noisy categories -> one row
  # listing every match. Matches are joined with \037 (rendered as separate lines in HTML).
  sort -t "$TAB" -k2,2 -k4,4 "$FINDINGS_RAW" | awk -F'\t' '
    BEGIN { OFS = "\t" }
    {
      sev = $1; cat = $2; origin = $3
      m = $0; for (i = 1; i <= 3; i++) sub(/^[^\t]*\t/, "", m)
      sub(/^lib\/(arm64-v8a|armeabi-v7a|armeabi|x86_64|x86|mips64|mips)\//, "lib/*/", origin)
      col = (cat == "Private key marker (TLS library constant)" || cat == "Signed JWS with certificate chain (not a credential)" || cat == "Cleartext HTTP endpoint" || cat == "Internal/private address" || cat == "Non-production or internal-looking host")
      gk = col ? (sev SUBSEP cat) : (sev SUBSEP cat SUBSEP m)
      if (!(gk in idx)) { idx[gk] = ++ng; gsev[ng] = sev; gcat[ng] = cat; gcol[ng] = col; gm[ng] = m }
      g = idx[gk]
      if (!((g SUBSEP origin) in so)) { so[g SUBSEP origin] = 1; no[g]++; orig[g, no[g]] = origin }
      if (col && !((g SUBSEP m) in sm)) { sm[g SUBSEP m] = 1; nm[g]++; mt[g, nm[g]] = m }
    }
    END {
      for (g = 1; g <= ng; g++) {
        o = ""
        for (i = 1; i <= no[g]; i++) o = o (i > 1 ? "\037" : "") orig[g, i]
        m = gm[g]; cat = gcat[g]
        if (gcol[g]) {
          m = ""
          for (i = 1; i <= nm[g]; i++) m = m (i > 1 ? "\037" : "") mt[g, i]
          if (nm[g] > 1) cat = cat " x" nm[g]
        }
        print gsev[g], cat, o, m
      }
    }' > "$FINDINGS_RAW.grouped"

  awk -F'\t' 'BEGIN { r["critical"]=0; r["high"]=1; r["medium"]=2; r["low"]=3 } { print r[$1] "\t" $0 }' "$FINDINGS_RAW.grouped" \
    | sort -s -t "$TAB" -k1,1n -k3,3 -k5,5 > "$FINDINGS"

  # Per-section rows (ungrouped, as in the text report): rank, sec, sev, cat, origin, match
  awk -F'\t' 'BEGIN { r["critical"]=0; r["high"]=1; r["medium"]=2; r["low"]=3 } { print r[$2] "\t" $0 }' "$SECTION_ROWS" \
    | sort -s -t "$TAB" -k2,2n -k1,1n -k6,6 | awk '!seen[$0]++' > "$SECTION_ROWS.ranked"
  mv "$SECTION_ROWS.ranked" "$SECTION_ROWS"
}

alert_items() {
  awk -F'\t' "$AWK_LIB"'
    {
      m = $0; for (i = 1; i <= 4; i++) sub(/^[^\t]*\t/, "", m)
      printf "<li class=\"alert-item\"><span class=\"sev sev-%s\">%s</span><strong>%s</strong><div class=\"alert-origin\">%s</div><div class=\"alert-match\">%s</div></li>\n", $2, toupper($2), esc($3), render_matches($4, 2), render_matches(m, 4)
    }'
}

cnt() { awk -F'\t' -v s="$1" '$2 == s { n++ } END { print n + 0 }' "$FINDINGS"; }

render_html() {
  build_findings
  local crit high med low total esc_in worst cls head
  crit=$(cnt critical); high=$(cnt high); med=$(cnt medium); low=$(cnt low)
  total=$((crit + high + med + low))
  esc_in=$(printf '%s' "$INPUT" | html_escape)

  {
    cat <<'HTML_HEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Hardcoded Secrets Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Lato:wght@300;400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet"/>
<style>
  :root {
    --bg:#031B26; --surface:#01161E; --surface2:#063348; --border:#0a4a63;
    --teal:#004E63; --teal-lt:#006b87; --red:#D32027; --red-dk:#a81820;
    --orange:#e07b00; --green:#00a878;
    --text:#cdd9e0; --text-dim:#7a9aaa; --muted:#3d6070;
    --hot:rgba(211,32,39,.08); --radius:5px;
    color-scheme: dark;
  }
  *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font-family:'Lato',system-ui,-apple-system,"Segoe UI",sans-serif; font-size:13px; line-height:1.6; min-height:100vh; }
  a { color:var(--teal-lt); text-decoration:none; transition:color .15s; }
  a:hover { color:#fff; text-decoration:underline; }
  code, .mono { font-family:'Share Tech Mono',ui-monospace,Menlo,Consolas,monospace; }

  /* header */
  .header { background:linear-gradient(160deg,#020f18 0%,var(--teal) 100%); border-bottom:3px solid var(--red); padding:36px 48px 28px; position:relative; overflow:hidden; }
  .header::before { content:""; position:absolute; inset:0; background:repeating-linear-gradient(0deg,transparent,transparent 39px,rgba(0,78,99,.15) 40px),repeating-linear-gradient(90deg,transparent,transparent 39px,rgba(0,78,99,.15) 40px); pointer-events:none; }
  .header::after { content:""; position:absolute; right:-60px; top:-60px; width:320px; height:320px; border-radius:50%; background:radial-gradient(circle,rgba(211,32,39,.18) 0%,transparent 70%); pointer-events:none; }
  .header-inner { position:relative; z-index:1; }
  .logo { font-size:11px; letter-spacing:.22em; text-transform:uppercase; color:rgba(255,255,255,.55); margin-bottom:8px; font-family:'Share Tech Mono',monospace; }
  h1 { font-size:42px; font-weight:900; color:#fff; letter-spacing:-1px; line-height:1; text-transform:uppercase; }
  h1 .red { color:var(--red); }
  .subtitle { font-size:12px; color:rgba(255,255,255,.45); margin-top:8px; font-family:'Share Tech Mono',monospace; letter-spacing:.04em; }
  .subtitle a { color:rgba(255,255,255,.65); border-bottom:1px solid rgba(255,255,255,.2); padding-bottom:1px; }
  .subtitle a:hover { color:#fff; border-color:#fff; text-decoration:none; }

  /* attention panel */
  .alert { margin:0 48px 8px; border:1px solid var(--border); border-left:5px solid var(--muted); border-radius:var(--radius); background:var(--surface); padding:16px 20px; }
  .alert-danger { border-left-color:var(--red); background:linear-gradient(90deg,rgba(211,32,39,.14),var(--surface) 55%); border-color:rgba(211,32,39,.5); }
  .alert-warn   { border-left-color:var(--orange); background:linear-gradient(90deg,rgba(224,123,0,.12),var(--surface) 55%); }
  .alert-ok     { border-left-color:var(--green); background:linear-gradient(90deg,rgba(0,168,120,.12),var(--surface) 55%); }
  .alert-title { font-size:15px; font-weight:900; color:#fff; letter-spacing:.02em; text-transform:uppercase; }
  .alert-sub { color:var(--text-dim); font-size:12px; margin-top:2px; }
  .alert-list { list-style:none; margin-top:12px; }
  .alert-item { padding:8px 0; border-top:1px solid rgba(10,74,99,.6); }
  .alert-item strong { color:#fff; margin:0 8px 0 6px; }
  .alert-origin { color:var(--text-dim); font-family:'Share Tech Mono',monospace; font-size:11px; }
  .alert-match { font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--text); margin-top:3px; word-break:break-all; }
  .alert-more { margin-top:8px; color:var(--text-dim); font-size:12px; }

  /* stat cards */
  .stats { display:flex; gap:16px; padding:24px 48px; flex-wrap:wrap; }
  .stat-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:18px 24px; min-width:140px; flex:1; position:relative; overflow:hidden; }
  .stat-card::before { content:""; position:absolute; top:0; left:0; right:0; height:3px; background:var(--border); }
  .stat-card.teal::before { background:var(--teal-lt); }
  .stat-card.danger::before { background:var(--red); }
  .stat-card.warn::before { background:var(--orange); }
  .stat-card.neutral::before { background:var(--muted); }
  .stat-label { font-size:10px; text-transform:uppercase; letter-spacing:.18em; color:var(--text-dim); font-weight:700; }
  .stat-value { font-size:46px; font-weight:900; color:#fff; line-height:1; margin-top:6px; letter-spacing:-2px; }
  .stat-card.teal .stat-value { color:var(--teal-lt); }
  .stat-card.danger .stat-value { color:var(--red); }
  .stat-card.warn .stat-value { color:var(--orange); }

  /* section titles + toolbar */
  .sec-title { padding:8px 48px 10px; font-size:12px; font-weight:900; letter-spacing:.2em; text-transform:uppercase; color:var(--teal-lt); }
  .sec-note { padding:0 48px 10px; color:var(--text-dim); font-size:12px; }
  .toolbar { padding:0 48px 18px; display:flex; gap:10px; flex-wrap:wrap; align-items:center; border-bottom:1px solid var(--border); }
  .filter-btn { background:var(--surface); border:1px solid var(--border); color:var(--text-dim); padding:6px 16px; border-radius:20px; cursor:pointer; font-size:11px; font-family:'Lato',sans-serif; font-weight:700; letter-spacing:.06em; text-transform:uppercase; transition:all .15s; }
  .filter-btn:hover { border-color:var(--teal-lt); color:#fff; }
  .filter-btn.active { background:var(--teal); border-color:var(--teal-lt); color:#fff; }
  .filter-btn.active-danger { background:var(--red-dk); border-color:var(--red); color:#fff; }
  #search { margin-left:auto; background:var(--surface); border:1px solid var(--border); color:var(--text); padding:7px 14px; border-radius:var(--radius); font-size:12px; font-family:'Lato',sans-serif; width:260px; outline:none; transition:border .15s; }
  #search:focus { border-color:var(--teal-lt); }
  #search::placeholder { color:var(--muted); }

  /* findings table */
  .table-wrap { padding:16px 48px 24px; overflow-x:auto; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  thead tr { background:var(--surface2); border-bottom:2px solid var(--teal); }
  th { padding:11px 12px; text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.14em; color:var(--teal-lt); font-weight:700; white-space:nowrap; }
  td { padding:10px 12px; border-bottom:1px solid rgba(10,74,99,.5); vertical-align:top; }
  tr:hover td { background:rgba(0,78,99,.12); }
  .row-hot td { background:var(--hot); }
  .row-hot:hover td { background:rgba(211,32,39,.14); }
  .td-mono { font-family:'Share Tech Mono',monospace; color:var(--text-dim); font-size:11px; word-break:break-all; max-width:240px; }
  .td-match { font-family:'Share Tech Mono',monospace; font-size:11px; word-break:break-all; color:var(--text); }
  tr.hidden, details.hidden { display:none; }
  .empty { padding:18px 48px; color:var(--text-dim); font-style:italic; }

  /* severity badges */
  .sev { display:inline-block; padding:2px 9px; border-radius:3px; font-size:9px; font-weight:700; letter-spacing:.12em; text-transform:uppercase; white-space:nowrap; }
  .sev-critical { background:var(--red); color:#fff; }
  .sev-high { background:rgba(211,32,39,.22); color:#f07070; border:1px solid rgba(211,32,39,.45); }
  .sev-medium { background:rgba(224,123,0,.18); color:var(--orange); border:1px solid rgba(224,123,0,.4); }
  .sev-low { background:rgba(61,96,112,.35); color:var(--text-dim); }

  /* hosts */
  .hosts { padding:12px 48px 48px; }
  details.group { margin:8px 48px; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); }
  details.group > summary { cursor:pointer; padding:12px 16px; display:flex; align-items:center; gap:12px; list-style:none; }
  details.group > summary::-webkit-details-marker { display:none; }
  .gtoggle { width:22px; height:22px; flex:none; display:inline-flex; align-items:center; justify-content:center; border:1px solid var(--border); border-radius:4px; background:var(--surface2); color:var(--teal-lt); font:700 15px/1 'Share Tech Mono',monospace; }
  .gtoggle::before { content:"+"; }
  details.group[open] > summary .gtoggle::before { content:"\2212"; }
  details.group > summary:hover .gtoggle { border-color:var(--teal-lt); color:#fff; }
  details.more { display:block; margin-top:4px; }
  details.more > summary { cursor:pointer; display:inline-block; list-style:none; font-size:11px; font-weight:700; color:var(--teal-lt); border:1px solid var(--border); border-radius:999px; padding:1px 10px; }
  details.more > summary::-webkit-details-marker { display:none; }
  details.more > summary:hover { color:#fff; border-color:var(--teal-lt); }
  details.more .m-open { display:none; }
  details.more[open] .m-open { display:inline; }
  details.more[open] .m-closed { display:none; }
  details.more[open] > summary { margin-bottom:6px; }
  details.more.more-block { margin-top:10px; }
  .group-title { font-size:12px; font-weight:900; letter-spacing:.06em; text-transform:uppercase; color:var(--teal-lt); }
  details.group .table-wrap { padding:0 16px 16px; }
  details.group .sec-note, details.group .empty { padding-left:16px; padding-right:16px; }
  .hosts-inner { padding:4px 16px 16px; }
  .host-search { display:block; width:100%; max-width:320px; margin:0 0 8px; background:var(--bg); border:1px solid var(--border); color:var(--text); padding:7px 14px; border-radius:var(--radius); font-size:12px; font-family:'Lato',sans-serif; outline:none; }
  .host-search:focus { border-color:var(--teal-lt); }
  .host-search::placeholder { color:var(--muted); }
  details.host { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); margin:6px 0; padding:8px 14px; }
  details.host[open] { border-color:var(--teal-lt); }
  details.host summary { cursor:pointer; display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  details.host summary a { font-family:'Share Tech Mono',monospace; color:#fff; font-size:12px; }
  .badge { font-size:10px; font-weight:700; padding:2px 9px; border-radius:999px; border:1px solid var(--border); background:var(--surface2); color:var(--text-dim); }
  .url { margin:10px 0 0 4px; }
  .url a { font-family:'Share Tech Mono',monospace; font-size:11px; word-break:break-all; }
  .url ul { margin:4px 0 0; padding-left:22px; color:var(--text-dim); font-size:11px; font-family:'Share Tech Mono',monospace; }

  .footer { text-align:center; padding:24px 48px; font-size:11px; color:var(--muted); letter-spacing:.04em; border-top:1px solid var(--border); }
  .footer a { color:var(--text-dim); border-bottom:1px solid var(--muted); padding-bottom:1px; }
  @media (max-width:700px) { .header,.stats,.alert,.table-wrap,.hosts,.toolbar,.sec-title,.sec-note,details.group { padding-left:18px; padding-right:18px; margin-left:0; margin-right:0; } .alert { margin:0 18px 8px; } h1 { font-size:30px; } #search { width:100%; margin-left:0; } }
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="logo">&#9632; Secure Ideas · Professionally Evil</div>
    <h1>Hardcoded <span class="red">Secrets</span> Scanner</h1>
HTML_HEAD
    printf '    <div class="subtitle">Mobile Binary Secrets &amp; Endpoint Report &nbsp;·&nbsp; <span>%s</span> &nbsp;·&nbsp; %s &nbsp;·&nbsp;\n' \
      "$esc_in" "$(date | html_escape)"
    cat <<'HTML_SUB'
      <a href="https://www.linkedin.com/in/jordan-bonagura" target="_blank" rel="noopener noreferrer">Jordan Bonagura</a>
      &nbsp;·&nbsp;
      <a href="https://www.secureideas.com" target="_blank" rel="noopener noreferrer">Secure Ideas - Professionally Evil</a>
    </div>
  </div>
</div>
HTML_SUB

    # ---- Stat cards ----
    printf '<div class="stats">\n'
    printf '  <div class="stat-card danger"><div class="stat-label">Critical</div><div class="stat-value">%s</div></div>\n' "$crit"
    printf '  <div class="stat-card danger"><div class="stat-label">High</div><div class="stat-value">%s</div></div>\n' "$high"
    printf '  <div class="stat-card warn"><div class="stat-label">Medium</div><div class="stat-value">%s</div></div>\n' "$med"
    printf '  <div class="stat-card neutral"><div class="stat-label">Low</div><div class="stat-value">%s</div></div>\n' "$low"
    printf '</div>\n'

    # ---- Attention panel (top) ----
    if [ "$total" -gt 0 ]; then
      worst=$(head -1 "$FINDINGS" | cut -f2)
      case "$worst" in
        critical|high) cls="alert-danger"; head="&#9888; Needs attention" ;;
        *)             cls="alert-warn";   head="Review recommended" ;;
      esac
      printf '<div class="alert %s"><div class="alert-title">%s</div>\n' "$cls" "$head"
      printf '<div class="alert-sub">%s critical &middot; %s high &middot; %s medium &middot; %s low &mdash; worst first</div>\n<ul class="alert-list">\n' \
        "$crit" "$high" "$med" "$low"
      head -10 "$FINDINGS" | alert_items
      echo '</ul>'
      if [ "$total" -gt 10 ]; then
        printf '<details class="more more-block"><summary><span class="m-closed">+ %s more</span><span class="m-open">&minus; less</span></summary><ul class="alert-list">\n' "$((total - 10))"
        tail -n +11 "$FINDINGS" | alert_items
        echo '</ul></details>'
      fi
      echo '</div>'
    else
      echo '<div class="alert alert-ok"><div class="alert-title">&#10003; No findings</div><div class="alert-sub">Nothing matched the secret, token or endpoint rules. This is triage, not proof of absence.</div></div>'
    fi

    # ---- Findings table ----
    echo '<div class="sec-title">All findings (merged, worst first)</div>'
    if [ "$total" -gt 0 ]; then
      cat <<'HTML_TOOLBAR'
<div class="toolbar">
  <button class="filter-btn active" onclick="setSev('all',this)">All</button>
  <button class="filter-btn" onclick="setSev('critical',this)">Critical</button>
  <button class="filter-btn" onclick="setSev('high',this)">High</button>
  <button class="filter-btn" onclick="setSev('medium',this)">Medium</button>
  <button class="filter-btn" onclick="setSev('low',this)">Low</button>
  <input id="search" type="text" placeholder="Search all findings…" oninput="setQuery(this.value)"/>
</div>
<div class="table-wrap">
  <table id="findings">
    <thead><tr><th>Severity</th><th>Category</th><th>Origin file</th><th>Match</th></tr></thead>
    <tbody>
HTML_TOOLBAR
      awk -F'\t' "$AWK_LIB"'
        {
          m = $0; for (i = 1; i <= 4; i++) sub(/^[^\t]*\t/, "", m)
          hot = ($2 == "critical" || $2 == "high") ? " row-hot" : ""
          printf "<tr class=\"frow%s\" data-sev=\"%s\"><td><span class=\"sev sev-%s\">%s</span></td><td>%s</td><td class=\"td-mono\">%s</td><td class=\"td-match\">%s</td></tr>\n", hot, $2, $2, toupper($2), esc($3), render_matches($4, 3), render_matches(m, 25)
        }' "$FINDINGS"
      echo '    </tbody></table></div>'
      echo '<div id="no-match" class="empty" style="display:none">No findings match this filter. Click <strong>All</strong> to see everything.</div>'
    else
      echo '<div class="empty">(none)</div>'
    fi

    # ---- By group (same sections as the text report) ----
    echo '<div class="sec-title">Findings by group</div>'
    for t in "$SECDIR"/*.title; do
      n="${t%.title}"; title=$(cat "$t")
      case "$title" in
        0.*) gsec=0 ;; 1.*) gsec=1 ;; 2.*) gsec=2 ;; 3.*) gsec=3 ;; 4.*) gsec=4 ;; *) continue ;;
      esac
      gtitle=$(printf '%s' "$title" | html_escape)

      if [ "$gsec" != 4 ]; then
        gcount=$(awk -F'\t' -v s="$gsec" '$2 == s { n++ } END { print n + 0 }' "$SECTION_ROWS")
        printf '<details class="group" id="g%s"><summary><span class="gtoggle"></span><span class="group-title">%s</span> <span class="badge">%s</span></summary>\n' "$gsec" "$gtitle" "$gcount"
        if [ "$gcount" -gt 0 ]; then
          awk -F'\t' -v s="$gsec" "$AWK_LIB"'
            BEGIN {
              printf "<div class=\"table-wrap\"><table><thead><tr><th>Severity</th>%s<th>Origin file</th><th>Match</th></tr></thead><tbody>\n", (s == 2 ? "<th>Category</th>" : "")
            }
            $2 == s {
              m = $0; for (i = 1; i <= 5; i++) sub(/^[^\t]*\t/, "", m)
              hot = ($3 == "critical" || $3 == "high") ? " row-hot" : ""
              catcell = (s == 2) ? "<td>" esc($4) "</td>" : ""
              printf "<tr class=\"frow%s\" data-sev=\"%s\"><td><span class=\"sev sev-%s\">%s</span></td>%s<td class=\"td-mono\">%s</td><td class=\"td-match\">%s</td></tr>\n", hot, $3, $3, toupper($3), catcell, esc($5), linkify(m)
            }
            END { print "</tbody></table></div>" }
          ' "$SECTION_ROWS"
        else
          echo '<div class="empty">(none)</div>'
        fi
        echo '</details>'
      else
        printf '<details class="group" id="g4"><summary><span class="gtoggle"></span><span class="group-title">%s</span> <span class="badge">%s</span></summary>\n' "$gtitle" "$HOST_COUNT"
        echo '<div class="sec-note">Each URL appears once, with the files that contain it. Links open the live URL: only follow them for targets you are authorized to test.</div>'
        echo '<div class="hosts-inner"><input class="host-search" type="text" placeholder="Filter hosts / URLs / files…" oninput="filterHosts(this.value)"/>'
        if [ -s "$TRIPLES" ]; then
          awk -F'\t' -v flags="$HOST_FLAGS" "$AWK_LIB"'
            BEGIN {
              while ((getline line < flags) > 0) {
                split(line, a, "\t")
                tag[a[1]] = tag[a[1]] "<span class=\"sev sev-" a[2] "\">" esc(a[3]) "</span>"
              }
            }
            NR==FNR { if (!(($1 SUBSEP $2) in seen)) { seen[$1 SUBSEP $2] = 1; nu[$1]++ } next }
            $1 != host {
              if (host != "") print "</ul></div></details>"
              host = $1; url = ""
              printf "<details class=\"host\"><summary><a href=\"%s\" target=\"_blank\" rel=\"noopener noreferrer\">%s</a> <span class=\"badge\">%d URL%s</span> %s</summary>\n", esc(host), esc(host), nu[host], (nu[host] == 1 ? "" : "s"), tag[host]
            }
            $2 != url {
              if (url != "") print "</ul></div>"
              url = $2
              printf "<div class=\"url\"><a href=\"%s\" target=\"_blank\" rel=\"noopener noreferrer\">%s</a><ul>\n", esc(url), esc(url)
            }
            { printf "<li>%s</li>\n", esc($3) }
            END { if (host != "") print "</ul></div></details>" }
          ' "$TRIPLES" "$TRIPLES"
        else
          echo '<div class="empty" style="padding-left:0">(none)</div>'
        fi
        echo '</div></details>'
      fi
    done

    cat <<'HTML_FOOT'
<div class="footer">
  Generated by find_secrets.sh &nbsp;&middot;&nbsp;
  <a href="https://www.linkedin.com/in/jordan-bonagura" target="_blank" rel="noopener noreferrer">Jordan Bonagura</a>
  &nbsp;&middot;&nbsp;
  <a href="https://www.secureideas.com" target="_blank" rel="noopener noreferrer">Secure Ideas - Professionally Evil</a>
</div>

<script>
  // Severity buttons + search act ONLY on the merged "All findings" table.
  // The "Findings by group" tables always show every row (the badge count = rows shown).
  let sevFilter = 'all', query = '';
  function applyFilters() {
    let visible = 0;
    document.querySelectorAll('#findings tbody tr.frow').forEach(r => {
      const okSev = sevFilter === 'all' || r.dataset.sev === sevFilter;
      const okQ = !query || r.textContent.toLowerCase().includes(query);
      const show = okSev && okQ;
      r.classList.toggle('hidden', !show);
      if (show) visible++;
    });
    const nm = document.getElementById('no-match');
    if (nm) nm.style.display = visible === 0 ? 'block' : 'none';
  }
  function setSev(s, btn) {
    sevFilter = s;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active', 'active-danger'));
    btn.classList.add(s === 'critical' || s === 'high' ? 'active-danger' : 'active');
    applyFilters();
  }
  function setQuery(v) { query = v.toLowerCase(); applyFilters(); }
  // Group 4 has its own small filter for hosts / URLs / files
  function filterHosts(v) {
    v = v.toLowerCase();
    document.querySelectorAll('details.host').forEach(d => {
      const hide = !!v && !d.textContent.toLowerCase().includes(v);
      d.classList.toggle('hidden', hide);
      if (v && !hide) d.open = true;
    });
  }
</script>
</body>
</html>
HTML_FOOT
  } > "$HTML_OUT"
}

if [ -n "$HTML_OUT" ]; then
  render_html
fi

echo ""
echo "Report saved to:   $OUTPUT"
echo "URL list saved to: $URLS_OUT"
[ -n "$HTML_OUT" ] && echo "HTML report saved to: $HTML_OUT"
echo "Findings (sections 0-3): $TOTAL"
echo "URLs: $URL_COUNT valid and unique across $HOST_COUNT hosts ($INVALID_COUNT invalid discarded)"
