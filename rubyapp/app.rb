# rubyapp/app.rb — 취약 gem(nokogiri 등)을 함수에서 사용하는 코드 취약점.
require 'nokogiri' # nokogiri 1.10.4

SECRET_KEY = 'super-secret-rails-key'.freeze # CWE-798

# CWE-502: 신뢰 불가 데이터를 Marshal.load
def load_session(blob)
  Marshal.load(blob)
end

# CWE-95: eval 인젝션
def run_rule(expr)
  eval(expr)
end

# CWE-78: command injection
def backup(name)
  system("tar czf /tmp/#{name}.tgz /data")
end

# CWE-611: Nokogiri NOENT → XXE
def parse_xml(xml)
  Nokogiri::XML(xml) { |c| c.noblanks.noent.dtdload }
end
