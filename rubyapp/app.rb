# rubyapp/app.rb — Rails 컨트롤러 패턴. CodeQL ruby가 ActionController params 를 원격 소스로 인식.
require 'nokogiri'

SECRET_KEY = 'super-secret-rails-key'.freeze # CWE-798

class VulnController < ActionController::Base
  # CWE-95: eval 인젝션
  def run_eval
    eval(params[:expr])
  end

  # CWE-78: command injection (문자열 보간)
  def backup
    system("tar czf /tmp/#{params[:name]}.tgz /data")
  end

  # CWE-502: 신뢰 불가 데이터 Marshal.load
  def load_session
    Marshal.load(params[:blob])
  end

  # CWE-611: Nokogiri NOENT → XXE
  def parse_xml
    Nokogiri::XML(params[:xml]) { |c| c.noblanks.noent.dtdload }.to_s
  end
end
