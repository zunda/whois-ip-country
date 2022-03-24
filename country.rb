#!/usr/bin/ruby
#
# usage: echo 121.201.107.32 | bundle exec ruby country.rb
#
require 'whois'

whois = Whois::Client.new
ARGF.each do |text|
  next if text =~ /^#/
  ip = text.scan(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/).first
  if ip
    begin
      r = whois.lookup(ip).content
      cidr = r.match(/^(?:route|cidr|inetnum):\s*([\d\.\/]+)/i)[1]
      country = r.match(/^country:\s*(.+)$/i)[1]
      puts "#{ip}\t#{cidr}\t#{country}"
      sleep 1
    rescue NoMethodError
      puts r
    end
  end
end
