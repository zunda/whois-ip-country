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
    r = whois.lookup(ip).content
    cidr = r.scan(/^(?:route|cidr|inetnum):.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+)/i).flatten.first
    country = r.scan(/^country:\s*(.+)$/i).flatten.first
    puts "#{ip}\t#{cidr}\t#{country}"
    sleep 1
  end
end
