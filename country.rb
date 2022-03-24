#!/usr/bin/ruby
#
# usage: echo 121.201.107.32 | bundle exec ruby country.rb
#
require 'whois'

whois = Whois::Client.new
ARGF.each do |ip|
  ip.strip!
  r = whois.lookup(ip)
  cidr = r.match(/^route:\s*([\d\.\/]+)/i)[1]
  country = r.match(/^country:\s*(.+)$/i)[1]
  puts "#{ip}\t#{cidr}\t#{country}"
end
