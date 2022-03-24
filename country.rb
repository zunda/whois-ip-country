#!/usr/bin/ruby
#
# usage: echo 121.201.107.32 | bundle exec ruby country.rb
#
require 'whois'
require 'netaddr'

whois = Whois::Client.new
ARGF.each do |text|
  next if text =~ /^#/
  ip = text.scan(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/).first
  if ip
    r = whois.lookup(ip).content
    cidr = r.scan(/^(?:route|cidr|inetnum):.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+)/i).flatten.first
    unless cidr
      min, max = r.scan(/^(?:route|cidr|inetnum):.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*-\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i).flatten
      if max
        cidr = NetAddr.merge(NetAddr.range(min, max, Inclusive: true, Objectify: true)).first
      end
    end
    country = r.scan(/^country:\s*(.+)$/i).flatten.first

    if cidr and country
      puts "#{ip}\t#{cidr}\t#{country}"
    else
      puts r
    end
    sleep 1
  end
end
