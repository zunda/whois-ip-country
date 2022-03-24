#!/usr/bin/ruby
#
# usage: echo 121.201.107.32 | bundle exec ruby country.rb
#
require 'whois'

class IPv4Addr
  attr_reader :numeric
  def initialize(decimals)
    @numeric =  decimals.split(/\./).map{|e| Integer(e)}.inject(0){|s, e| s*256 + e}
  end

  def IPv4Addr.numeric(decimals)
    IPv4Addr.new(decimals).numeric
  end

  def IPv4Addr.prefixBits(min, max)
    33 - (IPv4Addr.numeric(min) ^ IPv4Addr.numeric(max)).bit_length
  end
end

re_ipv4 = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
re_inetnum = /(?:route|cidr|inetnum|IPv4 Address)\s*:/

whois = Whois::Client.new
ARGF.each do |text|
  next if text =~ /^#/
  ip = text.scan(re_ipv4).first
  if ip
    r = whois.lookup(ip).content

    # guess address range
    cidr = r.scan(/^#{re_inetnum}.*?(#{re_ipv4}\/\d+)/i).flatten.first
    unless cidr
      min, max = r.scan(/^#{re_inetnum}.*?(#{re_ipv4})\s*-\s*(#{re_ipv4})/i).flatten
      if max
        cidr = "#{min}/#{IPv4Addr.prefixBits(min, max)}"
      end
    end

    # guess country
    country = r.scan(/^country:\s*(.+)$/i).flatten.first
    unless country
      country = "KR" if r =~ /KRNIC/i
    end

    if cidr and country
      puts "#{ip}\t#{cidr}\t#{country}"
    else
      puts r
    end
    sleep 1
  end
end
