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

  def IPv4Addr.cidr(min, max)
    x = IPv4Addr.numeric(min)
    y = IPv4Addr.numeric(max)
    x, y = y, x if x > y
    prefix = 32 - (x ^ y).bit_length
    "#{min}/#{prefix}"
  end
end

class WhoisCountries
  RE_ipv4 = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
  RE_inetnum = /(?:route|cidr|inetnum|IPv4 Address|NetRange)\s*:/i

  def initialize
    @whois = Whois::Client.new
    @cache = Hash.new
  end

  def country_for(ip)
    x = IPAddr.new(ip)
    y = @cache.keys.detect{|cidr| cidr.include?(x)}
    return @cache[y] if y

    # lookup
    r = @whois.lookup(ip).content

    # guess address range
    min, max = r.scan(/^#{RE_inetnum}.*?(#{RE_ipv4})\s*-\s*(#{RE_ipv4})/i).flatten
    if max
      cidr = IPv4Addr.cidr(min, max)
    else
      cidr = r.scan(/^#{RE_inetnum}.*?(#{RE_ipv4}\/\d+)/i).flatten.first
    end
    unless cidr
      raise RuntimeError, "CIDR not found from the whois response for #{ip}\n#{r}"
    end

    # guess country
    country = r.scan(/NetName:\s*PRIVATE-ADDRESS-.*(RFC\d+)/i).flatten.first
    unless country
      c = r.scan(/^country:\s*(\w{2})$/i).flatten
      country = c.reject{|e| e == "EU"}.first || c.detect{|e| e == "EU"}
    end
    unless country
      country = "KR" if r =~ /KRNIC/i
    end
    unless cidr
      raise RuntimeError, "Country not found from the whois response for #{ip}\n#{r}"
    end

    @cache[IPAddr.new(cidr)] = country.upcase
    return country
  end
end

w = WhoisCountries.new
ARGF.each do |text|
  next if text =~ /^#/
  ip = text.scan(WhoisCountries::RE_ipv4).first
  if ip
    begin
      puts "#{ip}\t#{w.country_for(ip)}"
    rescue Timeout::Error
      $stderr.puts "Timed out looking up whois for #{ip}"
    rescue Errno::ECONNREFUSED, RuntimeError
      $stderr.puts $!.message
    end
  end
end
