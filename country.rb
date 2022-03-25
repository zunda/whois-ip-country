#!/usr/bin/ruby
#
# usage: echo 8.8.8.8 | bundle exec ruby country.rb
# looks up whois for IPv4 addresses to find registered country
#
# Copyright (c) 2022 zunda <zundan at gmail.com>
# Published under MIT license
#
require 'whois'

class IPv4Cidr
  def initialize(min, prefix_length)
    @min = min
    @prefix_length = Integer(prefix_length)
  end

  def to_s
    return "#{@min}/#{@prefix_length}"
  end

  def include?(decimals)
    p = 32 - (IPv4Cidr.numeric(@min) ^ IPv4Cidr.numeric(decimals)).bit_length
    return @prefix_length <= p
  end

  def IPv4Cidr.numeric(decimals)
    return decimals.split(/\./).map{|e| Integer(e)}.inject(0){|s, e| s*256 + e}
  end

  def IPv4Cidr.cidr(min, max)
    x = IPv4Cidr.numeric(min)
    y = IPv4Cidr.numeric(max)
    x, y = y, x if x > y
    p = 32 - (x ^ y).bit_length
    return IPv4Cidr.new(min, p)
  end
end

class WhoisCountries
  RE_ipv4 = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
  RE_inetnum = /(?:route|cidr|inetnum|IPv4 Address|NetRange)\s*:/i

  def initialize
    @whois = Whois::Client.new
    @cache = Hash.new
    @wait = 1 # sec
  end

  def country_for(ip)
    x = @cache.keys.detect{|cidr| cidr.include?(ip)}
    return @cache[x] if x

    # lookup
    r = @whois.lookup(ip).content
    sleep @wait

    # guess address range
    min, max = r.scan(/^#{RE_inetnum}.*?(#{RE_ipv4})\s*-\s*(#{RE_ipv4})/i).flatten
    if max
      cidr = IPv4Cidr.cidr(min, max)
    else
      cidr = IPv4Cidr.new(*r.scan(/^#{RE_inetnum}.*?(?:(#{RE_ipv4})\/(\d+))/i).first)
    end
    unless cidr
      raise RuntimeError, "CIDR not found from the whois response for #{ip}\n#{r}"
    end

    # guess country
    country = r.scan(/NetName:\s*PRIVATE-ADDRESS-.*(RFC\d+)/i).flatten.first
    unless country
      c = r.scan(/^country:\s*(\w{2})$/i).flatten
      country = c.reject{|e| e == "EU"}.first&.upcase || c.detect{|e| e == "EU"}
    end
    unless country
      country = "KR" if r =~ /KRNIC/i
    end
    unless country
      raise RuntimeError, "Country not found from the whois response for #{ip}\n#{r}"
    end

    @cache[cidr] = country
    return country
  end
end

w = WhoisCountries.new
ARGF.each do |text|
  next if text =~ /^#/
  if ip = text.scan(WhoisCountries::RE_ipv4).first
    begin
      puts "#{w.country_for(ip)}\t#{text}"
    rescue Timeout::Error
      $stderr.puts "Timed out looking up whois for #{ip}"
    rescue Errno::ECONNREFUSED, RuntimeError
      $stderr.puts $!.message
    end
  end
end
