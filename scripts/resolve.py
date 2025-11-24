#!/usr/bin/python3

import requests
import pandas as pd
import io
import dns.resolver
import socket
from collections import defaultdict
import ipaddress

def is_valid_ipv4(ip):
  try:
    ip_obj = ipaddress.IPv4Address(ip)
    return ip_obj not in ipaddress.IPv4Network('127.0.0.0/8') and \
           ip_obj not in ipaddress.IPv4Network('0.0.0.0/8') and \
           ip_obj not in ipaddress.IPv4Network('10.0.0.0/8') and \
           ip_obj not in ipaddress.IPv4Network('172.16.0.0/12') and \
           ip_obj not in ipaddress.IPv4Network('192.168.0.0/16')
  except ipaddress.AddressValueError:
    return False

def is_valid_ipv6(ip):
  try:
    ip_obj = ipaddress.IPv6Address(ip)
    return ip_obj not in ipaddress.IPv6Network('::1/128') and \
           ip_obj not in ipaddress.IPv6Network('::/128') and \
           ip_obj not in ipaddress.IPv6Network('fc00::/7')
  except ipaddress.AddressValueError:
    return False

def resolve_domain(domain, record_type='A'):
  try:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 10
    resolver.lifetime = 15
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    answer = resolver.resolve(domain, record_type)
    return [rdata.to_text() for rdata in answer]
  except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers, socket.gaierror) as e:
    return []

def process_domains_from_csv(csv_url):
  response = requests.get(csv_url)
  response.raise_for_status()
  try:
    data = pd.read_csv(io.StringIO(response.text), sep=';', usecols=['MCC', 'MNC', 'ISO'], on_bad_lines='skip')
  countries = defaultdict(lambda: defaultdict(list))
  with open("all_domains.txt", 'w') as all_file:
    for _, row in data.iterrows():
      mcc = str(int(row['MCC']).zfill(3))
      mnc = str(int(row['MNC']).zfill(3))
      domain = f"epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org"
      all_file.write(f"{domain}\n")

  # Prepare ip output files
  with open("all_ipv4.txt", 'w') as ipv4_file, open("all_ipv6.txt", 'w') as ipv6_file:

    # Write to all domain file
    for country_code in sorted(countries.keys()):
      for record_type in ['A', 'AAAA']:
        if countries[country_code].get(record_type):
          for domain, ips in sorted(countries[country_code][record_type], key=lambda x: x[0]):
            if record_type == 'A':
              for ip4 in sorted(ips):
                ipv4_file.write(f"{ip4}\n")
            elif record_type == 'AAAA':
              for ip6 in sorted(ips):
                ipv6_file.write(f"{ip6}\n")

  # Write individual country files
  for country_code in sorted(countries.keys()):
    sanitized_country_code = country_code.astype(str).replace('/', '-').lower()
    with open(f"domains/{sanitized_country_code}.txt", 'w') as country_file, \
         open(f"ipv4/{sanitized_country_code}.txt", 'w') as ipv4_country_file, \
         open(f"ipv6/{sanitized_country_code}.txt", 'w') as ipv6_country_file:
      for record_type in ['A', 'AAAA']:
        if countries[country_code].get(record_type):
          for domain, ips in sorted(countries[country_code][record_type], key=lambda x: x[0]):
            country_file.write(f"{domain}\n")
            if record_type == 'A':
              for ip4 in sorted(ips):
                ipv4_country_file.write(f"{ip4}\n")
            elif record_type == 'AAAA':
              for ip6 in sorted(ips):
                ipv6_country_file.write(f"{ip6}\n")

process_domains_from_csv("https://mcc-mnc.net/mcc-mnc.csv")
