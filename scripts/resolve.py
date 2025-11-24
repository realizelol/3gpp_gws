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
    print(f"Error resolving domain {domain} (type {record_type}): {e}")
    return []

def download_csv(url):
  response = requests.get(url)
  response.raise_for_status()
  try:
    data = pd.read_csv(io.StringIO(response.text), sep=';', usecols=['MCC', 'MNC', 'ISO'], on_bad_lines='skip')
    return data
  except Exception as e:
    print(f"Error parsing CSV: {e}")
    return pd.DataFrame()

def process_domains_from_csv(csv_url):
  data = download_csv(csv_url)
  if data.empty:
    print("CSV contains no valid data")
    return
  data = data[data['ISO'].notna() & (data['ISO'].str.strip() != '')]

  countries = defaultdict(lambda: defaultdict(list))
  with open("all_domains.txt", 'w') as all_file:
    for _, row in data.iterrows():
      mcc = str(row['MCC']).zfill(3)
      mnc = str(row['MNC']).zfill(3)
      country_code = str(row['ISO'])
      if pd.isna(country_code) or not country_code.strip():
        continue
      sanitized_country_code = country_code.replace('/', '-').lower()

      domain = f"epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org"
      all_file.write(f"{domain}\n")

      ipv4_addresses = resolve_domain(domain, 'A')
      ipv6_addresses = resolve_domain(domain, 'AAAA')
      if ipv4_addresses:
        countries[country_code]['A'].append((domain, ipv4_addresses))
      if ipv6_addresses:
        countries[country_code]['AAAA'].append((domain, ipv6_addresses))

  with open("all_ipv4.txt", 'w') as ipv4_file, open("all_ipv6.txt", 'w') as ipv6_file:
    for country_code in sorted(countries.keys()):
      for record_type in ['A', 'AAAA']:
        if countries[country_code].get(record_type):
          for domain, ips in sorted(countries[country_code][record_type], key=lambda x: x[0]):
            for ip in sorted(ips):
              if record_type == 'A' and is_valid_ipv4(ip):
                ipv4_file.write(f"{ip}\n")
              elif record_type == 'AAAA' and is_valid_ipv6(ip):
                ipv6_file.write(f"{ip}\n")

  for country_code in sorted(countries.keys()):
    sanitized_country_code = country_code.replace('/', '-').lower()
    with open(f"domains/{sanitized_country_code}.txt", 'w') as country_file, \
         open(f"ipv4/{sanitized_country_code}.txt", 'w') as ipv4_country_file, \
         open(f"ipv6/{sanitized_country_code}.txt", 'w') as ipv6_country_file:
      for record_type in ['A', 'AAAA']:
        if countries[country_code].get(record_type):
          for domain, ips in sorted(countries[country_code][record_type], key=lambda x: x[0]):
            country_file.write(f"{domain}\n")
            for ip in sorted(ips):
              if record_type == 'A' and is_valid_ipv4(ip):
                ipv4_country_file.write(f"{ip}\n")
              elif record_type == 'AAAA' and is_valid_ipv6(ip):
                ipv6_country_file.write(f"{ip}\n")

process_domains_from_csv("https://mcc-mnc.net/mcc-mnc.csv")
