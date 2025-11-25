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

def ip_to_int(ip, ver):
  if ver == 4:
    return int(ipaddress.IPv4Address(ip))
  if ver == 6:
    return int(ipaddress.IPv6Address(ip))

def sort_ips(ips, version):
  valid_ips = [ip for ip in ips if (is_valid_ipv4(ip) if version == 4 else is_valid_ipv6(ip))]
  return sorted(valid_ips, key=lambda ip: ip_to_int(ip, version))

def resolve_domain(domain, record_type='A'):
  try:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 6.0
    resolver.lifetime = 5.0
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    answer = resolver.resolve(domain, record_type)
    return [rdata.to_text() for rdata in answer]
  except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers, socket.gaierror) as e:
    #with open("_dns_errors.txt", 'a') as file:
    #  file.write(f"Error resolving domain {domain} (type {record_type}): {e}\n")
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
  all_domains = []
  all_ipv4_ips = []
  all_ipv6_ips = []
  data = download_csv(csv_url)
  if data.empty:
    print("CSV contains no valid data")
    return
  countries = defaultdict(lambda: defaultdict(list))
  country_domains = defaultdict(list)

  for _, row in data.iterrows():
    mcc = str(row['MCC']).zfill(3)
    mnc = str(row['MNC']).zfill(3)
    country_code = str(row['ISO'])
    sanitized_country_code = country_code.replace('/', '-').lower()

    domain = f"epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org"
    all_domains.append(domain)
    country_domains[sanitized_country_code].append(domain)

    ipv4_addresses = resolve_domain(domain, 'A')
    ipv6_addresses = resolve_domain(domain, 'AAAA')
    if ipv4_addresses:
      countries[country_code]['A'].append((domain, ipv4_addresses))
      all_ipv4_ips.extend(ipv4_addresses)
    if ipv6_addresses:
      countries[country_code]['AAAA'].append((domain, ipv6_addresses))
      all_ipv6_ips.extend(ipv6_addresses)

  all_domains.sort()
  with open("all_domains.txt", 'w') as file:
    file.write("\n".join(all_domains) + "\n")

  for country_code, domains in country_domains.items():
    sorted_domains = sorted(domains)
    country_file_path = f"domains/{country_code}.txt"
    with open(country_file_path, 'w') as country_file:
      country_file.write("\n".join(sorted_domains) + "\n")

  all_ipv4_ips_sorted = sort_ips(all_ipv4_ips, 4)
  all_ipv6_ips_sorted = sort_ips(all_ipv6_ips, 6)
  with open("all_ipv4.txt", 'w') as ipv4_file:
    for ip in all_ipv4_ips_sorted:
      ipv4_file.write(f"{ip}\n")
  with open("all_ipv6.txt", 'w') as ipv6_file:
    for ip in all_ipv6_ips_sorted:
      ipv6_file.write(f"{ip}\n")

  for country_code in sorted(countries.keys()):
    sanitized_country_code = country_code.replace('/', '-').lower()
    with open(f"ipv4/{sanitized_country_code}.txt", 'w') as ipv4_country_file, \
         open(f"ipv6/{sanitized_country_code}.txt", 'w') as ipv6_country_file:

      if countries[country_code].get('A'):
        ipv4_ips = []
        for domain, ips in countries[country_code]['A']:
          ipv4_ips.extend(ips)
        sorted_ipv4 = sort_ips(ipv4_ips, 4)
        for ip in sorted_ipv4:
          ipv4_country_file.write(f"{ip}\n")

      if countries[country_code].get('AAAA'):
        ipv6_ips = []
        for domain, ips in countries[country_code]['AAAA']:
          ipv6_ips.extend(ips)
        sorted_ipv6 = sort_ips(ipv6_ips, 6)
        for ip in sorted_ipv6:
          ipv6_country_file.write(f"{ip}\n")

process_domains_from_csv("https://mcc-mnc.net/mcc-mnc.csv")
