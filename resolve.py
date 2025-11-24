#!/usr/bin/python3

import requests
import pandas as pd
import io
import dns.resolver
import socket
from collections import defaultdict

def resolve_domain(domain, record_type='A'):
  try:
    # Use dnspython to resolve the domain
    resolver = dns.resolver.Resolver()
    resolver.timeout = 10  # Erhöht das Timeout auf 10 Sekunden
    resolver.lifetime = 15  # Erhöht die maximale Lebensdauer der Anfrage
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    answer = resolver.resolve(domain, record_type)
    return [rdata.to_text() for rdata in answer]
  except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers, socket.gaierror) as e:
    # If the domain cannot be resolved, return an empty list
    return []

def download_csv(url):
  response = requests.get(url)
  response.raise_for_status()
  try:
    data = pd.read_csv(io.StringIO(response.text), sep=';', usecols=['MCC', 'MNC', 'ISO'], on_bad_lines='skip')
  except pd.errors.ParserError:
    data = pd.read_csv(io.StringIO(response.text), sep=',', usecols=['MCC', 'MNC', 'ISO'], on_bad_lines='skip')
  return data

def process_domains_from_csv(csv_url):
  data = download_csv(csv_url)

  # Group by country code (ISO)
  countries = defaultdict(lambda: defaultdict(list))  # Nested dictionary: countries[iso_code][record_type]

  # For each row in the CSV, generate the domain and resolve it
  for _, row in data.iterrows():
    country_code = row['ISO']
    mcc = str(int(row['MCC']))
    mnc = str(int(row['MNC']))
    
    # Generate domain
    domain = f"epdg.epc.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org"
    
    # Resolve the domain for both IPv4 and IPv6
    for record_type in ['A', 'AAAA']:
      resolved_ips = resolve_domain(domain, record_type)
      if resolved_ips:
        # Use a set to remove duplicate IPs
        unique_ips = set(resolved_ips)
        countries[country_code][record_type].append((domain, unique_ips))

  # Prepare output files
  with open("_domains.txt", 'w') as all_file, open("_ipv4.txt", 'w') as ipv4_file, open("_ipv6.txt", 'w') as ipv6_file:
    
    # Write to all domain file
    for country_code in sorted(countries.keys()):
      all_file.write(f"{country_code}\n")
      for record_type in ['A', 'AAAA']:
        if countries[country_code].get(record_type):
          for domain, ips in sorted(countries[country_code][record_type], key=lambda x: x[0]):
            all_file.write(f"{domain}\n")
            for ip in sorted(ips):  # Sort IPs for better readability
              all_file.write(f"{ip}\n")
          
          # Also write to the specific files (ipv4 and ipv6)
          if record_type == 'A':
            for domain, ips in sorted(countries[country_code][record_type], key=lambda x: x[0]):
              ipv4_file.write(f"{domain}\n")
              for ip in sorted(ips):
                ipv4_file.write(f"{ip}\n")
          elif record_type == 'AAAA':
            for domain, ips in sorted(countries[country_code][record_type], key=lambda x: x[0]):
              ipv6_file.write(f"{domain}\n")
              for ip in sorted(ips):
                ipv6_file.write(f"{ip}\n")
    
    # Write individual country files
    for country_code in sorted(countries.keys()):
      sanitized_country_code = country_code.replace('/', '-')
      with open(f"domains_{sanitized_country_code.lower()}.txt", 'w') as country_file, \
         open(f"ipv4_{sanitized_country_code.lower()}.txt", 'w') as ipv4_country_file, \
         open(f"ipv6_{sanitized_country_code.lower()}.txt", 'w') as ipv6_country_file:
        
        country_file.write(f"{country_code}\n")
        for record_type in ['A', 'AAAA']:
          if countries[country_code].get(record_type):
            for domain, ips in sorted(countries[country_code][record_type], key=lambda x: x[0]):
              country_file.write(f"{domain}\n")
              for ip in sorted(ips):
                country_file.write(f"{ip}\n")

            if record_type == 'A':
              for domain, ips in sorted(countries[country_code][record_type], key=lambda x: x[0]):
                ipv4_country_file.write(f"{domain}\n")
                for ip in sorted(ips):
                  ipv4_country_file.write(f"{ip}\n")
            elif record_type == 'AAAA':
              for domain, ips in sorted(countries[country_code][record_type], key=lambda x: x[0]):
                ipv6_country_file.write(f"{domain}\n")
                for ip in sorted(ips):
                  ipv6_country_file.write(f"{ip}\n")

process_domains_from_csv("https://mcc-mnc.net/mcc-mnc.csv")
