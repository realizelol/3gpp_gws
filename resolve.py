#!/usr/bin/python3

import socket
import dns.resolver
import sys

def resolve_domain(domain, record_type='A'):
  try:
    resolver = dns.resolver.Resolver()
    answer = resolver.resolve(domain, record_type)
    return [rdata.to_text() for rdata in answer]
  except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, socket.gaierror) as e:
    return []

def process_domains(input_file, output_file, record_type='A'):
  with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
    domains = infile.readlines()
    for domain in domains:
      domain = domain.strip()
      if domain:
        resolved_ips = resolve_domain(domain, record_type)
        if resolved_ips:
          for ip in resolved_ips:
            outfile.write(f"{ip}\n")
          outfile.write("\n")

def main():
  if len(sys.argv) != 4:
    print("Usage: python resolve_domains.py <input_file> <output_file> <record_type (A/AAAA)>")
    sys.exit(1)

  input_file = sys.argv[1]
  output_file = sys.argv[2]
  record_type = sys.argv[3].upper()

  if record_type not in ['A', 'AAAA']:
    sys.exit(1)

  process_domains(input_file, output_file, record_type)

if __name__ == "__main__":
  main()
