import re
import csv
from collections import Counter
from ipwhois import IPWhois
from tqdm import tqdm

def log_file_reader(syslog_path):
    with open(syslog_path, 'r') as file:
        log_content = file.read()
        ip_regex = r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ip_list = re.findall(ip_regex, log_content)
        return ip_list

def get_ip_info(ip):
    try:
        ipwhois_result = IPWhois(ip).lookup_rdap()
        registrar = ipwhois_result.get('asn_registry', '')
        description = ipwhois_result.get('asn_description', '')
        country = ipwhois_result.get('asn_country_code', '')
        return {'Registrar': registrar, 'Description': description, 'Country': country}
    except Exception as e:
        print(f"Error fetching information for IP {ip}: {e}")
        return {'Registrar': '', 'Description': '', 'Country': ''}

def count_ip_occurrences(ip_list):
    return Counter(ip_list)

def write_to_csv(counter, ip_info_dict, output_file='output.csv'):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        header = ['IP', 'Count', 'ASN Registry', 'ASN Description', 'ASN Country']  # Added comma after 'Description'
        writer.writerow(header)

        # Set to keep track of processed IPs
        processed_ips = set()

        for ip, count in tqdm(counter.items(), desc="Processing IPs", unit=" IP"):
            # Skip duplicates
            if ip in processed_ips:
                continue

            ip_info = ip_info_dict[ip]  # Retrieve IP information
            writer.writerow((ip, count, ip_info['Registrar'], ip_info['Description'], ip_info['Country']))

            # Mark IP as processed
            processed_ips.add(ip)

if __name__ == "__main__":
    syslog_path = 'syslog'
    ip_list = log_file_reader(syslog_path)
    
    # Get IP information for each unique IP in the list
    ip_info_dict = {ip: get_ip_info(ip) for ip in tqdm(set(ip_list), desc="Fetching IP Information", unit=" IP")}
    
    ip_counter = count_ip_occurrences(ip_list)
    write_to_csv(ip_counter, ip_info_dict)