import re
import csv
from collections import Counter
from ipwhois import IPWhois
from tqdm import tqdm

# Function to read file and parse all source IP addresses
def log_file_reader(syslog_path):
    with open(syslog_path, 'r') as file:
        log_content = file.read()
        # Looks for strings beginning with SRC= and parses IPs
        ip_regex = r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ip_list = re.findall(ip_regex, log_content)
        return ip_list

# Function that uses ipwhois to grab asn data for each IP address
def get_ip_info(ip):
    try:
        ipwhois_result = IPWhois(ip).lookup_rdap()
        registrar = ipwhois_result.get('asn_registry', '')
        description = ipwhois_result.get('asn_description', '')
        country = ipwhois_result.get('asn_country_code', '')
        return {'Registrar': registrar, 'Description': description, 'Country': country}
    except Exception as e:
        # Just a little error handling for failed attempts
        print(f"Error fetching information for IP {ip}: {e}")
        return {'Registrar': '', 'Description': '', 'Country': ''}

# Function that counts the number of times the same source IP is foudn
def count_ip_occurrences(ip_list):
    return Counter(ip_list)

# Function that writes the results to a CSV
def write_to_csv(counter, ip_info_dict, output_file='output.csv'):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        header = ['IP', 'Count', 'ASN Registry', 'ASN Description', 'ASN Country']
        writer.writerow(header)

        # Variable for processing IP addresses
        processed_ips = set()

        # Uses tqdm to keep track of progress
        for ip, count in tqdm(counter.items(), desc="Processing IPs", unit=" IP"):
            # Skip duplicates
            if ip in processed_ips:
                continue
            
            # Puts together the CSV file
            ip_info = ip_info_dict[ip]
            writer.writerow((ip, count, ip_info['Registrar'], ip_info['Description'], ip_info['Country']))

            # Adds processed IP addresses to the set to avoid duplicates
            processed_ips.add(ip)

# Main loop
if __name__ == "__main__":
    # Set's the file path of the log file to syslog_path
    syslog_path = 'syslog'
    ip_list = log_file_reader(syslog_path)
    
    # Calls get_ip_info function and puts results in ip_info_dict variable
    # Uses tqdm to track and display progress in console
    ip_info_dict = {ip: get_ip_info(ip) for ip in tqdm(set(ip_list), desc="Fetching IP Information", unit=" IP")}
    # Calls count_ip_occurances function and puts results in ip_counter variable
    ip_counter = count_ip_occurrences(ip_list)
    # Calls write_to_csv function and combines ip_info_dict and ip_counter variables
    write_to_csv(ip_counter, ip_info_dict)
