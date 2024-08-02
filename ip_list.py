import csv
import requests
import time

# Replace with your actual VirusTotal API key
API_KEY = '4ddef45f45ad6f852171bde6ada415ec6ff4d23be4a85136a72f83658ce7e0cd'
API_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

# Function to get VirusTotal report for an IP
def get_vt_report(ip):
    params = {'apikey': API_KEY, 'ip': ip}
    response = requests.get(API_URL, params=params)
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        print(f"Error decoding JSON for IP {ip}. Response content: {response.content}")
        return None

# Read IPs from CSV and query VirusTotal
def analyze_ips(csv_file):
    with open(csv_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        with open('vt_results.csv', 'w', newline='') as outfile:
            fieldnames = ['dest_ip', 'positives', 'total', 'country', 'owner', 'as_owner', 'report_link']
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in reader:
                ip = row['dest_ip']
                result = get_vt_report(ip)
                if result:
                    print(f"Results for IP {ip}:")
                    positives = result.get('positives', 'N/A')
                    total = result.get('total', 'N/A')
                    country = result.get('country', 'N/A')
                    owner = result.get('owner', 'N/A')
                    as_owner = result.get('as_owner', 'N/A')
                    report_link = f"https://www.virustotal.com/gui/ip-address/{ip}/detection"
                    print(f"Positives: {positives}, Total: {total}, Country: {country}, Owner: {owner}, AS Owner: {as_owner}")
                    print('-' * 60)
                    writer.writerow({
                        'dest_ip': ip,
                        'positives': positives,
                        'total': total,
                        'country': country,
                        'owner': owner,
                        'as_owner': as_owner,
                        'report_link': report_link
                    })
                # Respect VirusTotal API rate limits
                time.sleep(15)  # Adjust based on your API's rate limits

# Call the function with your CSV file
analyze_ips('destination_ips.csv')
