import requests
import urllib3
from prettytable import PrettyTable

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnManager:
    def __init__(self, nexpose_url, username, password): 
        self.nexpose_url = nexpose_url
        self.username = username
        self.password = password
        self.headers = {'Content-Type': 'application/json'}

    def get_asset_details_by_id(self, asset_id):        
        try:
            asset_url = f"{self.nexpose_url}/assets/{asset_id}"
            response = requests.get(asset_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Failed to get asset details for asset ID {asset_id}. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error getting asset details for asset ID {asset_id}: {e}")
        return None

    def get_asset_details_by_ip(self, ip_address):
        try:
            asset_url = f"{self.nexpose_url}/assets?ip={ip_address}"
            response = requests.get(asset_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            if response.status_code == 200:
                # Find the correct asset by matching IP address
                assets = response.json().get("resources", [])
                for asset in assets:
                    addresses = asset.get('addresses', [])
                    for address in addresses:
                        if address.get('ip') == ip_address:
                            return asset
                print(f"No asset found for IP {ip_address}")
                return None
            else:
                print(f"Failed to get asset details for IP {ip_address}. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error getting asset details for IP {ip_address}: {e}")
        return None

    def get_vulnerabilities(self, asset_id):
        try:
            vuln_url = f"{self.nexpose_url}/assets/{asset_id}/vulnerabilities?size=500"
            response = requests.get(vuln_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            if response.status_code == 200:
                return response.json().get("resources", [])
            else:
                print(f"Failed to list vulnerabilities for asset ID {asset_id}. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error listing vulnerabilities for asset ID {asset_id}: {e}")
        return []

    def get_solution_data(self, url):
        try:
            response = requests.get(url, headers=self.headers, auth=(self.username, self.password), verify=False)
            if response.status_code == 200:
                return response.json()["resources"][0]["summary"]["text"]
            else:
                print(f"Failed to get solution data. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error getting solution data: {e}")
        return None

    def get_vulnerability_details(self, vuln_id):
        try:
            vuln_details_url = f"{self.nexpose_url}/vulnerabilities/{vuln_id}"
            response = requests.get(vuln_details_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            if response.status_code == 200:
                vuln_details = response.json()
                severity = vuln_details.get("severity", "N/A")
                return severity
            else:
                print(f"Failed to get vulnerability details for ID {vuln_id}. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error getting vulnerability details for ID {vuln_id}: {e}")
        return "N/A"

    def list_vulnerabilities(self, asset_id):


        
        asset_details = self.get_asset_details_by_id(asset_id)
        if not asset_details:
            print(f"No asset details found for asset ID: {asset_id}")
            return

        ip_addresses = [address['ip'] for address in asset_details.get('addresses', [])]

        if not ip_addresses:
            ip_addresses = ['N/A']

        vulnerabilities = self.get_vulnerabilities(asset_id)
        if not vulnerabilities:
            print(f"No vulnerabilities found for asset ID: {asset_id}")
            return

        vuln_table = []
        for vuln in vulnerabilities:
            vuln_id = vuln['id']
            cve = ""
            cvss_score = ""
            category = ""
            exploits = "No"
            solution_url = vuln["links"][3]["href"]
            solution_data = self.get_solution_data(solution_url)
            severity = self.get_vulnerability_details(vuln_id)

            # Retrieve CVE, CVSS score, category, and risk score
            try:
                vuln_details_url = f"{self.nexpose_url}/vulnerabilities/{vuln_id}"
                response = requests.get(vuln_details_url, headers=self.headers, auth=(self.username, self.password), verify=False)
                if response.status_code == 200:
                    vuln_details = response.json()
                    cve = ', '.join(vuln_details.get("cves", []))
                    cvss_score = vuln_details.get("cvss", {}).get("v2", {}).get("score", "")
                    category = ', '.join(vuln_details.get("categories", []))

                    # Retrieve risk score
                    risk_score = vuln_details.get("riskScore", "N/A")

                    # Check if there are exploits available
                    exploits_url = f"{self.nexpose_url}/vulnerabilities/{vuln_id}/exploits"
                    exploits_response = requests.get(exploits_url, headers=self.headers, auth=(self.username, self.password), verify=False)
                    if exploits_response.status_code == 200:
                        exploits_data = exploits_response.json().get("resources", [])
                        if exploits_data:
                            exploits = "Yes"
            except Exception as e:
                print(f"Error getting vulnerability details for ID {vuln_id}: {e}")

            for ip_address in ip_addresses:
                vuln_table.append([asset_id, ip_address, vuln_id, category, cve, severity, cvss_score, risk_score, exploits, solution_data])

        headers = ['Asset ID', 'IP Address', 'Vulnerability ID', 'Category', 'CVE', 'Severity', 'CVSS Score', 'Risk Score', 'Exploits', 'Solution']

        # Create a PrettyTable instance
        table = PrettyTable(headers)

        # Add rows to the table
        for row in vuln_table:
            table.add_row(row)

        # Set desired column widths (adjust values as needed)
        table.max_width = 120  # Set total table width
        table.align = 'l'  # Set alignment to left

        print(table)

def main():
    nexpose_url = 'https://10.9.21.201:3780/api/3'  # Update with your URL
    username = 'bl4nc0s'                               # Update with your username
    password = 'N0Pa$$w0rdF0rY0u@:^)'                 # Update with your password

    vuln_manager = VulnManager(nexpose_url, username, password)

    while True:
        search_option = input("Do you want to search by ID or by IPs? (id/ip): ").strip().lower()

        if search_option not in ('id', 'ip'):
            print("Invalid option. Please choose 'id' or 'ip'.")
            continue

        if search_option == 'id':
            asset_ids = input("Enter one or more asset IDs separated by commas (e.g., 12345,67890): ").strip().split(',')
            asset_ids = [id.strip() for id in asset_ids]

            for asset_id in asset_ids:
                if not asset_id.isdigit():
                    print(f"Invalid asset ID: {asset_id}. Please enter a valid numeric ID.")
                    continue
                vuln_manager.list_vulnerabilities(asset_id)
        else:  # search_option == 'ip'
            ip_addresses = input("Enter one or more IP addresses separated by commas (e.g., 10.9.21.254,192.168.1.1): ").strip().split(',')
            ip_addresses = [ip.strip() for ip in ip_addresses]

            for ip_address in ip_addresses:

                
                asset_details = vuln_manager.get_asset_details_by_ip(ip_address)
                if asset_details:
                    asset_id = asset_details['id']
                    vuln_manager.list_vulnerabilities(asset_id)
                else:
                    print(f"No asset found for IP: {ip_address}")

        choice = input("Do you want to check vulnerabilities for more assets? (yes/no): ").strip().lower()
        if choice != 'yes':
            break

if __name__ == "__main__":
    main()
