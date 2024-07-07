import requests
import urllib3
from tabulate import tabulate
from ipaddress import IPv4Address

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TicketManager:
    def __init__(self, nexpose_url, username, password):
        self.nexpose_url = nexpose_url
        self.username = username
        self.password = password
        self.headers = {'Content-Type': 'application/json'}

    def get_assigned_asset_groups(self, user_id):
        try:
            asset_groups_url = f"{self.nexpose_url}/users/{user_id}/asset_groups"
            response = requests.get(asset_groups_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            response.raise_for_status()  # Raise HTTPError for bad status codes
            asset_groups = response.json().get("resources", [])
            return asset_groups
        except requests.exceptions.RequestException as e:
            print(f"Error fetching assigned asset groups for user {user_id}: {e}")
            return []

    def get_asset_group_name(self, asset_group_id):
        try:
            asset_group_url = f"{self.nexpose_url}/asset_groups/{asset_group_id}"
            response = requests.get(asset_group_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            response.raise_for_status()  # Raise HTTPError for bad status codes
            asset_group_name = response.json().get("name", "N/A")
            return asset_group_name
        except requests.exceptions.RequestException as e:
            print(f"Error fetching asset group name for asset group ID {asset_group_id}: {e}")
            return "N/A"

    def get_asset_ids_and_ips(self, user_id, asset_group_id):
        try:
            assets_url = f"{self.nexpose_url}/asset_groups/{asset_group_id}/assets"
            response = requests.get(assets_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            response.raise_for_status()  # Raise HTTPError for bad status codes
            asset_ids = response.json().get("resources", [])

            assets_info = []
            for asset_id in asset_ids:
                asset_info = self.get_asset_ip_address(asset_id)
                assets_info.append({"asset_id": asset_id, "ip_addresses": asset_info})

            return assets_info
        except requests.exceptions.RequestException as e:
            print(f"Error fetching asset IDs and IPs for user {user_id}, asset group {asset_group_id}: {e}")
            return []

    def get_asset_ip_address(self, asset_id):
        try:
            asset_url = f"{self.nexpose_url}/assets/{asset_id}"
            response = requests.get(asset_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            response.raise_for_status()  # Raise HTTPError for bad status codes
            asset_info = response.json()
            ip_addresses = asset_info.get("addresses", [])
            if ip_addresses:
                ip_addresses = sorted([ip_info["ip"] for ip_info in ip_addresses], key=lambda ip: IPv4Address(ip), reverse=True)
                return ip_addresses
            else:
                return ["N/A"]
        except requests.exceptions.RequestException as e:
            print(f"Error fetching IP address for asset ID {asset_id}: {e}")
            return ["N/A"]

    def display_users_table(self):
        try:
            users_url = f"{self.nexpose_url}/users"
            response = requests.get(users_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            response.raise_for_status()  # Raise HTTPError for bad status codes
            users = response.json().get("resources", [])
            if not users:
                print("No users found.")
                return

            user_table = []
            for user in users:
                user_id = user.get('id', 'N/A')
                user_name = user.get('name', 'N/A')
                user_email = user.get('email', 'N/A')
                assigned_asset_groups = self.get_assigned_asset_groups(user_id)

                for asset_group_id in assigned_asset_groups:
                    asset_group_name = self.get_asset_group_name(asset_group_id)
                    assets_info = self.get_asset_ids_and_ips(user_id, asset_group_id)

                    for info in assets_info:
                        asset_id = info["asset_id"]
                        ip_addresses = info["ip_addresses"]
                        user_table.append([user_id, user_name, user_email, asset_group_name, asset_id, ', '.join(ip_addresses)])

            headers = ['User ID', 'Name', 'Email', 'Asset Group', 'Asset ID', 'Asset IP']
            print(tabulate(user_table, headers=headers, tablefmt='grid'))
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")

    def search_by_username(self, username):
        try:
            users_url = f"{self.nexpose_url}/users"
            response = requests.get(users_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            response.raise_for_status()  # Raise HTTPError for bad status codes
            users = response.json().get("resources", [])
            if not users:
                print(f"No users found for username '{username}'.")
                return

            user_table = []
            for user in users:
                if user.get('name') == username:
                    user_id = user.get('id', 'N/A')
                    user_name = user.get('name', 'N/A')
                    user_email = user.get('email', 'N/A')
                    assigned_asset_groups = self.get_assigned_asset_groups(user_id)

                    for asset_group_id in assigned_asset_groups:
                        asset_group_name = self.get_asset_group_name(asset_group_id)
                        assets_info = self.get_asset_ids_and_ips(user_id, asset_group_id)

                        for info in assets_info:
                            asset_id = info["asset_id"]
                            ip_addresses = info["ip_addresses"]
                            user_table.append([user_id, user_name, user_email, asset_group_name, asset_id, ', '.join(ip_addresses)])

            headers = ['User ID', 'Name', 'Email', 'Asset Group', 'Asset ID', 'Asset IP']
            print(tabulate(user_table, headers=headers, tablefmt='grid'))
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")

    def search_by_ips(self, ip_addresses):
        try:
            all_assets = []
            for ip in ip_addresses:
                assets_url = f"{self.nexpose_url}/assets?filter=ip-address eq {ip}"
                response = requests.get(assets_url, headers=self.headers, auth=(self.username, self.password), verify=False)
                response.raise_for_status()  # Raise HTTPError for bad status codes
                assets = response.json().get("resources", [])
                all_assets.extend(assets)

            if not all_assets:
                print("No assets found for the provided IP addresses.")
                return

            asset_table = []
            for asset in all_assets:
                asset_id = asset.get('id', 'N/A')
                ip_addresses = self.get_asset_ip_address(asset_id)
                user_id = asset.get('user-id', 'N/A')
                username, email = self.get_user_details(user_id)
                asset_table.append([asset_id, ', '.join(ip_addresses), username, email])

            headers = ['Asset ID', 'Asset IP', 'Username', 'Email']
            print(tabulate(asset_table, headers=headers, tablefmt='grid'))
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")

    def get_user_details(self, user_id):
        try:
            user_url = f"{self.nexpose_url}/users/{user_id}"
            response = requests.get(user_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            response.raise_for_status()  # Raise HTTPError for bad status codes
            user_info = response.json()
            username = user_info.get('name', 'N/A')
            email = user_info.get('email', 'N/A')
            return username, email
        except requests.exceptions.RequestException as e:
            print(f"Error fetching user details for user ID {user_id}: {e}")
            return 'N/A', 'N/A'

def main():
    nexpose_url = 'https://10.9.21.201:3780/api/3'  # Update with your URL
    username = 'bl4nc0s'                               # Update with your username
    password = 'N0Pa$$w0rdF0rY0u@:^)'                 # Update with your password

    ticket_manager = TicketManager(nexpose_url, username, password)

    while True:
        print("1. Display all users and IPs")
        print("2. Search by username")
        print("3. Search by IPs")
        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == '1':
            ticket_manager.display_users_table()
        elif choice == '2':
            username = input("Enter the username: ").strip()
            ticket_manager.search_by_username(username)
        elif choice == '3':
            ip_addresses = input("Enter one or more IP addresses separated by commas (e.g., 10.9.21.254,192.168.1.1): ").strip().split(',')
            ip_addresses = [ip.strip() for ip in ip_addresses]
            ticket_manager.search_by_ips(ip_addresses)
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

        another_query = input("Do you want to perform another query? (yes/no): ").strip().lower()
        if another_query != 'yes':
            break

if __name__ == "__main__":
    main()
