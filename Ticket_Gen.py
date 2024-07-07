import requests
import urllib3
from prettytable import PrettyTable
import datetime
import json
import difflib
import mysql.connector


# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NexposeManager:
    def __init__(self, nexpose_url, username, password, glpi_url, glpi_user_token, glpi_app_token, glpi_session_token):
        self.nexpose_url = nexpose_url
        self.username = username
        self.password = password
        self.glpi_url = glpi_url
        self.glpi_user_token = glpi_user_token
        self.glpi_app_token = glpi_app_token
        self.glpi_session_token = glpi_session_token
        self.headers = {'Content-Type': 'application/json'}
        self.vulnerability_categories = {} # Dictionary to store vulnerability categories

    def get_asset_details_by_id(self, asset_id):
        try:
            asset_url = f"{self.nexpose_url}/assets/{asset_id}"
            response = requests.get(asset_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            response.raise_for_status()  # Raise HTTPError for bad status codes
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching asset details for asset ID {asset_id}: {e}")
            return None

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
            if isinstance(asset_ids, list):
                for asset_id in asset_ids:
                    asset_info = self.get_asset_ip_address(asset_id)
                    assets_info.append({"asset_id": asset_id, "ip_address": asset_info})
            else:
                print(f"Error fetching asset IDs and IPs for user {user_id}, asset group {asset_group_id}: Unexpected response format")

            return assets_info
        except requests.exceptions.RequestException as e:
            print(f"Error fetching asset IDs and IPs for user {user_id}, asset group {asset_group_id}: {e}")
            return []

    def get_asset_ip_address(self, asset_id):
        try:
            asset_url = f"{self.nexpose_url}/assets/{asset_id}"
            response = requests.get(asset_url, headers=self.headers, auth=(self.username, self.password), verify=False)
            response.raise_for_status()  # Raise HTTPError for bad status codes
            ip_addresses = response.json().get("addresses", [])
            if ip_addresses:
                ip_address = ip_addresses[0]["ip"]
                return ip_address
            else:
                return "N/A"
        except requests.exceptions.RequestException as e:
            print(f"Error fetching IP address for asset ID {asset_id}: {e}")
            return "N/A"

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
    def check_existing_ticket(self, ip_address, cve, solution, assigned_to):
        try:
            # Establish a connection to the database
            cnx = mysql.connector.connect(user='glpi_user', password='1234567890',
                                          host='10.9.21.201', database='glpi_db')
            cursor = cnx.cursor()

            # Construct the SQL query
            query = ("SELECT id, name FROM glpi_tickets "
                     "WHERE content LIKE %s AND content LIKE %s AND content LIKE %s AND content LIKE %s")

            # Execute the query
            cursor.execute(query, (f"%{ip_address}%", f"%{cve}%", f"%{solution}%", f"%{assigned_to}%"))

            # Fetch all matching tickets
            similar_tickets = cursor.fetchall()

            cursor.close()
            cnx.close()

            if similar_tickets:
                print("\nSimilar Tickets Found:\n")
                print("{:<10} {:<50}".format("Ticket ID", "Subject"))
                print("=" * 70)

                # Sort similar tickets by ticket ID before printing
                similar_tickets.sort(key=lambda x: x[0])

                for ticket in similar_tickets:
                    ticket_id, subject = ticket
                    print("{:<10} {:<50}".format(ticket_id, subject))

                print("=" * 70)
                return True
            else:
                print("\nNo similar tickets found.")
                return False

        except mysql.connector.Error as err:
            print(f"Error searching for existing tickets: {err}")
            return False
    def create_glpi_ticket(self, user_id, asset_id, ip_address, asset_username, assigned_to, vulnerability_details, vulnerability_category, risk_score):
        try:
            # Check if a similar ticket already exists
            if self.check_existing_ticket(ip_address, vulnerability_details, vulnerability_category, assigned_to):
                create_new = input("A similar ticket already exists. Do you want to create a new one? (yes/no): ").lower()
                if create_new != 'yes':
                    print("Ticket creation aborted.")
                    return
            # Search for the user ID of 'assigned_to' (CitizenTwo)
            assigned_to_id = self.search_user_id(assigned_to)
            if assigned_to_id is None:
                # User not found
                return

            # Get the user ID of GLPI (user_id=2) to set as the requester
            glpi_user_id = 2

            # Check if the assigned user is an admin (assuming admin ID is 1)
            admin_user_id = 1

            if assigned_to_id == admin_user_id:
                print(f"User '{assigned_to}' is an admin and cannot be assigned tickets.")
                return

            category_id = self.get_or_create_category(vulnerability_category)

            # Define mappings for priority, urgency, and impact
            priority_mapping = {
                'High': 4,       # Priority 'High' corresponds to integer value 4
                'Very High': 5,  # Priority 'Very High' corresponds to integer value 5
                'Major': 6       # Priority 'Major' corresponds to integer value 6
            }

            urgency_mapping = {
                'High': 3,       # Urgency 'High' corresponds to integer value 3
                'Very High': 4,  # Urgency 'Very High' corresponds to integer value 4
                'Major': 5       # Urgency 'Major' corresponds to integer value 5
            }

            impact_mapping = {
                'High': 3,       # Impact 'High' corresponds to integer value 3
                'Very High': 4,  # Impact 'Very High' corresponds to integer value 4
                'Major': 5       # Impact 'Major' corresponds to integer value 5
            }

            # Map risk score to priority, impact, and urgency
            if 650 <= risk_score < 750:
                priority = priority_mapping['High']
                impact = 'High'
                urgency = 'High'
                # Set time to resolve to 5 days
                time_to_resolve = 5
            elif 750 <= risk_score < 900:
                priority = priority_mapping['Very High']
                impact = 'Very High'
                urgency = 'Very High'
                # Set time to resolve to 3 days
                time_to_resolve = 3
            elif 900 <= risk_score <= 1000:
                priority = priority_mapping['Major']
                impact = 'Major'
                urgency = 'Major'
                # Set time to resolve to 3 days
                time_to_resolve = 3
            else:
                print("Invalid risk score provided.")
                return

            # Calculate solve date based on current date and time to resolve
            current_date = datetime.datetime.now()
            solve_date = current_date + datetime.timedelta(days=time_to_resolve)

            # Check if the asset has a tag named "web"
            tag_check_response = requests.get(f"https://10.9.21.201:3780/api/3/assets/{asset_id}/tags", auth=(self.username, self.password), verify=False)
            if tag_check_response.status_code == 200:
                tags = tag_check_response.json().get("resources", [])
                web_tag_exists = any(tag.get("name") == "web" for tag in tags)
                system_tag_exists = any(tag.get("name") == "system" for tag in tags)
                mail_tag_exists = any(tag.get("name") == "mail" for tag in tags)
            else:
                web_tag_exists = False
                system_tag_exists = False
                mail_tag_exists = False

            # Initialize _users_id_observer
            _users_id_observer = None

            # If the "web" tag exists, change _users_id_assign and _users_id_observer
            if web_tag_exists:
                # Set _users_id_observer to assigned_to_id (id of the owner of the asset)
                _users_id_observer = assigned_to_id
                 # Change _users_id_assign to the user with id=13
                assigned_to_id = 13
            if system_tag_exists:
                # Set _users_id_observer to assigned_to_id (id of the owner of the asset)
                _users_id_observer = assigned_to_id
                # Change _users_id_assign to the user with id=14
                assigned_to_id = 14
            if mail_tag_exists:
                # Set _users_id_observer to assigned_to_id (id of the owner of the asset)
                _users_id_observer = assigned_to_id
                # Change _users_id_assign to the user with id=14
                assigned_to_id = 14

            # Construct the ticket data
            ticket_data = {
                "input": {
                    "name": f"Vulnerability Ticket: {asset_id} - {asset_username}",
                    "content": f"**Asset Details:**\n- **Asset ID:** {asset_id}\n- **Username:** {asset_username}\n- **IP Address:** {ip_address}\n\n{vulnerability_details}\n\n**Vulnerability Category:** {vulnerability_category}",
                    "status": 1,  # Set ticket status to "New"
                    "type": 1,  # Set ticket type to "Incident"
                    "_users_id_requester": glpi_user_id,  # Set the requester to GLPI user ID
                    "_users_id_assign": assigned_to_id,  # Add the Assigned To field
                    "_users_id_observer": _users_id_observer,  # Set the observer
                    "itilcategories_id": category_id,  # Add the category ID
                    "priority": priority,  # Set priority based on risk score
                    "impact": impact_mapping[impact],  # Set impact based on risk score
                    "urgency": urgency_mapping[urgency],  # Set urgency based on risk score
                    "time_to_resolve": solve_date.strftime("%Y-%m-%d %H:%M:%S"),  # Set solve date
                    "due_date": solve_date.strftime("%Y-%m-%d %H:%M:%S"),  # Set solve date
                    # Add other required fields as needed
                }
            }

            # Construct headers with super admin session token and app token
            session_token = self.fetch_session_token()
            headers = {
                "Content-Type": "application/json",
                "App-Token": self.glpi_app_token,
                "Session-Token": session_token  # Use the session token of the super admin
            }

            # Make the API request to create the ticket with the session token of the super admin
            response = requests.post(f"{self.glpi_url}/Ticket", json=ticket_data, headers=headers)

            # Check if the request was successful
            if response.status_code == 201:
                ticket_id = response.json().get("id")
                print(f"Ticket created successfully with ID: {ticket_id}")

                # Add assigned user as an actor in the "assign to" field
                assign_data = {
                    "input": {
                        "tickets_id": ticket_id,
                        "users_id": assigned_to_id,
                        "type": 2
                    }
                }

                # Make the API request to add the assigned user as an actor to the ticket
                response = requests.post(f"{self.glpi_url}/Ticket/{ticket_id}/Ticket_User/", json=assign_data, headers=headers)
                if response.status_code == 201:
                    print(f"{assigned_to} added as an actor in the 'assign to' field.")
                else:
                    # print(f"Error adding {assigned_to} as an actor: {response.status_code} {response.text}")
                    pass

                # Update ticket with solve date
                solve_date_data = {
                    "input": {
                        "solvedate": solve_date.strftime("%Y-%m-%d %H:%M:%S")
                    }
                }

                # Make the API request to update the ticket with the solve date
                response = requests.put(f"{self.glpi_url}/Ticket/{ticket_id}", json=solve_date_data, headers=headers)
                if response.status_code == 200:
                    pass #print(f"Solve date updated for ticket ID: {ticket_id}")
                else:
                    print(f"Error updating solve date for ticket ID {ticket_id}: {response.status_code} {response.text}")

            else:
                print(f"Error creating ticket: {response.status_code} {response.text}")

        except Exception as e:
            print(f"Error creating ticket: {e}")

    def search_user_id(self, username):
        try:
            session_token = self.fetch_session_token()
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"user_token {self.glpi_user_token}",
                "App-Token": self.glpi_app_token,
                "Session-Token": session_token
            }
            params = {
                "criteria": [
                    {
                        "field": "name",
                        "searchtype": "equals",
                        "value": username
                    }
                ]
            }
            response = requests.get(f"{self.glpi_url}/User", params=params, headers=headers)
            if response.status_code == 200:
                users = response.json()
                for user in users:
                    if user.get("name") == username:
                        return user.get("id")
                print(f"User with username '{username}' not found.")
            else:
                print(f"Error searching for user: {response.status_code} {response.text}")

        except Exception as e:
            print(f"Error searching for user: {e}")

    def create_category(self, category_name):
        try:
            # Check if the category already exists
            category_id = self.get_category_id(category_name)
            if category_id:
                return category_id

            # If the category does not exist, create it
            category_data = {
                "input": {
                    "name": category_name
                }
            }
            session_token = self.fetch_session_token()
            headers = {
                "Content-Type": "application/json",
                "App-Token": self.glpi_app_token,
                "Session-Token": session_token
            }

            response = requests.post(f"{self.glpi_url}/ITILCategory", json=category_data, headers=headers)
            if response.status_code == 201:
                category_id = response.json().get("id")
                print(f"Category '{category_name}' created successfully with ID: {category_id}")
                return category_id
            else:
                print(f"Error creating category '{category_name}': {response.status_code} {response.text}")
                return None

        except Exception as e:
            print(f"Error creating category '{category_name}': {e}")
            return None
    def get_category_id(self, category_name):
        try:
            session_token = self.fetch_session_token()
            headers = {
                "Content-Type": "application/json",
                "App-Token": self.glpi_app_token,
                "Session-Token": session_token
            }

            params = {
                "criteria": [
                    {
                        "field": "name",
                        "searchtype": "equals",
                        "value": category_name
                    }
                ]
            }

            response = requests.get(f"{self.glpi_url}/ITILCategory", params=params, headers=headers)

            if response.status_code == 200:
                categories = response.json()
                if categories:
                    return categories[0].get("id")
                else:
                    # If the category doesn't exist, return None
                    return None
            else:
                print(f"Error fetching category ID for '{category_name}': {response.status_code} {response.text}")
                return None

        except Exception as e:
            print(f"Error fetching category ID for '{category_name}': {e}")
            return None
    def get_or_create_category(self, vulnerability_category):
        try:
            # Check if the category already exists
            category_id = self.get_category_id(vulnerability_category)

            if category_id:
                return category_id

            # If the category does not exist, create it
            category_id = self.create_category(vulnerability_category)

            if category_id:
                # Update vulnerability_categories dictionary with the new category ID
                self.vulnerability_categories[vulnerability_category] = category_id
                return category_id
            else:
                # If category creation fails, raise an exception or handle it appropriately
                raise Exception(f"Failed to create category '{vulnerability_category}'")

        except Exception as e:
            print(f"Error getting or creating category '{vulnerability_category}': {e}")
            return None
    def list_vulnerabilities(self, asset_id, user_id, user_name, user_email):
        asset_details = self.get_asset_details_by_id(asset_id)
        if not asset_details:
            print(f"No asset details found for asset ID: {asset_id}")
            return

        asset_username = user_name  # Use the provided username
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
            category = ', '.join(vuln.get("categories", []))  # Category
            exploits = "No"
            solution_url = vuln["links"][3]["href"]
            solution_data = self.get_solution_data(solution_url)
            severity = self.get_vulnerability_details(vuln_id)
            category_names = vuln.get("categories", [])  # Retrieve categories for the vulnerability
            category = ', '.join(category_names) if category_names else "N/A"  # Concatenate category names into a single string

            category_ids = []
            for category_name in category_names:
                category_id = self.get_or_create_category(category_name)
                if category_id:
                    category_ids.append(category_id)
            # Retrieve CVE, CVSS score, category, and risk score
            try:
                vuln_details_url = f"{self.nexpose_url}/vulnerabilities/{vuln_id}"
                response = requests.get(vuln_details_url, headers=self.headers, auth=(self.username, self.password), verify=False)
                if response.status_code == 200:
                    vuln_details = response.json()
                    cve = ', '.join(vuln_details.get("cves", []))
                    cvss_score = vuln_details.get("cvss", {}).get("v2", {}).get("score", "")
                    category_names = vuln_details.get("categories", [])
                    category = ', '.join(category_names) if category_names else "N/A"  # Concatenate category names into a single string

                    # Retrieve risk score
                    risk_score = vuln_details.get("riskScore", "N/A")

                    # Check if there are exploits available
                    exploits_url = f"{self.nexpose_url}/vulnerabilities/{vuln_id}/exploits"
                    exploits_response = requests.get(exploits_url, headers=self.headers, auth=(self.username, self.password), verify=False)
                    if exploits_response.status_code == 200:
                        exploits_data = exploits_response.json().get("resources", [])
                        if exploits_data:
                            exploits = "Yes"

                    if risk_score and float(risk_score) > 650:
                        for ip_address in ip_addresses:
                            category_tuple = tuple(category_names)
                            vuln_table.append([asset_id, ip_address, vuln_id, category, cve, severity, cvss_score, risk_score, exploits, solution_data])
                            # Create GLPI ticket for each vulnerability
                            self.create_glpi_ticket(user_id, asset_id, ip_address, asset_username, user_name, f"**Vulnerability ID:** {vuln_id}\n**Category:** {category}\n**CVE:** {cve}\n**Severity:** {severity}\n**CVSS Score:** {cvss_score}\n**Risk Score:** {risk_score}\n**Exploits:** {exploits}\n**Solution:** {solution_data}", category, risk_score)

            except Exception as e:
                print(f"Error getting vulnerability details for ID {vuln_id}: {e}")

        headers = ['Asset ID', 'IP Address', 'Vulnerability ID', 'Category', 'CVE', 'Severity', 'CVSS Score', 'Risk Score', 'Exploits', 'Solution']

        # Create a PrettyTable instance if there are vulnerabilities
        if vuln_table:
            table = PrettyTable(headers)

            # Add rows to the table
            for row in vuln_table:
                table.add_row(row)

            # Set desired column widths (adjust values as needed)
            table.max_width = 120  # Set total table width
            table.align = 'l'  # Set alignment to left

            print(table)
    def fetch_session_token(self):
        try:
            response = requests.get(
                f"{self.glpi_url}/initSession?get_full_session=true",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "user_token 61XBdvRmmx7ITlRYtUcjWl1W7fF8jfdBxNl0nd19",
                    "App-Token": self.glpi_app_token
                }
            )
            response.raise_for_status()
            session_data = response.json()
            session_token = session_data.get("session_token")
            return session_token
        except requests.exceptions.RequestException as e:
            print(f"Error fetching session token: {e}")
            return None
def main():
    nexpose_url = 'https://10.9.21.201:3780/api/3'
    nexpose_username = 'bl4nc0s'
    nexpose_password = 'N0Pa$$w0rdF0rY0u@:^)'
    glpi_url = 'http://10.9.21.201/apirest.php'
    glpi_user_token = '61XBdvRmmx7ITlRYtUcjWl1W7fF8jfdBxNl0nd19'
    glpi_app_token = 'grbZqYUGjzECRenx9zm0h8jR1kJszbUSFMSQgymq'
    #glpi_session_token = '3oc8i6l98go6rbbkf0f6ppopb6'
    glpi_session_token = None

    # Initialize Nexpose Manager
    nexpose_manager = NexposeManager(nexpose_url, nexpose_username, nexpose_password, glpi_url, glpi_user_token, glpi_app_token, glpi_session_token)

    try:
        # Fetching all users in InsightVM
        users_response = requests.get(f"{nexpose_url}/users", headers=nexpose_manager.headers, auth=(nexpose_username, nexpose_password), verify=False)
        users = users_response.json().get("resources", [])
        if not users:
            print("No users found.")
            return

        # Displaying users in a table, starting from the second user
        user_table = PrettyTable(['User ID', 'Username'])
        # Initialize user ID counter starting from 2
        user_id_counter = 2
        for user in users[1:]:  # Start from the second user
            user_table.add_row([user['id'], user['name']])
        print("Users in InsightVM:")
        print(user_table)

        # Getting user input for ID selection
        user_id = input("Enter the User ID to proceed: ")

        # Validating the input
        user_id = int(user_id)
        user_name = None
        for user in users:
            if user['id'] == user_id:
                user_name = user['name']
                break
        if user_name is None:
            print("Invalid User ID.")
            return

        # Proceeding with the selected user
        user_email = "zbuidqcmrwlqomkllh@cazlg.com "  # Replace with actual user email
        assigned_asset_groups = nexpose_manager.get_assigned_asset_groups(user_id)

        user_table = []
        for asset_group_id in assigned_asset_groups:
            asset_group_name = nexpose_manager.get_asset_group_name(asset_group_id)
            assets_info = nexpose_manager.get_asset_ids_and_ips(user_id, asset_group_id)

            for info in assets_info:
                asset_id = info["asset_id"]
                ip_address = info["ip_address"]
                user_table.append([user_id, user_name, user_email, asset_group_name, asset_id, ip_address])
                nexpose_manager.list_vulnerabilities(asset_id, user_id, user_name, user_email)

    except ValueError:
        print("Invalid input for User ID. Please enter a valid integer.")
    except KeyboardInterrupt:
        print("\nExiting gracefully... Goodbye! 👋")

if __name__ == "__main__":
    main()
