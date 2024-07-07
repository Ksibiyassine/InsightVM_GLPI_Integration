import requests
from prettytable import PrettyTable
from tqdm import tqdm
from colorama import Fore, Style
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class NexposeManager:
    def __init__(self, glpi_url, glpi_app_token):
        self.glpi_url = glpi_url
        self.glpi_app_token = glpi_app_token
        self.glpi_session_token = None  # Initialize session token to None
        self.user_id_map = {}  # Initialize user_id_map

    def get_headers(self):
        # Fetch the session token dynamically
        session_token = self.fetch_session_token()
        if session_token:
            return {
                "Content-Type": "application/json",
                "App-Token": self.glpi_app_token,
                "Session-Token": session_token  # Use the fetched session token
            }
        else:
            print("Failed to fetch session token.")
            return None

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

    def create_user_id_map(self):
        user_id_map = {}
        try:
            headers = self.get_headers()
            response = requests.get(f"{self.glpi_url}/User", headers=headers)
            response.raise_for_status()
            users_data = response.json()
            for user_data in users_data:
                user_id = user_data.get('id')
                user_name = user_data.get('name')
                if user_id and user_name:
                    user_id_map[user_id] = user_name
        except requests.exceptions.HTTPError as e:
            print(f"HTTP Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        return user_id_map

    def get_user_name(self, user_id):
        if user_id in self.user_id_map:
            return self.user_id_map[user_id]
        else:
            return f"User {user_id}"

    def get_assigned_tickets(self, all_tickets=False):
        if all_tickets:
            self.fetch_all_tickets()
        else:
            start_id, end_id = self.get_ticket_range()
            if start_id is not None and end_id is not None:
                self.user_id_map = self.create_user_id_map()  # Initialize user_id_map
                user_id = self.select_user()
                if user_id:
                    self.fetch_assigned_tickets_range(user_id, start_id, end_id)
                else:
                    print("User not found.")

    def fetch_assigned_tickets_range(self, user_id, start_id, end_id):
        all_tickets = []
        with tqdm(total=end_id - start_id + 1, desc="Scanning Tickets") as pbar:
            for ticket_id in range(start_id, end_id + 1):
                try:
                    headers = self.get_headers()
                    response = requests.get(f"{self.glpi_url}/Ticket/{ticket_id}", headers=headers)
                    if response.status_code == 404:
                        pbar.update(1)
                        continue  # Skip the ticket and proceed to the next one
                    response.raise_for_status()
                    ticket = response.json()
                    if self.is_ticket_assigned_to_user(ticket, user_id):
                        all_tickets.append(ticket)
                        self.print_ticket_summary(ticket)
                        # Check for delay
                        delay_minutes = ticket.get('solve_delay_stat', 0)
                        if delay_minutes > 2 * 24 * 60:  # More than 2 days in minutes
                            self.send_delay_alert_email(ticket)
                    pbar.update(1)
                except requests.exceptions.HTTPError as e:
                    print(f"HTTP Error: {e}")
                except Exception as e:
                    print(f"An unexpected error occurred: {e}")
        return all_tickets  # Return all_tickets if needed

    def fetch_all_tickets(self):
        try:
            headers = self.get_headers()
            response = requests.get(f"{self.glpi_url}/Ticket/", headers=headers)
            response.raise_for_status()
            tickets_data = response.json()
            with tqdm(total=tickets_data["total"], desc="Scanning Tickets") as pbar:
                for ticket_id in range(1, tickets_data["total"] + 1):
                    try:
                        response = requests.get(f"{self.glpi_url}/Ticket/{ticket_id}", headers=headers)
                        response.raise_for_status()
                        ticket = response.json()
                        self.print_ticket_summary(ticket)
                        pbar.update(1)
                    except requests.exceptions.HTTPError as e:
                        print(f"HTTP Error: {e}")
                    except Exception as e:
                        print(f"An unexpected error occurred: {e}")
        except requests.exceptions.HTTPError as e:
            print(f"HTTP Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def is_ticket_assigned_to_user(self, ticket, user_id):
        assigned_users = self.get_assigned_users(ticket)
        return user_id in assigned_users

    def format_delay(self, solve_delay_stat):
        total_minutes = int(solve_delay_stat) // 60
        days, hours = divmod(total_minutes, 24*60)
        hours, minutes = divmod(hours, 60)

        delay_str = ""
        if days > 0:
            delay_str += f"{days} day{'s' if days > 1 else ''} "
        if hours > 0:
            delay_str += f"{hours} hour{'s' if hours > 1 else ''} "
        if minutes > 0:
            delay_str += f"{minutes} minute{'s' if minutes > 1 else ''} "

        if not delay_str:
            delay_str = "0 minutes"

        return delay_str.strip()

    def print_ticket_summary(self, ticket):
        ticket_id = ticket['id']  # Define ticket_id here
        table = PrettyTable(['Ticket ID', 'Name', 'Date', 'Requester', 'Observer', 'Assigned To', 'Status', 'Time to Resolve', 'Delay'])
        requester_id = ticket.get('_users_id_requester', 'N/A')
        assigned_users = self.get_assigned_users(ticket)

        requester = self.get_user_name(requester_id)
        assigned_users_names = [self.get_user_name(user_id) for user_id in assigned_users]

        # Split assigned users into requester, observer, and assigned to
        if len(assigned_users_names) >= 2:
            requester = assigned_users_names[0]
            assigned_to = assigned_users_names[1]
            observer = "N/A"
            if len(assigned_users_names) > 2:
                observer = assigned_users_names[2]
        else:
            requester = "N/A"
            assigned_to = "/N/A"
            observer = "N/A"
        ticket_name = ticket['name']
        ticket_date = ticket['date']
        status_mapping = {
            1: (Fore.CYAN + 'INCOMING' + Style.RESET_ALL),
            2: (Fore.BLUE + 'ASSIGNED' + Style.RESET_ALL),
            3: (Fore.YELLOW + 'PLANNED' + Style.RESET_ALL),
            4: (Fore.MAGENTA + 'WAITING' + Style.RESET_ALL),
            5: (Fore.GREEN + 'SOLVED' + Style.RESET_ALL),
            6: (Fore.RED + 'CLOSED' + Style.RESET_ALL),
            7: (Fore.GREEN + 'ACCEPTED' + Style.RESET_ALL),
            8: (Fore.MAGENTA + 'OBSERVED' + Style.RESET_ALL),
            9: (Fore.YELLOW + 'EVALUATION' + Style.RESET_ALL),
            10: (Fore.CYAN + 'APPROVAL' + Style.RESET_ALL),
            11: (Fore.BLUE + 'TEST' + Style.RESET_ALL),
            12: (Fore.RED + 'QUALIFICATION' + Style.RESET_ALL)
        }
        status = status_mapping.get(ticket['status'], 'UNKNOWN')
        solve_delay_stat = ticket.get('solve_delay_stat', 0)
        delay_formatted = self.format_delay(solve_delay_stat)
        # Parse time to resolve
        time_to_resolve = ticket.get('time_to_resolve', 'N/A')
        table.add_row([ticket_id, ticket_name, ticket_date, requester, observer, assigned_to, status, time_to_resolve, delay_formatted])
        print(table)

    def get_assigned_users(self, ticket):
        headers = self.get_headers()
        ticket_id = ticket['id']
        response = requests.get(f"{self.glpi_url}/Ticket/{ticket_id}/Ticket_User", headers=headers)
        response.raise_for_status()
        users_data = response.json()
        assigned_users = []
        for user_data in users_data:
            user_id = user_data.get('users_id')
            if user_id:
                assigned_users.append(user_id)
        return assigned_users

    def select_user(self):
        try:
            user_id_input = int(input("Enter the ID of the user you're searching for: "))
            if user_id_input in self.user_id_map:
                return user_id_input
            else:
                print("User not found.")
                return None
        except ValueError:
            print("Invalid input. Please enter a numeric value.")
            return None

    def get_ticket_range(self):
        try:
            option = input("Do you want to search in all tickets? (yes/no): ").lower()
            if option == "yes":
                return 1, 7_000  # Assuming 1 million is the maximum ticket ID
            elif option == "no":
                start_id = int(input("Enter the start ID of the ticket range: "))
                end_id = int(input("Enter the end ID of the ticket range: "))
                return start_id, end_id
            else:
                print("Invalid option. Please enter 'yes' or 'no'.")
                return None, None
        except ValueError:
            print("Invalid input. Please enter numeric values.")
            return None, None

    def display_glpi_users_table(self):
        try:
            headers = self.get_headers()
            response = requests.get(f"{self.glpi_url}/User", headers=headers)
            response.raise_for_status()
            users_data = response.json()
            table = PrettyTable(['User ID', 'Name'])
            for user_data in users_data:
                user_id = user_data.get('id')
                user_name = user_data.get('name')
                if user_id and user_name:
                    table.add_row([user_id, user_name])
            print("GLPI Users:")
            print(table)
        except requests.exceptions.HTTPError as e:
            print(f"HTTP Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def send_delay_alert_email(self, ticket):
        # Email configuration
        sender_email = "yassine.ksibi@edu.isetcom.tn"
        receiver_email = "osyzvknyhoycxszivb@cazlg.com"
        app_password = "icoj ulls usyx csvl"

        # Email content
        ticket_id = ticket['id']
        ticket_name = ticket['name']
        assigned_users_names = [self.get_user_name(user_id) for user_id in self.get_assigned_users(ticket)]
        assigned_to = assigned_users_names[1] if len(assigned_users_names) > 1 else "N/A"
        observer = assigned_users_names[2] if len(assigned_users_names) > 2 else "N/A"
        time_to_resolve = ticket.get('time_to_resolve', 'N/A')
        delay_formatted = self.format_delay(ticket.get('solve_delay_stat', 0))

        subject = f"🚨 Ticket Delay Alert: #{ticket_id} - {ticket_name}"
        body = f"""<html>
<head>
    <style>
        body {{
            font-family: 'Arial Rounded MT Bold', sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
            color: #333;
        }}
        .container {{
            width: 80%;
            margin: 50px auto;
            padding: 30px;
            border-radius: 10px;
            background-color: rgba(255, 255, 255, 0.9);
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.2);
            animation: slide-in-fwd-center 0.5s cubic-bezier(0.25, 0.46, 0.45, 0.94) both;
        }}
        @keyframes slide-in-fwd-center {{
            0% {{
                transform: translateZ(-1000px);
                opacity: 0;
            }}
            100% {{
                transform: translateZ(0);
                opacity: 1;
            }}
        }}
        h2 {{
            color: #FFD700;
            margin-bottom: 20px;
            text-align: center;
            font-size: 28px;
            border-bottom: 2px solid #FFD700;
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 15px;
            border-bottom: 1px solid #ddd;
            text-align: left;
            font-size: 16px;
        }}
        th {{
            background-color: #f2f2f2;
            color: #333;
        }}
        td {{
            background-color: #fff;
        }}
        p {{
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 20px;
        }}
        .signature {{
            text-align: center;
            color: #777;
            font-style: italic;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>🚨 Ticket Delay Alert</h2>
        <p>Dear Support Team,</p>
        <p>We would like to inform you that there is a delay in resolving the following ticket:</p>
        <table>
            <tr>
                <th>Field</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Ticket ID:</td>
                <td>{ticket_id}</td>
            </tr>
            <tr>
                <td>Ticket Name:</td>
                <td>{ticket_name}</td>
            </tr>
            <tr>
                <td>Assigned To:</td>
                <td>{assigned_to}</td>
            </tr>
            <tr>
                <td>Observer:</td>
                <td>{observer}</td>
            </tr>
            <tr>
                <td>Time to Resolve:</td>
                <td>{time_to_resolve}</td>
            </tr>
            <tr>
                <td>Delay:</td>
                <td>{delay_formatted}</td>
            </tr>
        </table>
        <p>Please take appropriate action to address this delay.</p>
        <p class="signature">Best regards,<br>Your Support Team</p>
    </div>
</body>
</html>
"""

        message = MIMEMultipart("alternative")
        message['From'] = sender_email
        message['To'] = receiver_email
        message['Subject'] = subject

        # Attach HTML content
        message.attach(MIMEText(body, 'html'))

        # Send email
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, app_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
            server.quit()
            print("\n" + Fore.GREEN + "✓ Delay alert email sent successfully!" + Fore.RESET + "\n")
        except Exception as e:
            print(Fore.RED + "✗ Error sending email:", e, Fore.RESET)
if __name__ == "__main__":
    glpi_url = 'http://10.9.21.201/apirest.php'
    glpi_app_token = 'grbZqYUGjzECRenx9zm0h8jR1kJszbUSFMSQgymq'
    nexpose_manager = NexposeManager(glpi_url, glpi_app_token)
    nexpose_manager.display_glpi_users_table()  # Display GLPI users table
    nexpose_manager.get_assigned_tickets()
