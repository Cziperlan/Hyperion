import tkinter as tk
from tkinter import messagebox, scrolledtext, StringVar, Menu
from tkinter import ttk
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# Define the connection settings for the Cisco 7200 router
ROUTER = {
    "device_type": "cisco_ios",
    "host": "192.168.0.18",  # Replace with actual router IP
    "username": "admin",     # Replace with actual username
    "password": "admin",     # Replace with actual password
    "secret": "admin",       # Replace with enable secret if required
}

class CiscoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cisco 7200 Router Manager - GNS3")

        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create the "Main" tab with router commands and interface configuration
        self.main_tab = tk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text="Main")

        # Create the "DHCP Configuration" tab
        self.dhcp_tab = tk.Frame(self.notebook)
        self.notebook.add(self.dhcp_tab, text="DHCP Configuration")

        # Menu setup
        self.menu = Menu(root)
        self.root.config(menu=self.menu)
        
        # Create a "File" menu with an exit option
        self.file_menu = Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Exit", command=root.quit)

        # Command section in the main tab
        self.command_label = tk.Label(self.main_tab, text="Router Commands")
        self.command_label.grid(row=0, column=0, padx=10, pady=5)
        
        self.command_entry = tk.Entry(self.main_tab, width=40)
        self.command_entry.grid(row=0, column=1, padx=10, pady=5)
        
        self.run_button = tk.Button(self.main_tab, text="Run Command", command=self.run_command)
        self.run_button.grid(row=0, column=2, padx=10, pady=5)
        
        # Scrollable output area
        self.output_area = scrolledtext.ScrolledText(self.main_tab, wrap=tk.WORD, width=60, height=20)
        self.output_area.grid(row=1, column=0, columnspan=3, padx=10, pady=10)
        
        # Common commands buttons
        self.interface_button = tk.Button(self.main_tab, text="Show Interfaces", command=self.show_interfaces)
        self.interface_button.grid(row=2, column=0, padx=10, pady=5)

        self.route_button = tk.Button(self.main_tab, text="Show IP Route", command=self.show_ip_route)
        self.route_button.grid(row=2, column=1, padx=10, pady=5)

        self.clear_button = tk.Button(self.main_tab, text="Clear Output", command=self.clear_output)
        self.clear_button.grid(row=2, column=2, padx=10, pady=5)

        # Interface dropdown menu
        self.intf_label = tk.Label(self.main_tab, text="Select Interface:")
        self.intf_label.grid(row=3, column=0, padx=10, pady=5)

        self.selected_interface = StringVar(self.main_tab)
        self.intf_menu = tk.OptionMenu(self.main_tab, self.selected_interface, "Loading...")
        self.intf_menu.grid(row=3, column=1, padx=10, pady=5)

        # IP Address and Subnet Mask Entry
        self.ip_label = tk.Label(self.main_tab, text="IP Address:")
        self.ip_label.grid(row=4, column=0, padx=10, pady=5)
        
        self.ip_entry = tk.Entry(self.main_tab, width=20)
        self.ip_entry.grid(row=4, column=1, padx=10, pady=5)
        
        self.mask_label = tk.Label(self.main_tab, text="Subnet Mask:")
        self.mask_label.grid(row=5, column=0, padx=10, pady=5)
        
        self.mask_entry = tk.Entry(self.main_tab, width=20)
        self.mask_entry.grid(row=5, column=1, padx=10, pady=5)
        
        self.set_ip_button = tk.Button(self.main_tab, text="Set IP Address", command=self.set_ip_address)
        self.set_ip_button.grid(row=6, column=1, padx=10, pady=5)

        # Initialize interfaces in dropdown
        self.initialize_interfaces()

        # DHCP Configuration section (in the DHCP tab)
        self.dhcp_pool_name_label = tk.Label(self.dhcp_tab, text="DHCP Pool Name:")
        self.dhcp_pool_name_label.grid(row=0, column=0, padx=10, pady=5)
        self.dhcp_pool_name_entry = tk.Entry(self.dhcp_tab, width=20)
        self.dhcp_pool_name_entry.grid(row=0, column=1, padx=10, pady=5)
        
        self.dhcp_network_label = tk.Label(self.dhcp_tab, text="Network Range:")
        self.dhcp_network_label.grid(row=1, column=0, padx=10, pady=5)
        self.dhcp_network_entry = tk.Entry(self.dhcp_tab, width=20)
        self.dhcp_network_entry.grid(row=1, column=1, padx=10, pady=5)
        
        self.dhcp_subnet_mask_label = tk.Label(self.dhcp_tab, text="Subnet Mask:")
        self.dhcp_subnet_mask_label.grid(row=2, column=0, padx=10, pady=5)
        self.dhcp_subnet_mask_entry = tk.Entry(self.dhcp_tab, width=20)
        self.dhcp_subnet_mask_entry.grid(row=2, column=1, padx=10, pady=5)

        self.dhcp_gateway_label = tk.Label(self.dhcp_tab, text="Default Gateway:")
        self.dhcp_gateway_label.grid(row=3, column=0, padx=10, pady=5)
        self.dhcp_gateway_entry = tk.Entry(self.dhcp_tab, width=20)
        self.dhcp_gateway_entry.grid(row=3, column=1, padx=10, pady=5)
        
        self.dhcp_dns_label = tk.Label(self.dhcp_tab, text="DNS Server:")
        self.dhcp_dns_label.grid(row=4, column=0, padx=10, pady=5)
        self.dhcp_dns_entry = tk.Entry(self.dhcp_tab, width=20)
        self.dhcp_dns_entry.grid(row=4, column=1, padx=10, pady=5)

        # Button to apply DHCP settings
        self.dhcp_configure_button = tk.Button(self.dhcp_tab, text="Apply DHCP Configuration", command=self.configure_dhcp)
        self.dhcp_configure_button.grid(row=5, column=1, padx=10, pady=10)

    def connect_router(self):
        try:
            connection = ConnectHandler(**ROUTER)
            connection.enable()
            return connection
        except NetmikoTimeoutException:
            messagebox.showerror("Connection Error", "Connection to router timed out.")
        except NetmikoAuthenticationException:
            messagebox.showerror("Authentication Error", "Authentication failed. Check username and password.")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to router: {e}")
        return None

    def run_command(self):
        command = self.command_entry.get()
        if command:
            connection = self.connect_router()
            if connection:
                try:
                    output = connection.send_command(command)
                    self.output_area.insert(tk.END, f"> {command}\n{output}\n\n")
                except Exception as e:
                    messagebox.showerror("Command Error", f"Failed to execute command: {e}")
                finally:
                    connection.disconnect()

    def show_interfaces(self):
        connection = self.connect_router()
        if connection:
            try:
                output = connection.send_command("show ip interface brief")
                self.output_area.insert(tk.END, "Interface Status:\n" + output + "\n\n")
            except Exception as e:
                messagebox.showerror("Interface Error", f"Failed to retrieve interfaces: {e}")
            finally:
                connection.disconnect()

    def show_ip_route(self):
        connection = self.connect_router()
        if connection:
            try:
                output = connection.send_command("show ip route")
                self.output_area.insert(tk.END, "IP Routing Table:\n" + output + "\n\n")
            except Exception as e:
                messagebox.showerror("Route Error", f"Failed to retrieve IP routes: {e}")
            finally:
                connection.disconnect()

    def clear_output(self):
        self.output_area.delete(1.0, tk.END)

    def initialize_interfaces(self):
        connection = self.connect_router()
        if connection:
            try:
                output = connection.send_command("show ip interface brief")
                interfaces = self.parse_interfaces(output)
                self.update_interface_menu(interfaces)
                if interfaces:
                    self.selected_interface.set(interfaces[0])  # Default to the first interface
            except Exception as e:
                messagebox.showerror("Interface Initialization Error", f"Failed to initialize interfaces: {e}")
            finally:
                connection.disconnect()

    def parse_interfaces(self, output):
        interfaces = []
        lines = output.splitlines()[1:]  # Skip the header line
        for line in lines:
            parts = line.split()
            if len(parts) > 1:
                interfaces.append(parts[0])
        return interfaces

    def update_interface_menu(self, interfaces):
        menu = self.intf_menu["menu"]
        menu.delete(0, "end")
        for interface in interfaces:
            menu.add_command(label=interface, command=lambda value=interface: self.selected_interface.set(value))

    def set_ip_address(self):
        interface = self.selected_interface.get()
        ip_address = self.ip_entry.get()
        subnet_mask = self.mask_entry.get()
        if interface and ip_address and subnet_mask:
            connection = self.connect_router()
            if connection:
                try:
                    connection.send_config_set([f"interface {interface}", f"ip address {ip_address} {subnet_mask}"])
                    messagebox.showinfo("Success", f"IP address {ip_address} set on interface {interface}")
                except Exception as e:
                    messagebox.showerror("Configuration Error", f"Failed to set IP address: {e}")
                finally:
                    connection.disconnect()

    def configure_dhcp(self):
        pool_name = self.dhcp_pool_name_entry.get()
        network = self.dhcp_network_entry.get()
        subnet_mask = self.dhcp_subnet_mask_entry.get()
        gateway = self.dhcp_gateway_entry.get()
        dns = self.dhcp_dns_entry.get()
        
        if pool_name and network and subnet_mask:
            connection = self.connect_router()
            if connection:
                try:
                    commands = [
                        f"ip dhcp pool {pool_name}",
                        f"network {network} {subnet_mask}",
                        f"default-router {gateway}" if gateway else "",
                        f"dns-server {dns}" if dns else "",
                    ]
                    connection.send_config_set(commands)
                    messagebox.showinfo("DHCP Config", "DHCP configuration applied successfully")
                except Exception as e:
                    messagebox.showerror("DHCP Error", f"Failed to apply DHCP configuration: {e}")
                finally:
                    connection.disconnect()

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")

        self.username_label = tk.Label(root, text="Username:")
        self.username_label.grid(row=0, column=0, padx=10, pady=10)
        self.username_entry = tk.Entry(root)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        self.password_label = tk.Label(root, text="Password:")
        self.password_label.grid(row=1, column=0, padx=10, pady=10)
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        self.login_button = tk.Button(root, text="Login", command=self.check_login)
        self.login_button.grid(row=2, column=1, padx=10, pady=10)

    def check_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username == "admin" and password == "admin":
            self.root.withdraw()
            main_root = tk.Toplevel(self.root)
            app = CiscoGUI(main_root)
        else:
            messagebox.showerror("Login Error", "Invalid username or password")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    login_app = LoginWindow(root)
    root.mainloop()
