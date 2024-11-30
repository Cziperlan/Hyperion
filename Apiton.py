from netmiko import ConnectHandler
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import re
import threading

class DHCPPool:
    def __init__(self, name, network, mask, dns=None):
        self.name = name
        self.network = network
        self.mask = mask
        self.dns = dns if dns else ""

class RouterConfigGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cisco Router Configuration")
        self.ssh_connection = None
        
        # Create notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create tabs
        self.connection_tab = ttk.Frame(self.notebook)
        self.interface_tab = ttk.Frame(self.notebook)
        self.dhcp_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.connection_tab, text='Connection')
        self.notebook.add(self.interface_tab, text='Interface Config')
        self.notebook.add(self.dhcp_tab, text='DHCP')
        
        # Connection Frame
        self.conn_frame = ttk.LabelFrame(self.connection_tab, text="SSH Connection", padding="10")
        self.conn_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Connection inputs
        ttk.Label(self.conn_frame, text="IP Address:").grid(row=0, column=0, sticky="w")
        self.ip_entry = ttk.Entry(self.conn_frame)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(self.conn_frame, text="Username:").grid(row=1, column=0, sticky="w")
        self.username_entry = ttk.Entry(self.conn_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(self.conn_frame, text="Password:").grid(row=2, column=0, sticky="w")
        self.password_entry = ttk.Entry(self.conn_frame, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=2)
        
        self.connect_btn = ttk.Button(self.conn_frame, text="Connect", command=self.connect_to_router)
        self.connect_btn.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Interface Frame
        self.interface_frame = ttk.Frame(self.interface_tab, padding="10")
        self.interface_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Interface dropdown
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(self.interface_frame, textvariable=self.interface_var)
        self.interface_dropdown.grid(row=0, column=0, columnspan=2, padx=5, pady=2, sticky="ew")
        self.interface_dropdown.bind('<<ComboboxSelected>>', self.on_interface_select)
        
        # IP Address configuration
        ttk.Label(self.interface_frame, text="IP Address:").grid(row=1, column=0, sticky="w")
        self.ip_addr_entry = ttk.Entry(self.interface_frame)
        self.ip_addr_entry.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(self.interface_frame, text="Subnet Mask:").grid(row=2, column=0, sticky="w")
        self.subnet_entry = ttk.Entry(self.interface_frame)
        self.subnet_entry.grid(row=2, column=1, padx=5, pady=2)
        
        # Interface status checkbox
        self.status_var = tk.BooleanVar()
        self.status_check = ttk.Checkbutton(self.interface_frame, text="Interface Enabled", 
                                          variable=self.status_var, command=self.toggle_interface_status)
        self.status_check.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Apply IP button
        self.apply_btn = ttk.Button(self.interface_frame, text="Apply IP Configuration", 
                                  command=self.apply_ip_config)
        self.apply_btn.grid(row=4, column=0, columnspan=2, pady=5)
        
        # Initially disable interface configuration
        self.set_interface_frame_state('disabled')

    def set_interface_frame_state(self, state):
        """Enable or disable interface configuration widgets"""
        for child in self.interface_frame.winfo_children():
            child.configure(state=state)

    def connect_to_router(self):
        """Establish SSH connection to the router"""
        try:
            device = {
                'device_type': 'cisco_ios',
                'ip': self.ip_entry.get(),
                'username': self.username_entry.get(),
                'password': self.password_entry.get(),
                'secret': self.password_entry.get()  # Using the same password for enable secret
            }
            
            self.ssh_connection = ConnectHandler(**device)
            self.ssh_connection.enable()  # Enter enable mode
            messagebox.showinfo("Success", "Connected to router successfully!")
            
            # Get and populate interfaces
            self.get_interfaces()
            self.set_interface_frame_state('normal')
            
            # Switch to interface tab
            self.notebook.select(1)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}")

    def get_interfaces(self):
        """Get available interfaces from router"""
        if self.ssh_connection:
            output = self.ssh_connection.send_command("show ip interface brief")
            # Filter out interface names only
            interfaces = [line.split()[0] for line in output.splitlines()[1:] 
                        if line.strip() and not line.startswith("Interface")]
            self.interface_dropdown['values'] = interfaces

    def on_interface_select(self, event):
        """Handle interface selection"""
        if self.ssh_connection and self.interface_var.get():
            interface = self.interface_var.get()
            # Get interface status
            output = self.ssh_connection.send_command(f"show ip interface {interface}")
            
            # Update status checkbox
            if "administratively down" in output:
                self.status_var.set(False)
            else:
                self.status_var.set(True)
                
            # Get IP address and subnet if configured
            ip_match = re.search(r"Internet address is (\d+\.\d+\.\d+\.\d+)/(\d+)", output)
            if ip_match:
                self.ip_addr_entry.delete(0, tk.END)
                self.ip_addr_entry.insert(0, ip_match.group(1))
                # Convert CIDR to subnet mask
                mask_bits = int(ip_match.group(2))
                mask = '.'.join([str((0xffffffff << (32 - mask_bits) >> i) & 0xff) 
                               for i in [24, 16, 8, 0]])
                self.subnet_entry.delete(0, tk.END)
                self.subnet_entry.insert(0, mask)

    def toggle_interface_status(self):
        """Toggle interface administrative status"""
        if self.ssh_connection and self.interface_var.get():
            interface = self.interface_var.get()
            status = "no shutdown" if self.status_var.get() else "shutdown"
            
            # Execute in separate thread to avoid GUI freezing
            thread = threading.Thread(target=self._apply_interface_status, 
                                   args=(interface, status))
            thread.start()

    def _apply_interface_status(self, interface, status):
        """Apply interface status change"""
        try:
            commands = [
                f"interface {interface}",
                status
            ]
            self.ssh_connection.config_mode()
            self.ssh_connection.send_config_set(commands)
            self.ssh_connection.exit_config_mode()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change interface status: {str(e)}")

    def apply_ip_config(self):
        """Apply IP address configuration to interface"""
        if self.ssh_connection and self.interface_var.get():
            interface = self.interface_var.get()
            ip_address = self.ip_addr_entry.get()
            subnet_mask = self.subnet_entry.get()
            
            try:
                commands = [
                    f"interface {interface}",
                    f"ip address {ip_address} {subnet_mask}"
                ]
                self.ssh_connection.config_mode()
                output = self.ssh_connection.send_config_set(commands)
                self.ssh_connection.exit_config_mode()
                messagebox.showinfo("Success", "IP configuration applied successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to apply IP configuration: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = RouterConfigGUI(root)
    root.mainloop()