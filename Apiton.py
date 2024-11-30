from netmiko import ConnectHandler
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import re
import threading
from tkinter import scrolledtext
import ipaddress


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
        self.time_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.connection_tab, text='Connection')
        self.notebook.add(self.interface_tab, text='Interface Config')
        self.notebook.add(self.dhcp_tab, text='DHCP')
        self.notebook.add(self.time_tab, text='Time Config')
        
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

        # DHCP Frame
        self.dhcp_frame = ttk.LabelFrame(self.dhcp_tab, text="DHCP Pool Configuration", padding="10")
        self.dhcp_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # DHCP Pool List
        self.pools_frame = ttk.LabelFrame(self.dhcp_frame, text="Configured Pools")
        self.pools_frame.pack(fill='x', padx=5, pady=5)
        
        self.pool_listbox = tk.Listbox(self.pools_frame, height=5)
        self.pool_listbox.pack(fill='x', padx=5, pady=5)
        self.pool_listbox.bind('<<ListboxSelect>>', self.on_pool_select)
        
        # DHCP Configuration inputs
        config_frame = ttk.Frame(self.dhcp_frame)
        config_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(config_frame, text="Pool Name:").grid(row=0, column=0, sticky="w")
        self.pool_name_entry = ttk.Entry(config_frame)
        self.pool_name_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(config_frame, text="Network Address:").grid(row=1, column=0, sticky="w")
        self.network_entry = ttk.Entry(config_frame)
        self.network_entry.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(config_frame, text="Subnet Mask:").grid(row=2, column=0, sticky="w")
        self.dhcp_mask_entry = ttk.Entry(config_frame)
        self.dhcp_mask_entry.grid(row=2, column=1, padx=5, pady=2)
        
        ttk.Label(config_frame, text="Default Gateway:").grid(row=3, column=0, sticky="w")
        self.gateway_entry = ttk.Entry(config_frame)
        self.gateway_entry.grid(row=3, column=1, padx=5, pady=2)
        
        ttk.Label(config_frame, text="DNS Servers:").grid(row=4, column=0, sticky="w")
        self.dns_entry = ttk.Entry(config_frame)
        self.dns_entry.grid(row=4, column=1, padx=5, pady=2)
        
        # Excluded addresses
        ttk.Label(config_frame, text="Excluded Addresses:").grid(row=5, column=0, sticky="w")
        self.excluded_entry = ttk.Entry(config_frame)
        self.excluded_entry.grid(row=5, column=1, padx=5, pady=2)
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.dhcp_frame)
        buttons_frame.pack(fill='x', padx=5, pady=5)
        
        self.create_pool_btn = ttk.Button(buttons_frame, text="Create/Update Pool", 
                                        command=self.create_dhcp_pool)
        self.create_pool_btn.pack(side='left', padx=5)
        
        self.delete_pool_btn = ttk.Button(buttons_frame, text="Delete Pool", 
                                        command=self.delete_dhcp_pool)
        self.delete_pool_btn.pack(side='left', padx=5)
        
        self.refresh_pools_btn = ttk.Button(buttons_frame, text="Refresh Pools", 
                                        command=self.refresh_dhcp_pools)
        self.refresh_pools_btn.pack(side='left', padx=5)
        
        # Status display
        self.status_text = scrolledtext.ScrolledText(self.dhcp_frame, height=5, width=50)
        self.status_text.pack(fill='x', padx=5, pady=5)

        # Initially disable interface configuration
        self.set_interface_frame_state('disabled')

        # Create the time configuration frame
        self.time_frame = ttk.LabelFrame(self.time_tab, text="Time Configuration", padding="10")
        self.time_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # Time configuration mode selection
        self.time_mode = tk.StringVar(value="ntp")
        ttk.Radiobutton(self.time_frame, text="NTP", variable=self.time_mode, 
                        value="ntp", command=self.toggle_time_mode).pack(anchor="w", pady=2)
        ttk.Radiobutton(self.time_frame, text="Manual", variable=self.time_mode, 
                        value="manual", command=self.toggle_time_mode).pack(anchor="w", pady=2)

        # NTP configuration frame
        self.ntp_frame = ttk.LabelFrame(self.time_frame, text="NTP Configuration", padding="10")
        self.ntp_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(self.ntp_frame, text="NTP Server:").pack(anchor="w")
        self.ntp_server_entry = ttk.Entry(self.ntp_frame)
        self.ntp_server_entry.pack(fill='x', padx=5, pady=2)

        self.ntp_btn = ttk.Button(self.ntp_frame, text="Configure NTP", 
                                command=self.configure_ntp)
        self.ntp_btn.pack(pady=5)

        # Manual time configuration frame
        self.manual_frame = ttk.LabelFrame(self.time_frame, text="Manual Time Configuration", 
                                        padding="10")
        self.manual_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(self.manual_frame, text="Time (HH:MM:SS):").pack(anchor="w")
        self.time_entry = ttk.Entry(self.manual_frame)
        self.time_entry.pack(fill='x', padx=5, pady=2)

        ttk.Label(self.manual_frame, text="Date (YYYY-MM-DD):").pack(anchor="w")
        self.date_entry = ttk.Entry(self.manual_frame)
        self.date_entry.pack(fill='x', padx=5, pady=2)

        self.manual_btn = ttk.Button(self.manual_frame, text="Set Time", 
                                command=self.set_manual_time)
        self.manual_btn.pack(pady=5)

        # Initially hide manual frame
        self.manual_frame.pack_forget()

    def set_interface_frame_state(self, state):
        """Enable or disable interface configuration widgets"""
        for child in self.interface_frame.winfo_children():
            child.configure(state=state)

    def set_dhcp_frame_state(self, state):
        """Enable or disable DHCP configuration widgets"""
        for child in self.dhcp_frame.winfo_children():
            if isinstance(child, ttk.Frame) or isinstance(child, ttk.LabelFrame):
                for subchild in child.winfo_children():
                    if not isinstance(subchild, scrolledtext.ScrolledText):
                        subchild.configure(state=state)

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
        if self.ssh_connection:
            self.set_dhcp_frame_state('normal')
            self.refresh_dhcp_pools()


    def get_interfaces(self):
        """Get available interfaces from router"""
        if self.ssh_connection:
            output = self.ssh_connection.send_command("show ip interface brief")
            # Filter out interface names only
            interfaces = [line.split()[0] for line in output.splitlines()[1:] 
                        if line.strip() and not line.startswith("Interface")]
            self.interface_dropdown['values'] = interfaces

    def refresh_dhcp_pools(self):
        """Refresh the list of DHCP pools from the router"""
        if self.ssh_connection:
            try:
                output = self.ssh_connection.send_command("show ip dhcp pool")
                self.pool_listbox.delete(0, tk.END)
                
                # Parse and display pools
                current_pool = None
                for line in output.splitlines():
                    if line.startswith("Pool"):
                        current_pool = line.split()[1]
                        self.pool_listbox.insert(tk.END, current_pool)
                
                self.status_text.delete(1.0, tk.END)
                self.status_text.insert(tk.END, "DHCP pools refreshed successfully\n")
            except Exception as e:
                self.status_text.insert(tk.END, f"Error refreshing pools: {str(e)}\n")

    def on_pool_select(self, event):
        """Handle pool selection from listbox"""
        if not self.pool_listbox.curselection():
            return
            
        selected_pool = self.pool_listbox.get(self.pool_listbox.curselection())
        if self.ssh_connection:
            try:
                output = self.ssh_connection.send_command(f"show running-config | section ip dhcp pool {selected_pool}")
                
                # Clear existing entries
                self.pool_name_entry.delete(0, tk.END)
                self.network_entry.delete(0, tk.END)
                self.dhcp_mask_entry.delete(0, tk.END)
                self.gateway_entry.delete(0, tk.END)
                self.dns_entry.delete(0, tk.END)
                
                # Parse and fill in pool details
                self.pool_name_entry.insert(0, selected_pool)
                
                for line in output.splitlines():
                    if "network" in line:
                        parts = line.split()
                        self.network_entry.insert(0, parts[1])
                        self.dhcp_mask_entry.insert(0, parts[2])
                    elif "default-router" in line:
                        self.gateway_entry.insert(0, line.split()[1])
                    elif "dns-server" in line:
                        self.dns_entry.insert(0, ' '.join(line.split()[1:]))
                        
            except Exception as e:
                self.status_text.insert(tk.END, f"Error loading pool details: {str(e)}\n")

    def create_dhcp_pool(self):
        """Create or update a DHCP pool"""
        if not self.ssh_connection:
            return
            
        try:
            # Validate inputs
            if not all([self.pool_name_entry.get(), self.network_entry.get(), 
                    self.dhcp_mask_entry.get(), self.gateway_entry.get()]):
                raise ValueError("Pool name, network, mask, and gateway are required")
                
            # Prepare commands
            commands = [
                f"ip dhcp pool {self.pool_name_entry.get()}",
                f"network {self.network_entry.get()} {self.dhcp_mask_entry.get()}",
                f"default-router {self.gateway_entry.get()}"
            ]
            
            # Add DNS if specified
            if self.dns_entry.get():
                commands.append(f"dns-server {self.dns_entry.get()}")
                
            # Add excluded addresses if specified
            if self.excluded_entry.get():
                for addr in self.excluded_entry.get().split():
                    commands.insert(0, f"ip dhcp excluded-address {addr}")
                    
            # Apply configuration
            self.ssh_connection.config_mode()
            output = self.ssh_connection.send_config_set(commands)
            self.ssh_connection.exit_config_mode()
            
            self.status_text.insert(tk.END, "DHCP pool created/updated successfully\n")
            self.refresh_dhcp_pools()
            
        except Exception as e:
            self.status_text.insert(tk.END, f"Error creating DHCP pool: {str(e)}\n")

    def delete_dhcp_pool(self):
        """Delete selected DHCP pool"""
        if not self.pool_listbox.curselection():
            return
            
        selected_pool = self.pool_listbox.get(self.pool_listbox.curselection())
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete pool '{selected_pool}'?"):
            try:
                commands = [f"no ip dhcp pool {selected_pool}"]
                self.ssh_connection.config_mode()
                output = self.ssh_connection.send_config_set(commands)
                self.ssh_connection.exit_config_mode()
                
                self.status_text.insert(tk.END, f"DHCP pool '{selected_pool}' deleted successfully\n")
                self.refresh_dhcp_pools()
                
            except Exception as e:
                self.status_text.insert(tk.END, f"Error deleting pool: {str(e)}\n")

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

    def toggle_time_mode(self):
        """Toggle between NTP and manual time configuration"""
        if self.time_mode.get() == "ntp":
            self.manual_frame.pack_forget()
            self.ntp_frame.pack(fill='x', padx=5, pady=5)
        else:
            self.ntp_frame.pack_forget()
            self.manual_frame.pack(fill='x', padx=5, pady=5)

    def configure_ntp(self):
        """Configure NTP on the router"""
        if not self.ssh_connection:
            messagebox.showerror("Error", "Not connected to router")
            return

        ntp_server = self.ntp_server_entry.get().strip()
        if not ntp_server:
            messagebox.showerror("Error", "Please enter NTP server address")
            return

        try:
            commands = [
                'conf t',
                f'ntp server {ntp_server}',
                'end'
            ]
            output = self.ssh_connection.send_config_set(commands)
            messagebox.showinfo("Success", "NTP configuration applied successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to configure NTP: {str(e)}")

    def set_manual_time(self):
        """Set manual time on the router"""
        if not self.ssh_connection:
            messagebox.showerror("Error", "Not connected to router")
            return

        time = self.time_entry.get().strip()
        date = self.date_entry.get().strip()

        if not time or not date:
            messagebox.showerror("Error", "Please enter both time and date")
            return

        try:
            # Format: clock set HH:MM:SS DD MONTH YYYY
            date_parts = date.split('-')
            if len(date_parts) != 3:
                messagebox.showerror("Error", "Invalid date format. Use YYYY-MM-DD")
                return

            # Convert month number to name
            months = ['January', 'February', 'March', 'April', 'May', 'June',
                    'July', 'August', 'September', 'October', 'November', 'December']
            month_name = months[int(date_parts[1]) - 1]

            command = f'clock set {time} {date_parts[2]} {month_name} {date_parts[0]}'
            output = self.ssh_connection.send_command_timing(command)
            
            messagebox.showinfo("Success", "Time set successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set time: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = RouterConfigGUI(root)
    root.mainloop()