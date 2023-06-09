import json
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.simpledialog import askstring
class ServerManagerGUI:
    def __init__(self):
        self.config_file = "config.json"
        self.servers = []

        # Load server configuration from config.json
        self.load_server_configuration()

        self.root = tk.Tk()
        self.root.title("Server Manager")

        # Create the GUI components
        self.create_server_frame()
        self.create_access_rules_frame()
        self.create_buttons()

    def load_server_configuration(self):
        try:
            with open(self.config_file) as file:
                config = json.load(file)
                self.servers = config.get("servers", [])
        except (FileNotFoundError, json.JSONDecodeError):
            self.servers = []

    def save_server_configuration(self):
        config = {"servers": self.servers}
        with open(self.config_file, "w") as file:
            json.dump(config, file, indent=4)

    def create_server_frame(self):
        self.server_frame = tk.LabelFrame(self.root, text="Servers")
        self.server_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.server_listbox = tk.Listbox(self.server_frame)
        self.server_listbox.pack(side="left", fill="both", expand=True)

        self.server_scrollbar = tk.Scrollbar(self.server_frame)
        self.server_scrollbar.pack(side="right", fill="y")

        self.server_listbox.config(yscrollcommand=self.server_scrollbar.set)
        self.server_scrollbar.config(command=self.server_listbox.yview)

        self.server_listbox.bind("<<ListboxSelect>>", self.on_server_select)

    def create_access_rules_frame(self):
        self.access_rules_frame = tk.LabelFrame(self.root, text="Access Rules")
        self.access_rules_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.access_rules_text = tk.Text(self.access_rules_frame)
        self.access_rules_text.pack(side="left", fill="both", expand=True)

        self.access_rules_scrollbar = tk.Scrollbar(self.access_rules_frame)
        self.access_rules_scrollbar.pack(side="right", fill="y")

        self.access_rules_text.config(yscrollcommand=self.access_rules_scrollbar.set)
        self.access_rules_scrollbar.config(command=self.access_rules_text.yview)

    def create_buttons(self):
        self.buttons_frame = tk.Frame(self.root)
        self.buttons_frame.pack(pady=10)

        self.add_button = tk.Button(self.buttons_frame, text="Add Server", command=self.add_server)
        self.add_button.pack(side="left", padx=5)

        self.delete_button = tk.Button(self.buttons_frame, text="Delete Server", command=self.delete_server)
        self.delete_button.pack(side="left", padx=5)

        self.generate_default_access_rule_button = tk.Button(self.buttons_frame, text="Generate Default Access Rule", command=self.generate_default_access_rule)
        self.generate_default_access_rule_button.pack(side="left", padx=5)

        self.save_server_configuration_button = tk.Button(self.buttons_frame, text="Save Server Configuration", command=self.save_server_configuration)
        self.save_server_configuration_button.pack(side="left", padx=5)

    def add_server(self):
        server_name = askstring("Add Server", "Enter server name:")
        if server_name:
            server_ip = askstring("Add Server", "Enter server IP:")
            if server_ip:
                server = {"name": server_name, "ip": server_ip, "access_rules": {}}
                self.servers.append(server)
                self.server_listbox.insert(tk.END, server_name)

    def delete_server(self):
        selected_index = self.server_listbox.curselection()
        if selected_index:
            confirmed = messagebox.askyesno("Delete Server", "Are you sure you want to delete this server?")
            if confirmed:
                del self.servers[selected_index[0]]
                self.server_listbox.delete(selected_index)

    def on_server_select(self, event):
        selected_index = self.server_listbox.curselection()
        if selected_index:
            server = self.servers[selected_index[0]]
            self.access_rules_text.delete(1.0, tk.END)
            self.access_rules_text.insert(tk.END, json.dumps(server["access_rules"], indent=4))

    def generate_default_access_rule(self):
        selected_index = self.server_listbox.curselection()
        if selected_index:
            server = self.servers[selected_index[0]]
            server["access_rules"]["manager"] = {"allow": True}
            server["access_rules"]["hr"] = {"allow": False}
            server["access_rules"]["worker"] = {"allow": False}
            self.access_rules_text.delete(1.0, tk.END)
            self.access_rules_text.insert(tk.END, json.dumps(server["access_rules"], indent=4))

    def run(self):
        self.root.mainloop()

    def save_and_exit(self):
        self.save_server_configuration()
        self.root.destroy()

# Run the server manager GUI
server_manager = ServerManagerGUI()
server_manager.run()
server_manager.save_and_exit()
