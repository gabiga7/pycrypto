from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
from colorama import init, Fore, Style
import time
import json

# Initialize colorama
init()

class AttributeCertificate:
    def __init__(self, version, holder, issuer, serial_number, validity_period, attributes):
        self.version = version
        self.holder = holder
        self.issuer = issuer
        self.signature_algorithm = None
        self.serial_number = serial_number
        self.validity_period = validity_period
        self.attributes = attributes
        self.signature_value = None

    def sign(self, private_key):
        data_to_sign = "".join([
            str(self.version),
            self.holder,
            self.issuer,
            str(self.serial_number),
            str(self.validity_period),
            json.dumps(self.attributes)
        ]).encode("utf-8")
        self.signature_algorithm = "RSASSA-PKCS1-v1_5 SHA-256"
        self.signature_value = private_key.sign(
            data_to_sign,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    """def verify(self):
        data_to_verify = "".join([
            str(self.version),
            self.holder,
            self.issuer,
            str(self.serial_number),
            str(self.validity_period),
            json.dumps(self.attributes)
        ]).encode("utf-8")
        try:
            self.issuer_public_key.verify(
                self.signature_value,
                data_to_verify,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("Signature is valid.")
        except InvalidSignature:
            print("Signature is invalid.")"""

class Repository:
    def __init__(self):
        self.acs = {}

    def store_ac(self, name, ac):
        self.acs[name] = ac
        print(f"{Fore.WHITE}[{datetime.datetime.now()}] AC stored in the repository for {name}{Style.RESET_ALL}")

    def get_ac(self, name):
        ac = self.acs.get(name)
        if ac:
            print(f"{Fore.WHITE}[{datetime.datetime.now()}] AC retrieved from the repository for {name}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[{datetime.datetime.now()}] No AC found in the repository for {name}{Style.RESET_ALL}")
        return ac

# Define a company's authorization center (ACIssuer), that will issue Attribute Certificates (AC)
class ACIssuer:
    def __init__(self, name, repository):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.key.public_key()
        self.name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
        self.repository = repository

    # Issue an AC to an employee
    def issue_ac(self, employee):
        print(f"{Fore.CYAN}[{datetime.datetime.now()}] --- {self.name.rfc4514_string()} is issuing an AC to {employee.name.rfc4514_string()} ---{Style.RESET_ALL}")
        time.sleep(1)  # Introduce a time delay for a dynamic effect
        ac = AttributeCertificate(
            version=1,
            holder=employee.name.rfc4514_string(),
            issuer=self.name.rfc4514_string(),
            serial_number=x509.random_serial_number(),
            validity_period=f"{datetime.datetime.utcnow()}/{datetime.datetime.utcnow() + datetime.timedelta(days=365)}",
            attributes={"role": employee.role},
            issuer_public_key=self.public_key  # Pass the ACIssuer's public key
        )
        ac.sign(self.key)
        self.repository.store_ac(employee.name.rfc4514_string(), ac)
        return ac

# Define an employee with a role
class Employee:
    def __init__(self, name, role):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
        self.role = role

    @property
    def public_key(self):
        return self.key.public_key()

# Define a company's sensitive system (Server)
class Server:
    def __init__(self, server_config, repository):
        self.name = server_config['name']
        self.ip = server_config['ip']
        self.access_rules = server_config['access_rules']
        self.repository = repository

    def load_access_rules(self, access_rules_file):
        with open(access_rules_file) as file:
            config = json.load(file)
        
        for server_config in config['servers']:
            if server_config['name'] == self.name:
                return server_config['access_rules']
        
        return {}

    def access_request(self, employee):
        print(f"{Fore.CYAN}[{datetime.datetime.now()}] --- {employee.name.rfc4514_string()} ({employee.role}) is trying to access {self.name} ---{Style.RESET_ALL}")
        time.sleep(1)  # Introduce a time delay for a dynamic effect
        ac = self.repository.get_ac(employee.name.rfc4514_string())
        if not ac:
            print(f"{Fore.RED}Access denied: No AC found for {employee.name.rfc4514_string()}.{Style.RESET_ALL}")
            return
        ac.verify()
        role = ac.attributes.get("role")
        if role in self.access_rules and self.access_rules[role]['allow']:
            print(f"{Fore.GREEN}Access granted: {employee.name.rfc4514_string()} ({employee.role}) has accessed {self.name}.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Access denied: {employee.name.rfc4514_string()} ({employee.role}) does not have access to {self.name}.{Style.RESET_ALL}")







# Typing effect function
def typing_effect(text):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(0.05)  # Adjust the delay between characters as needed
    print()

# Load server configurations from config.json
def load_server_configs():
    with open('config.json') as file:
        config = json.load(file)
    return config['servers']



# Create the repository, ACIssuer, employees, and servers
repository = Repository()
ac_issuer = ACIssuer('Authorization Center', repository)


# Create servers based on the configurations
server_configs = load_server_configs()
servers = [Server(server_config, repository) for server_config in server_configs]

print(f"{Fore.MAGENTA}~~~~~~ Demo: Employee Access Control ~~~~~~{Style.RESET_ALL}")

# Create the employees with their roles
alice = Employee('Alice', 'hr')
bob = Employee('Bob', 'worker')
charlie = Employee('Charlie', 'manager')
print("")
print("Employees:")
print(f"Alice: {alice.name.rfc4514_string()} ({alice.role})")
print(f"Bob: {bob.name.rfc4514_string()} ({bob.role})")
print(f"Charlie: {charlie.name.rfc4514_string()} ({charlie.role})")

# The ACIssuer issues ACs to the employees
print("")
typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] Issuing Attribute Certificates...")
typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] AC is beeing issued to Alice...")
time.sleep(1)
alice_ac = ac_issuer.issue_ac(alice)
time.sleep(1)
typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] AC is beeing issued to Bob...")
time.sleep(1)
bob_ac = ac_issuer.issue_ac(bob)
time.sleep(1)
typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] AC is beeing issued to Charlie...")
time.sleep(1)
charlie_ac = ac_issuer.issue_ac(charlie)
typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] Issuing Attribute Certificates done")
time.sleep(2)
print("")

# The employees try to access the servers
typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] Accessing the servers...")
for server in servers:
    typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] Alice is attempting to access {server.name}...")
    time.sleep(1)
    server.access_request(alice)
    time.sleep(1)
    print("")

for server in servers:
    typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] Bob is attempting to access {server.name}...")
    time.sleep(1)
    server.access_request(bob)
    time.sleep(1)
    print("")

for server in servers:
    typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] Charlie is attempting to access {server.name}...")
    time.sleep(1)
    server.access_request(charlie)
    time.sleep(1)
    print("")
time.sleep(1)

print("")
typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] Printing AC attributes for each employee...")
time.sleep(1)
print(f"{Fore.YELLOW}Alice's AC attributes:")
alice_ac_attributes = [(ext.oid._name, ext.value) for ext in alice_ac.extensions]
for attr in alice_ac_attributes:
    print(f"{attr[0]}: {attr[1]}")
print("")

print(f"{Fore.YELLOW}Bob's AC attributes:")
bob_ac_attributes = [(ext.oid._name, ext.value) for ext in bob_ac.extensions]
for attr in bob_ac_attributes:
    print(f"{attr[0]}: {attr[1]}")
print("")

print(f"{Fore.YELLOW}Charlie's AC attributes:")
charlie_ac_attributes = [(ext.oid._name, ext.value) for ext in charlie_ac.extensions]
for attr in charlie_ac_attributes:
    print(f"{attr[0]}: {attr[1]}")
print("")

typing_effect(f"{Fore.YELLOW}[{datetime.datetime.now()}] Printing AC attributes done")
time.sleep(2)



print(f"{Fore.MAGENTA}~~~~~~ End of Demo ~~~~~~{Style.RESET_ALL}")
