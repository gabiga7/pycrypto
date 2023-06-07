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
