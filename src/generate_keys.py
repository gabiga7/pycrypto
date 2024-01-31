from Crypto.PublicKey import RSA
import shutil
import os

def generate_rsa_keypair(directory, key_name="id"):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Convertir les clés en une seule ligne et les reconvertir en bytes
    private_key_one_line = private_key.decode().replace('\n', '').encode()
    public_key_one_line = public_key.decode().replace('\n', '').encode()

    # Enregistrer la clé privée en une seule ligne en tant que bytes
    with open(os.path.join(directory, f"{key_name}.pem"), "wb") as priv_file:
        priv_file.write(private_key_one_line)

    # Enregistrer la clé publique en une seule ligne en tant que bytes
    with open(os.path.join(directory, f"{key_name}.pub"), "wb") as pub_file:
        pub_file.write(public_key_one_line)

    return os.path.join(directory, f"{key_name}.pub")

# Générer les paires de clés pour Alice et Bob
alice_public_key_path = generate_rsa_keypair("alice_pc")
bob_public_key_path = generate_rsa_keypair("bob_pc")

# Assurez-vous que le dossier ac_issuer existe
ac_issuer_path = os.path.join("ac_issuer")
if not os.path.exists(ac_issuer_path):
    os.makedirs(ac_issuer_path)

# Copier les clés publiques dans le dossier ac_issuer
shutil.copy(alice_public_key_path, os.path.join(ac_issuer_path, "alice_dupont.pub"))
shutil.copy(bob_public_key_path, os.path.join(ac_issuer_path, "bob_dumas.pub"))

print("Les clés ont été générées et copiées avec succès.")
