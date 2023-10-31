from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from main import menu

#Générer les paires de clés dans un fichier
def Generate_RSA_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Write private_key to disk for safe keeping
    with open("private_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"Azertyuiop!123"),
        ))

    # Write public_key to disk for safe keeping
    public_key = key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


#Générer un certificat autosigné par RSA
def generer_certificat(nom, prenom, email):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = f"{prenom} {nom}"
    cert.get_subject().emailAddress = email
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Valable pour un an
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')

    with open(f"{email}.pem", "wb") as cert_file:
         cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))



#Chiffrer un message de votre choix par ce certificat
def crypter_msg_certificate(certificate_path, message):
    with open(certificate_path, "rb") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
        public_key = cert.public_key()

        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return ciphertext
def certificat():
    print("****************************"
          "**    Certificat (RSA)    **"
          "****************************")
    print("1) Générer les paires de clés dans un fichier")
    print("2) Générer un certificat autosigné par RSA")
    print("3) Chiffrer un message de votre choix par ce certificat")
    print("4) Revenir au menu principal")

    choix2 =input("Donnez votre choix :")
    if choix2 == '1':
        Generate_RSA_key()
    elif choix2 == '2':
        generer_certificat("private_key.pem", "self_signed_certificate.pem")
        print("Self-Signed Certificate generated.")
    elif choix2 == '3':
        message_to_encrypt = input(print("Enter un message:"))
        encrypted_message = crypter_msg_certificate("self_signed_certificate.pem", message_to_encrypt)
        print("Message Crypté avec la certificat:", encrypted_message)
    else:
        print("#################"
              "#Menu principal#"
              "################")
        menu()