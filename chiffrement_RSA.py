from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from main import menu
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


#Générer les paires de clés dans un fichier
def generation_cle():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("receiver_private.pem", "wb")
    file_out.write(private_key)
    file_out.close()
    public_key = key.publickey().export_key()
    file_out = open("receiver_public.pem", "wb")
    file_out.write(public_key)
    file_out.close()

#Chiffrer un message de votre choix par RSA
def chiffre_message_rsa():
    data = "Hello from the other side of the mother nature".encode("utf-8")
    recipient_public_key = RSA.import_key(open("receiver_public.pem").read())
    # Encrypt the session key with the public RSA key of the receiver
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    enc_data = cipher_rsa.encrypt(data)
    with open("encrypted_rsa", 'wb') as f:
        f.write(enc_data)

#Déchiffrer le message (b)
def dechiffrer_msg_rsa():
    private_key = RSA.import_key(open("receiver_private.pem").read())
    with open("encrypted_rsa", 'rb') as f:
        enc_data = f.read()
    # Decrypt the data with the private RSA key of the receiver
    cipher_rsa = PKCS1_OAEP.new(private_key)
    data = cipher_rsa.decrypt(enc_data)
    print(f"The original message: {data.decode('utf-8')}")

#Signer un message de votre choix par RSA
def signature_msg_rsa(message, private_key_path):
    with open(private_key_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(private_file.read(), password=None)
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

#Vérifier la signature du message (d)
def verification_signature(message, signature, public_key_path):
    with open(public_key_path, "rb") as public_file:
        public_key = serialization.load_pem_public_key(public_file.read())
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
def choix_chiffrement():

    print("****************************"
          "**    Chiffrement (RSA)    **"
          "****************************")
    print("1-Générer les paires de clés dans un fichier ")
    print("2- Chiffrer un message de votre choix par RSA ")
    print("3- Déchiffrer le message   ")
    print("4- Signer un message de votre choix par RSA ")
    print("5- Vérifier la signature du message  ")
    choice=input("Donner votre choix:")
    if choice == '1':
        generation_cle()
    elif choice == '2':
        message = input("Enter a message to encrypt using RSA: ")
        chiffrer_message = chiffre_message_rsa(message, "public_key.pem")
        print("message chiffré:", chiffrer_message)
        decfiffrer_message = dechiffrer_msg_rsa(chiffrer_message, "private_key.pem")
        print("message déchiffré:", decfiffrer_message)
    elif choice == '3':
        message_to_sign = input("Enter a message to sign with RSA: ")
        signature = signature_msg_rsa(message_to_sign, "private_key.pem")
        print("Message signé.", signature)
    elif choice == '4':
        message_to_verify = input("Enter a message to verify its RSA signature: ")
        provided_signature = input("Enter the provided signature: ")
        if verification_signature(message_to_verify, provided_signature, "public_key.pem"):
            print("Signature valide.")
        else:
            print("Signature n'est pas valide.")
    else:
        print("#################"
              "#Menu principal#"
              "################")
        menu()
