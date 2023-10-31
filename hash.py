from authentification import *
from hashlib import sha256
import time
import bcrypt
from main import menu


#Haché le mot par sha256
def hash256(password):
    import hashlib
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

#Haché le mot en générant un salt (bcrypt)
def hashsalt_bcrypt(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


#Attaquer par dictionnaire le mot inséré
def attaque_par_dictionnaire(password):
    dic = open("fenregistrement.txt", mode='r')
    n = 0
    t = time.process_time()
    for mot in dic:
        mot = mot.strip()
        n += 1
        if sha256(mot.encode()).hexdigest() == password:
            print(f"Mot de passe trouvé : {mot} \nPensez à le changer")
            print(f"{n} mots testés en {time.process_time() - t} secondes")
            dic.close()
            return True

    print("Bravo, aucun mot de passe ne correspond à votre")
    dic.close()
    return False

def choix_hachage():
    print("****************************"
          "   **    Hachage    **"
          "****************************")
    mot=input("Donner un mot a haché:")
    if mot:
        print("1- Haché le mot par sha256")
        print("2- Haché le mot en générant un salt (bcrypt)")
        print("3- Attaquer par dictionnaire le mot inséré   ")
        print("4- Revenir au menu principal ")

    choice=input("Donner votre choix:")

    if choice == '1':
        hash256(mot)
    elif choice == '2':
        hashsalt_bcrypt(mot)
    elif choice == '3':
        attaque_par_dictionnaire(mot)
    elif choice == '4':
        print("#################"
              "#Menu principal#"
              "################")
        menu()
2