from enregistrement import introduire_email, enregistrer, introduire_pwd
from getpass import getpass
from hashlib import sha256

def authentifier():

   v=False
   v1=False
   import pyfiglet
   import colorama
   print(colorama.Fore.RED)
   banner = pyfiglet.figlet_format("AUTHENTIFICATION", font="small")
   print(banner)
   f=open("fenregistrement.txt","r")
   ch=f.readline()
   while(ch!=""):
       ch=ch[:-1]
       p=ch.find("]")
       em=ch[1:p]
       ch=ch[p+2:]
       p1=ch.find("[")
       mdp1=ch[p1+1:-1]
       email=introduire_email()
       if(em==email):
           v=True
           print("Email valide")
           mdp = sha256(getpass("Donnez votre mot de passe : ").encode()).hexdigest()
           if (mdp == mdp1):
               v1 = True
               print("mot de passe valide")
           else:
               print("Mot de passe invalide.Veuillez vous enregistrer ")
       else:
           print("Veuillez saisir une autre adresse email")


       ch = f.readline()
   f.close()
   print("Authentification réussie !")

if authentifier():
    while True:
        print("**********Vous êtes authentifié, vous pouvez passer a l'étape suivante **********")
        print(" 1- Donnez un mot à haché (en mode invisible)")
        print(" 2- Chiffrement (RSA)")
        print(" 3- Certificat (RSA)")
        choix = int(input("Donnez votre choix :"))

        if choix == '1':
            from hash import choix_hachage
            choix_hachage()
        elif choix == '2':
            from chiffrement_RSA import choix_chiffrement
            choix_chiffrement()
        elif choix == '3':
            from certificat_RSA import certificat
            certificat()
        else:
            print("Choix invalide")
            print("#################"
                  "#Menu principal#"
                  "################")
            from main import menu
            menu()


