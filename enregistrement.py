import string
def introduire_email():
    global email
    import re
    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
    while True:
        email = input("Donnez votre email : ")
        if re.fullmatch(regex, email):
            return email
        else:
            print("Email invalide")


def introduire_pwd():
    global p
    from getpass import getpass
    from hashlib import sha256

    while True:
        p = getpass()
        if len(p) >= 8:
            if any(car in string.digits for car in p):
                if any(car in string.ascii_uppercase for car in p):
                    if any(car in string.ascii_lowercase for car in p):
                        if any(car in string.punctuation for car in p):
                            p = sha256(p.encode()).hexdigest()
                            return p
                        else:
                            print(
                                "Le mot de passe n'est pas sécurisé. "
                                "Il doit contenir au moins 8 caractères, "
                                "une combinaison de lettres majuscules et minuscules, "
                                "au moins un chiffre et au moins un caractère spécial")
                            print("au min un cart spécial")
                    else:
                        print("au minimum une lettre miniscule")
                else:
                    print("Au min une lettre maj")
            else:
                print("Au min un numérique")
        else:
            print("long >= 8 ")


def enregistrer():
    import pyfiglet
    import colorama
    print(colorama.Fore.RED)
    banner = pyfiglet.figlet_format("ENREGISTREMENT", font="small")
    print(banner)

    l_email = []
    l_pass = []
    while True:
        f = open("fenregistrement.txt", "a")
        l_email.append(introduire_email())
        l_pass.append(introduire_pwd())
        f.write(str(l_email))
        f.write(str(l_pass) + '\n')
        print("Vous avez terminé l'étape d'enregistrement")
        from main import menu
        print("#################"
              "#Menu principal#"
              "################")
        menu()
        f.close()