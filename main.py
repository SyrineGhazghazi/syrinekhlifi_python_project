import colorama
from enregistrement import enregistrer

from quitter import quitter

print(colorama.Fore.BLUE )
from art import *

tprint("BIENVENUE", font="small")


def menu():
    while True:
        print("1- Taper 1 pour l'enregistrement")
        print("2- Taper 2 pour l'authentification")
        print("3- Taper 3 pour quitter")
        choix = input("Donner votre choix: ")
        try:
            int(choix)
            it_is = True
        except ValueError:
            it_is = False
        if it_is:
            match int(choix):
                case 1:
                    enregistrer()
                    break
                case 2:
                    from authentification import authentifier
                    authentifier()
                    break
                case 3:
                    quitter()
                case _ :
                    print("Vérifier votre choix svp")
        else:
            print("Vérifier votre choix svp")


menu()
