from scapy.all import get_if_list

from tp1.utils.config import logger


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interface = ""
    # Liste des interfaces reseau disponibles sur la machine
    interfaces = get_if_list()
    for i in range(len(interfaces)):
        logger.info(f"{i} : {interfaces[i]}")

    # On redemande tant que le choix n'est pas valide
    while interface == "":
        choice = input("Choisissez une interface : ")
        if choice.isdigit() and int(choice) < len(interfaces):
            interface = interfaces[int(choice)]
        else:
            logger.warning("Choix invalide")
    return interface
