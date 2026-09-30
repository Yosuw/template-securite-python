from scapy.all import sniff

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []    # liste des paquets captures
        self.protocols = {}  # nom du protocole -> nombre de paquets

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")
        # On capture pendant 60 secondes sur l'interface choisie
        self.packets = sniff(iface=interface, timeout=60)
        logger.info(f"{len(self.packets)} paquets captures")

    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols
        """
        # Tri du dictionnaire par nombre de paquets, du plus grand au plus petit
        return dict(sorted(self.protocols.items(), key=lambda x: x[1], reverse=True))

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        self.protocols = {}
        for pkt in self.packets:
            # Un paquet contient plusieurs couches (ex : Ether / IP / TCP)
            for layer in pkt.layers():
                name = layer.__name__
                # On ignore les couches qui ne sont pas des protocoles interessants
                if name in ["Ether", "Raw", "Padding"]:
                    continue
                # On incremente le compteur du protocole
                if name in self.protocols:
                    self.protocols[name] += 1
                else:
                    self.protocols[name] = 1
        return self.protocols

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary