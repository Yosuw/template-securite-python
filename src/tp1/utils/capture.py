from scapy.all import sniff, ARP, IP, TCP, Ether

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []    # liste des paquets captures
        self.protocols = {}  # nom du protocole -> nombre de paquets
        self.attacks = []    # liste des attaques detectees

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

    def add_attack(self, attack_type, protocol, ip, mac) -> None:
        """
        Ajoute une attaque a la liste si elle n'y est pas deja
        """
        attack = {"type": attack_type, "protocol": protocol, "ip": ip, "attacker": mac}
        # Evite d'ajouter plusieurs fois la meme attaque
        if attack not in self.attacks:
            self.attacks.append(attack)
            logger.warning(f"Attaque detectee : {attack}")

    def detect_arp_spoofing(self) -> None:
        """
        Detecte l'ARP spoofing : une meme IP annoncee avec deux MAC differentes
        """
        table = {}  # IP -> MAC vue en premier
        for pkt in self.packets:
            # op == 2 correspond a une reponse ARP (is-at)
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                # Si l'IP est deja connue avec une autre MAC, c'est suspect
                if ip in table and table[ip] != mac:
                    self.add_attack("arp_spoofing", "ARP", ip, mac)
                elif ip not in table:
                    table[ip] = mac

    def detect_syn_scan(self) -> None:
        """
        Detecte un scan SYN : une IP qui envoie des SYN sur beaucoup de ports differents
        """
        ports = {}  # IP source -> liste des ports cibles
        macs = {}   # IP source -> MAC source
        for pkt in self.packets:
            # On ne garde que les paquets TCP avec uniquement le flag SYN
            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].flags == "S":
                ip = pkt[IP].src
                if ip not in ports:
                    ports[ip] = []
                if pkt[TCP].dport not in ports[ip]:
                    ports[ip].append(pkt[TCP].dport)
                macs[ip] = pkt[Ether].src
        # Au dela de 15 ports differents, on considere que c'est un scan
        for ip in ports:
            if len(ports[ip]) > 15:
                self.add_attack("syn_scan", "TCP", ip, macs[ip])

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