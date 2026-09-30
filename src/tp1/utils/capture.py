from urllib.parse import unquote_plus

from scapy.all import sniff, rdpcap, ARP, IP, TCP, Ether, Raw

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self, pcap: str = "") -> None:
        self.pcap = pcap  # fichier pcap a analyser (vide = capture en direct)
        # On ne demande une interface que si aucun fichier pcap n'est donne
        self.interface = "" if pcap else choose_interface()
        self.summary = ""
        self.packets = []    # liste des paquets captures
        self.protocols = {}  # nom du protocole -> nombre de paquets
        self.attacks = []    # liste des attaques detectees
        self.flag = None     # flag trouve dans l'injection SQL

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        # Lecture d'un fichier pcap si un fichier a ete donne
        if self.pcap:
            logger.info(f"Lecture du fichier {self.pcap}")
            self.packets = rdpcap(self.pcap)
        else:
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
        Detecte l'ARP spoofing : une meme IP annoncee avec plusieurs MAC,
        l'attaquant etant celui qui envoie des reponses ARP non sollicitees
        """
        requests = []     # requetes ARP en attente de reponse : (IP demandeur, IP demandee)
        macs = {}         # IP annoncee -> liste des MAC vues pour cette IP
        unsolicited = {}  # IP annoncee -> liste des MAC qui ont repondu sans qu'on leur demande

        # Les paquets ne sont pas forcement dans l'ordre : on les trie par date
        packets = sorted(self.packets, key=lambda p: p.time)
        for pkt in packets:
            if not pkt.haslayer(ARP):
                continue
            arp = pkt[ARP]
            # op == 1 : requete ARP (who-has), on la garde en attente
            if arp.op == 1:
                requests.append((arp.psrc, arp.pdst))
            # op == 2 : reponse ARP (is-at)
            elif arp.op == 2:
                ip = arp.psrc
                mac = arp.hwsrc
                if ip not in macs:
                    macs[ip] = []
                if mac not in macs[ip]:
                    macs[ip].append(mac)
                # La reponse est legitime seulement si quelqu'un a demande cette IP
                if (arp.pdst, ip) in requests:
                    requests.remove((arp.pdst, ip))
                else:
                    if ip not in unsolicited:
                        unsolicited[ip] = []
                    if mac not in unsolicited[ip]:
                        unsolicited[ip].append(mac)

        # Spoofing : plusieurs MAC pour une IP, on accuse celles qui repondent sans demande
        for ip in macs:
            if len(macs[ip]) > 1:
                for mac in unsolicited.get(ip, []):
                    self.add_attack("arp_spoofing", "ARP", ip, mac)

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
                self.add_attack("port_scan", "TCP", ip, macs[ip])

    def detect_sql_injection(self) -> None:
        """
        Detecte une injection SQL dans le contenu des paquets TCP et recupere le flag
        """
        # Mots cles typiques d'une injection SQL
        keywords = ["' or", "union select", "1=1", "--", "drop table"]
        for pkt in self.packets:
            # On regarde seulement les paquets TCP qui ont des donnees
            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                # Decodage des caracteres encodes dans les URL (%27 -> ', + -> espace...)
                data = unquote_plus(pkt[Raw].load.decode(errors="ignore"))
                data_lower = data.lower()
                for word in keywords:
                    if word in data_lower:
                        self.add_attack("sql_injection", "TCP", pkt[IP].src, pkt[Ether].src)
                        # Recherche du flag ESGI{...} dans le paquet
                        start = data_lower.find("esgi{")
                        if start != -1:
                            end = data.find("}", start)
                            self.flag = data[start:end + 1]
                        break

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

        # Lancement des differentes detections
        self.detect_arp_spoofing()
        self.detect_syn_scan()
        self.detect_sql_injection()

        self.summary = self._gen_summary()

    def get_json_attacks(self) -> list[dict]:
        """
        Retourne les attaques au format attendu dans report.json
        """
        json_attacks = []
        for attack in self.attacks:
            # Pour l'ARP spoofing on donne la MAC, pour les autres attaques l'IP
            if attack["type"] == "arp_spoofing":
                attacker = attack["attacker"]
            else:
                attacker = attack["ip"]
            json_attacks.append({"type": attack["type"], "attacker": attacker})
        return json_attacks
    
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
        # Si aucune attaque, le trafic est legitime
        if len(self.attacks) == 0:
            return "Tout va bien, aucun trafic illegitime detecte."
        summary = "Attaques detectees :\n"
        # Une ligne par attaque avec le protocole, l'IP et la MAC de l'attaquant
        for attack in self.attacks:
            summary += f"- {attack['type']} ({attack['protocol']}) : IP {attack['ip']}, MAC {attack['attacker']}\n"
        if self.flag:
            summary += f"Flag : {self.flag}\n"
        return summary