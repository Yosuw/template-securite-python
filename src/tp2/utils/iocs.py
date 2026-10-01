import re
from urllib.parse import urlparse

# Une chaine = au moins 4 caracteres imprimables consecutifs (comme la commande strings)
STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,24}", re.IGNORECASE)
MUTEX_RE = re.compile(r"(?:Global|Local)\\[\w.-]+")
REGISTRY_RE = re.compile(r"(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\.+")
PATH_RE = re.compile(r"[A-Za-z]:\\.+")
FLAG_RE = re.compile(r"FLAG=(ESGI\{[^}]+\})")

# Extensions de fichiers qui ressemblent a des domaines (ex : urlmon.dll)
FILE_EXTENSIONS = {
    "dll", "exe", "sys", "so", "debug", "txt", "log",
    "dat", "bin", "ini", "cfg", "tmp", "php", "html",
}  # fmt: skip


def extract_strings(data: bytes) -> list[str]:
    """
    Extrait les chaines de caracteres lisibles du fichier
    """
    return [s.decode() for s in STRING_RE.findall(data)]


def is_valid_ip(value: str) -> bool:
    """
    Verifie que chaque partie de l'IP est entre 0 et 255
    """
    return all(0 <= int(part) <= 255 for part in value.split("."))


def is_domain(value: str) -> bool:
    """
    Verifie qu'une chaine est un nom de domaine et pas un nom de fichier
    """
    if not DOMAIN_RE.fullmatch(value):
        return False
    extension = value.rsplit(".", 1)[1].lower()
    return extension not in FILE_EXTENSIONS


def extract_iocs(data: bytes) -> dict:
    """
    Extrait les indicateurs de compromission : domaines, IP, URLs, mutex,
    cles de registre et chemins
    """
    iocs = {"domains": set(), "ips": set(), "urls": set(), "mutex": set(), "registry": set(), "paths": set()}
    for string in extract_strings(data):
        # On ne garde que les chaines qui sont entierement un IOC,
        # pour eviter les faux positifs au milieu d'un texte
        if URL_RE.fullmatch(string):
            iocs["urls"].add(string)
            # Le domaine contenu dans l'URL est aussi un IOC
            host = urlparse(string).hostname
            if host and is_domain(host):
                iocs["domains"].add(host)
        elif IP_RE.fullmatch(string) and is_valid_ip(string):
            iocs["ips"].add(string)
        elif is_domain(string):
            iocs["domains"].add(string)
        elif MUTEX_RE.fullmatch(string):
            iocs["mutex"].add(string)
        elif REGISTRY_RE.fullmatch(string):
            iocs["registry"].add(string)
        elif PATH_RE.fullmatch(string):
            iocs["paths"].add(string)
    # Listes triees pour avoir toujours le meme resultat
    return {key: sorted(values) for key, values in iocs.items()}


def extract_flag(data: bytes) -> str | None:
    """
    Retourne le flag ecrit apres FLAG= (les autres ESGI{...} sont des leurres)
    """
    for string in extract_strings(data):
        match = FLAG_RE.search(string)
        if match:
            return match.group(1)
    return None
