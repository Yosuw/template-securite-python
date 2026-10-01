import lief

from tp2.utils.metadata import shannon_entropy

# lief affiche beaucoup d'avertissements sur les fichiers bizarres : on les coupe
lief.logging.disable()

# Fonctions systeme souvent utilisees par les malwares
SUSPICIOUS_APIS = {
    # telechargement et execution
    "URLDownloadToFileA", "URLDownloadToFileW", "WinExec", "ShellExecuteA", "ShellExecuteW",
    "CreateProcessA", "CreateProcessW", "system", "execve",
    # reseau
    "WSAStartup", "WSASocketA", "socket", "connect", "send", "recv",
    "InternetOpenA", "InternetOpenUrlA", "HttpSendRequestA",
    # espionnage du clavier
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
    # injection de code
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    # persistance et divers
    "RegSetValueExA", "RegCreateKeyExA", "CreateMutexA", "IsDebuggerPresent",
}  # fmt: skip


def parse_binary(path: str) -> dict:
    """
    Retourne le format, les imports, les exports, les sections et l'overlay
    d'un binaire PE ou ELF (dictionnaire vide si ce n'est pas un binaire)
    """
    binary = lief.parse(path)
    if binary is None:
        return {"format": None, "imports": [], "exports": [], "sections": [], "overlay": b""}

    sections = []
    for section in binary.sections:
        content = bytes(section.content)
        sections.append({"name": section.name, "size": len(content), "entropy": shannon_entropy(content)})

    return {
        "format": binary.format.__name__,
        "imports": sorted({function.name for function in binary.imported_functions if function.name}),
        "exports": sorted({function.name for function in binary.exported_functions if function.name}),
        "sections": sections,
        # L'overlay = les donnees ajoutees apres la fin du binaire.
        # Les malwares y cachent souvent leur configuration.
        "overlay": bytes(binary.overlay),
    }


def find_suspicious_apis(names: list[str]) -> list[str]:
    """
    Garde seulement les noms de fonctions connues pour etre utilisees par des malwares
    """
    return sorted(set(names) & SUSPICIOUS_APIS)
