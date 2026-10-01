# Template code Sécurité Python

## Description

Projet contenant les modèles de TP pour le cours de sécurité Python de 4e année de l'ESGI.

## Installation

Faire un fork puis un clone du projet :

```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
```

Installer les dépendances :

```bash
cd template-securite-python
poetry lock
poetry install
```

## Utilisation

Lancer le projet :

```bash
poetry run tp1
```

## TP1 - IDS/IPS maison

Outil d'analyse réseau en Python avec Scapy. Il lit un fichier PCAP (ou capture le trafic en direct sur une interface), compte les paquets par protocole, détecte des attaques et génère un rapport PDF et un fichier JSON.

### Installation

```bash
poetry install
```

### Utilisation

Analyse d'un fichier PCAP :

```bash
poetry run tp1 --pcap capture.pcap --out report.json
```

Capture en direct (droits root nécessaires, l'interface est demandée au lancement) :

```bash
sudo $(poetry env info --path)/bin/tp1
```

L'outil génère :
- `report.pdf` : résumé de l'analyse, tableau et graphique des protocoles ;
- `report.json` : protocoles, attaques détectées et flag.

### Détections

- **ARP spoofing** : une même IP annoncée par plusieurs MAC, l'attaquant est la MAC qui envoie des réponses ARP non sollicitées.
- **Scan de ports** : une IP qui envoie des SYN vers plus de 15 ports différents.
- **Injection SQL** : mots-clés suspects (`' OR`, `1=1`, `UNION SELECT`...) dans la ligne de requête HTTP.

### Tests

```bash
poetry run pytest tests/tp1
```

## TP2 - Triage automatisé de malware

Outil de triage en Python : pour chaque échantillon, il calcule les empreintes et l'entropie, analyse le binaire avec lief, extrait les IOC, applique des règles YARA, puis produit un verdict (famille, techniques MITRE ATT&CK, score) avec l'aide d'un LLM.

### Utilisation

```bash
poetry run tp2 --samples DOSSIER --rules DOSSIER --out DOSSIER
```

- `--samples` : dossier des échantillons à analyser
- `--rules` : dossier de règles YARA supplémentaires (facultatif, nos règles sont intégrées au code)
- `--out` : dossier de sortie, avec un `<sha256>.json` et un `<sha256>.pdf` par échantillon

### LLM

- **OpenRouter** si la variable `OPENROUTER_API_KEY` est définie (fichier `.env`) ;
- sinon **Ollama** en local (`ollama pull qwen2.5:3b`) ;
- sans LLM disponible (hors réseau), un verdict déterministe calculé à partir des preuves est utilisé.

### Sécurité de la chaîne LLM

- Le binaire n'est jamais envoyé au LLM : seul un résumé structuré (IOC, fonctions suspectes, matches YARA, entropie) est transmis, entre des délimiteurs `<DONNEES_NON_FIABLES>`.
- La réponse est validée : JSON strict, champs attendus, score borné entre 0 et 10.
- Le LLM ne décide jamais seul : il ne peut pas faire baisser le score calculé à partir des règles.
- Les IOC sont cherchés dans l'overlay du binaire, et seul le flag écrit après `FLAG=` est retenu, ce qui écarte les leurres.

### Tests

```bash
poetry run pytest tests/tp2
```
