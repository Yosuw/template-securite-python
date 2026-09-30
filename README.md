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
