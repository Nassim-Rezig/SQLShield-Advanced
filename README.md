# Advanced SQL Injection Vulnerability Scanner

Un outil sophistiqué pour l'analyse des vulnérabilités d'injection SQL sur les sites web. Cet outil est conçu uniquement à des fins éducatives et pour des tests de sécurité autorisés.

## Avertissement

Cet outil ne doit être utilisé que sur des sites web pour lesquels vous avez l'autorisation de réaliser des tests. Les tests de sécurité non autorisés sont illégaux et contraires à l'éthique.

## Fonctionnalités Avancées

- Détection de multiples types d'injections SQL :
  - Injections basées sur les erreurs (Error-based)
  - Injections temporelles (Time-based)
  - Injections booléennes (Boolean-based)
  - Injections aveugles (Blind)
  - Injections basées sur UNION
- Classification des vulnérabilités par niveau de risque (faible, moyen, élevé)
- Détection et identification des WAF (Web Application Firewalls)
- Respect des règles robots.txt lors du crawling
- Support d'authentification (Basic Auth, cookies)
- Utilisation de proxy pour l'anonymisation
- Multithreading avancé pour des analyses rapides
- Techniques d'évasion de WAF
- Identification précise du type de base de données (MySQL, PostgreSQL, Oracle, etc.)

## Prérequis

- Python 3.6+
- Paquets Python requis (installation via `pip install -r requirements.txt`) :
  - requests
  - beautifulsoup4
  - colorama
  - urllib3
  - tqdm
  - prettytable
  - fake-useragent
  - python-dateutil
  - rich

## Installation

1. Clonez ou téléchargez ce dépôt
2. Installez les paquets requis :

```
pip install -r requirements.txt
```

## Utilisation

Utilisation basique :

```
python sql_injection_scanner.py https://example.com
```

Options avancées :

```
python sql_injection_scanner.py https://example.com -t 10 --timeout 15 -v -m 100 -r 3 -o html
```

### Arguments en ligne de commande

#### Options principales
- `url`: URL cible à analyser (obligatoire)
- `-t, --threads`: Nombre de threads (défaut: 5)
- `--timeout`: Délai d'attente des requêtes en secondes (défaut: 10)
- `-v, --verbose`: Activer la sortie détaillée
- `-m, --max-urls`: Nombre maximum d'URLs à analyser (défaut: 50)
- `-d, --depth`: Profondeur maximale de crawling (défaut: 3)
- `-r, --risk`: Niveau de risque des payloads (1=Faible, 2=Moyen, 3=Élevé, défaut: 1)
- `--delay`: Délai entre les requêtes en secondes (défaut: 0)

#### Options d'authentification
- `-u, --user`: Nom d'utilisateur pour l'authentification basique
- `-p, --password`: Mot de passe pour l'authentification basique
- `--cookie`: Cookies à inclure dans les requêtes HTTP (format: nom1=valeur1;nom2=valeur2)

#### Options de proxy
- `--proxy`: Proxy à utiliser pour les requêtes HTTP (format: http://proxy:port)
- `--user-agent`: Chaîne User-Agent personnalisée

#### Options de crawling
- `--ignore-robots`: Ignorer les règles du fichier robots.txt

#### Options de sortie
- `-o, --output`: Format d'exportation des résultats (text, json, html, csv)

## Exemple de sortie

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   Advanced SQL Injection Vulnerability Scanner                            ║
║   For educational and security testing purposes only                      ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

[*] Target URL: https://example.com
[*] Threads: 5
[*] Timeout: 10 seconds
[*] Risk Level: 2 (1=Low, 2=Medium, 3=High)
[*] Verbose Mode: Disabled
[*] Crawling Depth: 3
[*] Respect robots.txt: Yes
[*] Authentication: Disabled
[*] Export Format: html

[*] Starting scan...
[*] Parsed robots.txt: 3 disallow rules found
[*] Found 2 forms on https://example.com/login.php
[*] Found 15 links on https://example.com (depth 0)
[!] WAF detected: CLOUDFLARE (from headers)
[+] SQL Injection found! [MEDIUM]
    URL: https://example.com/search.php
    Method: GET
    Input: q
    Type: error-based
    Database: mysql
    Payload: ' OR '1'='1

[+] Time-based SQL Injection found! [MEDIUM]
    URL: https://example.com/product.php
    Method: GET
    Input: id
    Database: mysql
    Payload: ' AND SLEEP(2) --

[*] Scan completed!
[*] URLs scanned: 25
[*] Scan duration: 0:01:45
[*] WAF detected: Yes - CLOUDFLARE

[+] Found 2 SQL injection vulnerabilities:

╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║                   SQL INJECTION VULNERABILITY REPORT                      ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

[*] Scan Summary:
    - Target URL: https://example.com
    - Scan started: 2025-05-23 12:55:10
    - Scan completed: 2025-05-23 12:56:55
    - Duration: 0:01:45
    - URLs scanned: 25
    - WAF detected: Yes - CLOUDFLARE

[*] Vulnerability Statistics:
    - Total vulnerabilities found: 2
    - Vulnerability types: error-based (1), time-based (1)
    - Database types identified: mysql (2)
    - Risk levels: High (0), Medium (2), Low (0)

[*] Detailed Findings:

[+] Vulnerability #1:
    URL: https://example.com/search.php
    Method: GET
    Input/Parameter: q
    Payload: ' OR '1'='1
    Type: error-based
    Database: mysql
    Risk Level: MEDIUM
    Evidence: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near...

[+] Vulnerability #2:
    URL: https://example.com/product.php
    Method: GET
    Input/Parameter: id
    Payload: ' AND SLEEP(2) --
    Type: time-based
    Database: mysql
    Risk Level: MEDIUM
    Evidence: Delayed response detected

[*] Report exported to sql_injection_report_20250523_125655.html
```

## Formats de rapport

L'outil peut générer des rapports dans plusieurs formats :

### HTML
Rapport interactif avec mise en forme et code couleur pour faciliter l'analyse des vulnérabilités.

### JSON
Format structuré pour l'intégration avec d'autres outils ou pour l'analyse automatisée.

### CSV
Format tabulaire pour l'importation dans des tableurs ou des bases de données.

### Texte
Rapport simple en texte brut pour une consultation rapide.

## Utilisation responsable

- Obtenez toujours une autorisation appropriée avant de tester un site web
- Signalez les vulnérabilités de manière responsable aux propriétaires des sites
- N'utilisez pas cet outil à des fins malveillantes
- Respectez la législation en vigueur concernant les tests de sécurité

## Licence

Ce projet est destiné uniquement à des fins éducatives et de test de sécurité autorisé.
