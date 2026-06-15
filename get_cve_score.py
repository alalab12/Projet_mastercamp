import requests
import time
import json
import os

# Dossiers de données locales (relatifs au script)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOSSIER_MITRE = os.path.join(BASE_DIR, "data", "mitre")
DOSSIER_FIRST = os.path.join(BASE_DIR, "data", "first")


def get_cve_scores(cve_id, mode="local"):
    """
    Récupère les informations MITRE et EPSS pour un CVE donné.

    Paramètres :
        cve_id (str) : identifiant CVE (ex : CVE-2023-3519)
        mode (str)   : "local" pour lire depuis data/mitre et data/first,
                       "remote" pour interroger les API en ligne.
    """

    # ── Récupération MITRE ─────────────────────────────────────────────────────
    data = None
    if mode == "local":
        chemin_mitre = os.path.join(DOSSIER_MITRE, cve_id)
        try:
            with open(chemin_mitre, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            print(f"  [local] Fichier MITRE introuvable pour {cve_id}, passage en mode remote")
            mode = "remote"
        except Exception as e:
            print(f"  [local] Erreur lecture MITRE {cve_id} : {e}")
            return None

    if mode == "remote":
        print(f"  Récupération des données MITRE pour {cve_id}")
        time.sleep(2)
        url_mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        try:
            response = requests.get(url_mitre, timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"  Erreur MITRE pour {cve_id} : {e}")
            return None

    if data is None:
        return None

    # Certains fichiers locaux sont des réponses d'erreur API (ex: CVE_RECORD_DNE)
    if "error" in data or "containers" not in data:
        print(f"  [skip] {cve_id} : {data.get('error', 'structure inconnue')}")
        return None

    # ── Extraction des champs MITRE ────────────────────────────────────────────
    try:
        description = data["containers"]["cna"]["descriptions"][0]["value"]
    except (KeyError, IndexError):
        description = "Non disponible"

    cvss_score = None
    base_severity = "Non renseigné"
    try:
        metrics = data["containers"]["cna"]["metrics"][0]
        if "cvssV3_1" in metrics:
            cvss_score = metrics["cvssV3_1"]["baseScore"]
            base_severity = metrics["cvssV3_1"].get("baseSeverity", "Non renseigné")
        elif "cvssV3_0" in metrics:
            cvss_score = metrics["cvssV3_0"]["baseScore"]
            base_severity = metrics["cvssV3_0"].get("baseSeverity", "Non renseigné")
    except (KeyError, IndexError):
        pass

    cwe = "Non disponible"
    cwe_desc = "Non disponible"
    try:
        problemtype = data["containers"]["cna"].get("problemTypes", [{}])
        if problemtype and "descriptions" in problemtype[0]:
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")
    except (KeyError, IndexError):
        pass

    produits_affectes_liste = []
    try:
        affected = data["containers"]["cna"]["affected"]
        for product in affected:
            vendor = product.get("vendor", "Non disponible")
            product_name = product.get("product", "Non disponible")
            versions = [
                v.get("version", "?")
                for v in product.get("versions", [])
                if v.get("status") == "affected"
            ]
            produits_affectes_liste.append({
                "vendor": vendor,
                "produit": product_name,
                "versions": ", ".join(versions)
            })
    except (KeyError, TypeError):
        pass

    # ── Récupération EPSS ──────────────────────────────────────────────────────
    epss_score = None

    if mode == "local":
        chemin_first = os.path.join(DOSSIER_FIRST, cve_id)
        try:
            with open(chemin_first, "r", encoding="utf-8") as f:
                data_epss = json.load(f)
            epss_data = data_epss.get("data", [])
            if epss_data:
                epss_score = epss_data[0]["epss"]
        except FileNotFoundError:
            print(f"  [local] Fichier FIRST introuvable pour {cve_id}")
        except Exception as e:
            print(f"  [local] Erreur lecture FIRST {cve_id} : {e}")

    else:
        print(f"  Récupération des données EPSS pour {cve_id}")
        time.sleep(2)
        url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        try:
            response_epss = requests.get(url_epss, timeout=10)
            response_epss.raise_for_status()
            data_epss = response_epss.json()
            epss_data = data_epss.get("data", [])
            if epss_data:
                epss_score = epss_data[0]["epss"]
        except Exception as e:
            print(f"  Erreur FIRST pour {cve_id} : {e}")

    return {
        "identifiant": cve_id,
        "score_cvss": cvss_score,
        "base_severity": base_severity,
        "type_cwe": cwe,
        "score_epss": epss_score,
        "description": description,
        "produits_affectes": produits_affectes_liste
    }
