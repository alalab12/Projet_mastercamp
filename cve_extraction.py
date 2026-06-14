import json
import re
import time
import requests
from pathlib import Path

# Répertoire de base du projet (à adapter selon l'arborescence réelle)
BASE_DIR = Path(__file__).resolve().parent

def extraire_cves(bulletin_id_ou_url, mode="local", type_bulletin="alertes"):
    """
    Extrait les CVEs depuis un bulletin ANSSI en mode local ou remote.

    Args:
        bulletin_id_ou_url (str): Nom de fichier (mode local) ou URL ANSSI (mode remote).
        mode (str): "local" pour lire un fichier, "remote" pour interroger l'API ANSSI.
        type_bulletin (str): Sous-dossier cible ("alertes", "avis", etc.).

    Returns:
        list[str]: Liste dédupliquée et triée de CVEs (ex. ["CVE-2024-1234", ...]).
    """

    contenu_brut = ""
    if mode == "local":
        chemin_fichier = BASE_DIR / "data" / type_bulletin / bulletin_id_ou_url

        try:
            with chemin_fichier.open("r", encoding="utf-8") as f:
                contenu_brut = f.read()
        except FileNotFoundError:
            print(f"Erreur : fichier introuvable : {chemin_fichier}")
            return []
        except OSError as e:
            print(f"Erreur : impossible de lire le fichier : {e}")
            return []

    elif mode == "remote":
        url_base = bulletin_id_ou_url.rstrip("/")
        url_json = f"{url_base}/json/"
        time.sleep(2)

        try:
            reponse = requests.get(url_json, timeout=15)
            reponse.raise_for_status()
            contenu_brut = reponse.text
        except requests.exceptions.HTTPError as e:
            print(f"Erreur HTTP : {e}")
            return []
        except requests.exceptions.ConnectionError as e:
            print(f"Erreur de connexion : {e}")
            return []
        except requests.exceptions.Timeout:
            print(f"Délai dépassé pour : {url_json}")
            return []
        except requests.exceptions.RequestException as e:
            print(f"Erreur réseau : {e}")
            return []

    else:
        print(f"Mode inconnu : {mode}")
        return []

    if not contenu_brut.strip():
        print("Avertissement : contenu vide.")
        return []

    cves_collectees = set()
    try:
        donnees_json = json.loads(contenu_brut)
        liste_cves = donnees_json.get("cves", [])

        if isinstance(liste_cves, list):
            for entree in liste_cves:
                if isinstance(entree, dict):
                    for cle in ("name", "cve", "id", "cve_id"):
                        valeur = entree.get(cle, "")
                        if isinstance(valeur, str) and re.match(r"CVE-\d{4}-\d{4,7}", valeur):
                            cves_collectees.add(valeur.strip())
                elif isinstance(entree, str) and re.match(r"CVE-\d{4}-\d{4,7}", entree):
                    cves_collectees.add(entree.strip())

    except (json.JSONDecodeError, AttributeError, TypeError) as e:
        print(f"Parsing JSON échoué, bascule sur regex : {e}")

    try:
        pattern_cve = re.compile(r"CVE-\d{4}-\d{4,7}")
        cves_regex = pattern_cve.findall(contenu_brut)
        cves_collectees.update(cves_regex)

    except (re.error, TypeError) as e:
        print(f"Erreur regex : {e}")
    liste_finale = sorted(cves_collectees)

    if not liste_finale:
        print("Aucune CVE trouvée dans ce bulletin.")

    return liste_finale


# Test de la fonction
if __name__ == "__main__":
    # Test en local
    fichier_test = "CERTFR-2024-ALE-001"
    print(f"Test local sur le fichier : {fichier_test}")
    resultat_local = extraire_cves(fichier_test, mode="local", type_bulletin="alertes")
    print(f"Résultat : {', '.join(resultat_local)}\n")

    url_test = "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/"
    print(f"Test remote sur l'URL : {url_test}")
    resultat_remote = extraire_cves(url_test, mode="remote")
    print(f"Résultat : {', '.join(resultat_remote)}\n")