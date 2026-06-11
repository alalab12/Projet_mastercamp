import requests
import numpy as np

def get_cve_scores(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    data = response.json()
    # Extraire la description
    description = data["containers"]["cna"]["descriptions"][0]["value"]
    # Extraire le score CVSS
    #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
    #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
    try:
        cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
    except (KeyError, IndexError):
        cvss_score = "Non disponible"

    cwe = "Non disponible"
    cwe_desc="Non disponible"
    problemtype = data["containers"]["cna"].get("problemTypes", {})
    if problemtype and "descriptions" in problemtype[0]:
        cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
        cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")
    # Extraire les produits affectés
    affected = data["containers"]["cna"]["affected"]
    for product in affected:
        vendor = product["vendor"]
        product_name = product["product"]
        versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
        #print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")
    # Afficher les résultats
    #print(f"CVE : {cve_id}")
    #print(f"Description : {description}")
    #"print(f"Score CVSS : {cvss_score}")
    #print(f"Type CWE : {cwe}")
    #print(f"CWE Description : {cwe_desc}")
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    # Requête GET pour récupérer les données JSON
    response = requests.get(url)
    data = response.json()
    # Extraire le score EPSS
    epss_data = data.get("data", [])
    if epss_data:
        epss_score = epss_data[0]["epss"]
        #print(f"CVE : {cve_id}")
        #print(f"Score EPSS : {epss_score}")
    else:
        #print(f"Aucun score EPSS trouvé pour {cve_id}")
        pass
    all_score = np.array([("CVE", cve_id), ("EPSS", epss_score), ("CVSS", cvss_score), ("CWE", cwe)], dtype=object)
    #print("All Scores:")
    #print(all_score)
    return all_score