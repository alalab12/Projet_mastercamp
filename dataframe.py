import pandas as pd
def consolider_en_dataframe(donnees_globales, nom_fichier_csv="donnees_enrichies.csv"):
    """
    Aplatit la structure imbriquée (Bulletins > CVEs > Produits) en un DataFrame.
    Règle d'or : 1 ligne = 1 combinaison unique (Bulletin + CVE + Produit).

    Args:
        donnees_globales (list): Liste de dictionnaires représentant les bulletins ANSSI enrichis.
        nom_fichier_csv (str): Chemin/nom du fichier CSV d'export. Défaut : "donnees_enrichies.csv".

    Returns:
        pd.DataFrame: DataFrame aplati contenant toutes les combinaisons Bulletin × CVE × Produit.
    """

    lignes_aplaties = []
    # BOUCLE 1 — Itération sur chaque bulletin ANSSI
    for bulletin in donnees_globales:

        # Extraction des champs de niveau "Bulletin" avec valeur par défaut
        id_anssi       = bulletin.get("id",               "Non renseigné")
        titre_anssi    = bulletin.get("titre",            "Non renseigné")
        type_bulletin  = bulletin.get("type",             "Non renseigné")
        date_pub       = bulletin.get("date_publication", "Non renseigné")
        lien_bulletin  = bulletin.get("lien",             "Non renseigné")

        # Récupération de la liste des CVEs enrichis
        cves_enrichis = bulletin.get("cves_enrichis", [])

        # CAS DÉGÉNÉRÉ 1 : Bulletin sans aucun CVE associé
        # → On crée quand même une ligne pour ne pas perdre le bulletin.
        if not cves_enrichis:
            lignes_aplaties.append({
                "ID ANSSI":           id_anssi,
                "Titre ANSSI":        titre_anssi,
                "Type":               type_bulletin,
                "Date de publication": date_pub,
                "Lien":               lien_bulletin,
                "Identifiant CVE":    "N/A",
                "Score CVSS":         "N/A",
                "Base Severity":      "N/A",
                "Type CWE":           "N/A",
                "Score EPSS":         "N/A",
                "Description":        "N/A",
                "Éditeur (Vendor)":   "N/A",
                "Produit":            "N/A",
                "Versions affectées": "N/A",
            })
            continue

        # BOUCLE 2 — Itération sur chaque CVE du bulletin courant
        for cve in cves_enrichis:
            identifiant_cve = cve.get("identifiant",    "Non renseigné")
            score_cvss      = cve.get("score_cvss",     None)
            base_severity   = cve.get("base_severity",  "Non renseigné")
            type_cwe        = cve.get("type_cwe",       "Non renseigné")
            score_epss      = cve.get("score_epss",     None)
            description     = cve.get("description",   "Non renseigné")
            produits_affectes = cve.get("produits_affectes", [])

            # CAS DÉGÉNÉRÉ 2 : CVE sans aucun produit associé
            # → On crée une ligne avec les infos Bulletin + CVE, sans produit.
            if not produits_affectes:
                lignes_aplaties.append({
                    "ID ANSSI":           id_anssi,
                    "Titre ANSSI":        titre_anssi,
                    "Type":               type_bulletin,
                    "Date de publication": date_pub,
                    "Lien":               lien_bulletin,
                    "Identifiant CVE":    identifiant_cve,
                    "Score CVSS":         score_cvss,
                    "Base Severity":      base_severity,
                    "Type CWE":           type_cwe,
                    "Score EPSS":         score_epss,
                    "Description":        description,
                    "Éditeur (Vendor)":   None,
                    "Produit":            None,
                    "Versions affectées": None,
                })
                continue

            # BOUCLE 3 — Itération sur chaque produit affecté par le CVE courant
            for produit in produits_affectes:
                editeur          = produit.get("vendor",   "Non renseigné")
                nom_produit      = produit.get("produit",  "Non renseigné")
                versions         = produit.get("versions", "Non renseigné")
                ligne = {
                    "ID ANSSI":            id_anssi,
                    "Titre ANSSI":         titre_anssi,
                    "Type":                type_bulletin,
                    "Date de publication": date_pub,
                    "Lien":                lien_bulletin,
                    "Identifiant CVE":     identifiant_cve,
                    "Score CVSS":          score_cvss,
                    "Base Severity":       base_severity,
                    "Type CWE":            type_cwe,
                    "Score EPSS":          score_epss,
                    "Description":         description,
                    "Éditeur (Vendor)":    editeur,
                    "Produit":             nom_produit,
                    "Versions affectées":  versions,
                }
                lignes_aplaties.append(ligne)

    # CONSTRUCTION DU DATAFRAME — une seule passe, hors de toute boucle.
    df = pd.DataFrame(lignes_aplaties)

    # EXPORT CSV
    # - index=False  : on n'exporte pas l'index pandas
    # - encoding='utf-8' : compatibilité maximale pour les caractères spéciaux
    df.to_csv(nom_fichier_csv, index=False, encoding="utf-8")
    return df