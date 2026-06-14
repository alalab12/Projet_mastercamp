import pandas as pd

def consolider_en_dataframe(donnees_globales, nom_fichier_csv="donnees_enrichies.csv"):
    lignes_aplaties = []

    for bulletin in donnees_globales:
        id_anssi       = bulletin.get("id",               "Non renseigné")
        titre_anssi    = bulletin.get("titre",            "Non renseigné")
        type_bulletin  = bulletin.get("type",             "Non renseigné")
        date_pub       = bulletin.get("date_publication", "Non renseigné")
        lien_bulletin  = bulletin.get("lien",             "Non renseigné")
        cves_enrichis  = bulletin.get("cves_enrichis",    [])

        if not cves_enrichis:
            lignes_aplaties.append({
                "ID ANSSI":            id_anssi,
                "Titre ANSSI":         titre_anssi,
                "Type":                type_bulletin,
                "Date de publication": date_pub,
                "Lien":                lien_bulletin,
                "Identifiant CVE":     "N/A",
                "Score CVSS":          "N/A",
                "Base Severity":       "N/A",
                "Type CWE":            "N/A",
                "Score EPSS":          "N/A",
                "Description":         "N/A",
                "Éditeur (Vendor)":    "N/A",
                "Produit":             "N/A",
                "Versions affectées":  "N/A",
            })
            continue

        for cve in cves_enrichis:
            identifiant_cve   = cve.get("identifiant",       "Non renseigné")
            score_cvss        = cve.get("score_cvss",        None)
            base_severity     = cve.get("base_severity",     "Non renseigné")
            type_cwe          = cve.get("type_cwe",          "Non renseigné")
            score_epss        = cve.get("score_epss",        None)
            description       = cve.get("description",       "Non renseigné")
            produits_affectes = cve.get("produits_affectes", [])

            if not produits_affectes:
                lignes_aplaties.append({
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
                    "Éditeur (Vendor)":    None,
                    "Produit":             None,
                    "Versions affectées":  None,
                })
                continue

            for produit in produits_affectes:
                editeur     = produit.get("vendor",   "Non renseigné")
                nom_produit = produit.get("produit",  "Non renseigné")
                versions    = produit.get("versions", "Non renseigné")
                lignes_aplaties.append({
                    "ID ANSSI":            id_anssi,
                    "Titre ANSSI":         titre_anssi.replace("\n", " "),
                    "Type":                type_bulletin.replace("\n", " "),
                    "Date de publication": date_pub,
                    "Lien":                lien_bulletin,
                    "Identifiant CVE":     identifiant_cve.replace("\n", " "),
                    "Score CVSS":          score_cvss,
                    "Base Severity":       base_severity,
                    "Type CWE":            type_cwe.replace("\n", " "),
                    "Score EPSS":          score_epss,
                    "Description":         description.replace("\n", " "),
                    "Éditeur (Vendor)":    editeur.replace("\n", " "),
                    "Produit":             nom_produit.replace("\n", " "),
                    "Versions affectées":  versions.replace("\n", " "),
                })

    df = pd.DataFrame(lignes_aplaties)
    df.to_csv(nom_fichier_csv, index=False, encoding="utf-8")
    return df
