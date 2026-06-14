import os
from cve_extraction import extraire_cves
from get_cve_score import get_cve_scores
from dataframe import consolider_en_dataframe

DOSSIER_ALERTES = r"C:\Users\audel\Documents\TP DATA\projet\data\alertes"
DOSSIER_AVIS    = r"C:\Users\audel\Documents\TP DATA\projet\data\Avis"

bulletins = []

for nom in os.listdir(DOSSIER_ALERTES):
    bulletins.append({
        "id": nom,
        "titre": nom,
        "type": "alerte",
        "date_publication": "",
        "lien": "",
        "mode": "local",
        "dossier": "alertes"
    })

for nom in os.listdir(DOSSIER_AVIS):
    bulletins.append({
        "id": nom,
        "titre": nom,
        "type": "avis",
        "date_publication": "",
        "lien": "",
        "mode": "local",
        "dossier": "Avis"
    })

print(f"Bulletins à traiter : {len(bulletins)}")
print("")

donnees_globales = []

for i in range(len(bulletins)):
    b_info = bulletins[i]
    print(f"Bulletin en cours : {b_info['id']} ({b_info['type']})  [{i+1}/{len(bulletins)}]")

    bulletin_complet = {
        "id": b_info["id"],
        "titre": b_info["titre"],
        "type": b_info["type"],
        "date_publication": b_info["date_publication"],
        "lien": b_info["lien"],
        "cves_enrichis": []
    }

    liste_cves = extraire_cves(b_info["id"], mode="local", type_bulletin=b_info["dossier"])

    cves_str = ", ".join(liste_cves) if liste_cves else "aucun"
    print(f"  CVE identifiés : {cves_str}")

    for cve_id in liste_cves:
        infos_cve = get_cve_scores(cve_id, mode="local")
        if infos_cve:
            bulletin_complet["cves_enrichis"].append(infos_cve)

    donnees_globales.append(bulletin_complet)
    print("")

df_final = consolider_en_dataframe(donnees_globales, nom_fichier_csv="donnees_enrichies.csv")

if not df_final.empty:
    print(f"Export terminé - {df_final.shape[0]} lignes générées dans donnees_enrichies.csv")
else:
    print("Erreur : le DataFrame est vide.")
