import os
import json
from cve_extraction import extraire_cves
from get_cve_score import get_cve_scores
from dataframe import consolider_en_dataframe

BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DOSSIER_ALERTES = os.path.join(BASE_DIR, "data", "alertes")
DOSSIER_AVIS    = os.path.join(BASE_DIR, "data", "Avis")


def lire_metadata(dossier, nom):
    """Lit le fichier JSON du bulletin pour extraire titre, date et lien."""
    chemin = os.path.join(dossier, nom)
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            data = json.load(f)
        titre = data.get("title", nom)
        date  = data.get("date_public", data.get("datePublic", ""))[:10] if data.get("date_public") or data.get("datePublic") else ""
        lien  = data.get("url", data.get("link", ""))
        return titre, date, lien
    except Exception:
        return nom, "", ""


bulletins = []

for nom in os.listdir(DOSSIER_ALERTES):
    titre, date, lien = lire_metadata(DOSSIER_ALERTES, nom)
    bulletins.append({
        "id":               nom,
        "titre":            titre,
        "type":             "alerte",
        "date_publication": date,
        "lien":             lien,
        "dossier":          "alertes"
    })

for nom in os.listdir(DOSSIER_AVIS):
    titre, date, lien = lire_metadata(DOSSIER_AVIS, nom)
    bulletins.append({
        "id":               nom,
        "titre":            titre,
        "type":             "avis",
        "date_publication": date,
        "lien":             lien,
        "dossier":          "Avis"
    })

print(f"Bulletins à traiter : {len(bulletins)}")
print("")

donnees_globales = []

for i, b_info in enumerate(bulletins):
    print(f"[{i+1}/{len(bulletins)}] {b_info['id']} ({b_info['type']})")

    bulletin_complet = {
        "id":               b_info["id"],
        "titre":            b_info["titre"],
        "type":             b_info["type"],
        "date_publication": b_info["date_publication"],
        "lien":             b_info["lien"],
        "cves_enrichis":    []
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
df_final = df_final[
    df_final["Score CVSS"].notna() | df_final["Score EPSS"].notna()
]
df_final.to_csv("donnees_enrichies.csv", index=False)
print(f"Après filtrage : {df_final.shape[0]} lignes")

if not df_final.empty:
    print(f"Export terminé — {df_final.shape[0]} lignes dans donnees_enrichies.csv")
else:
    print("Erreur : le DataFrame est vide.")