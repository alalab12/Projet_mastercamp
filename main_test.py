import pandas as pd
from cve_extraction import extraire_cves
from get_cve_score import get_cve_scores
from dataframe import consolider_en_dataframe
from get_bulletin import get_bulletin

FEED_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
FEED_AVIS    = "https://www.cert.ssi.gouv.fr/avis/feed/"


def executer_pipeline():
    print("Démarrage de l'analyse ANSSI")
    print("")

    bulletins_a_traiter = get_bulletin(FEED_ALERTES) + get_bulletin(FEED_AVIS)
    print(f"Bulletins récupérés : {len(bulletins_a_traiter)}")
    print("")

    donnees_globales = []

    for b_info in bulletins_a_traiter:
        print(f"Bulletin en cours : {b_info['id']} ({b_info['type']})")

        bulletin_complet = {
            "id": b_info["id"],
            "titre": b_info["titre"],
            "type": b_info["type"],
            "date_publication": b_info["date_publication"],
            "lien": b_info["lien"],
            "cves_enrichis": []
        }

        param_entree = b_info["id"] if b_info["mode"] == "local" else b_info["lien"]
        liste_cves = extraire_cves(param_entree, mode=b_info["mode"], type_bulletin=b_info["dossier"])

        cves_str = ", ".join(liste_cves) if liste_cves else "aucun"
        print(f"  CVE identifiés : {cves_str}")

        for cve_id in liste_cves:
            infos_cve = get_cve_scores(cve_id)
            if infos_cve:
                bulletin_complet["cves_enrichis"].append(infos_cve)

        donnees_globales.append(bulletin_complet)
        print("")

    df_final = consolider_en_dataframe(donnees_globales, nom_fichier_csv="donnees_enrichies.csv")

    if not df_final.empty:
        print(f"Export terminé - {df_final.shape[0]} lignes générées dans donnees_enrichies.csv")
    else:
        print("Erreur : le DataFrame est vide.")


if __name__ == "__main__":
    executer_pipeline()
