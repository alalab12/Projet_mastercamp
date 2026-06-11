import pandas as pd
from cve_extraction import extraire_cves
from get_cve_score import get_cve_scores
from dataframe import consolider_en_dataframe


def executer_pipeline():
    print("=== DÉMARRAGE DU PIPELINE ANSSI ===\n")

    bulletins_a_traiter = [
        {
            "id": "CERTFR-2024-ALE-001",
            "titre": "Multiples vulnérabilités dans Ivanti",
            "type": "alerte",
            "date_publication": "2024-01-11",
            "lien": "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/",
            "mode": "remote",
            "dossier": "alertes"
        },
        {
            "id": "CERTFR-2024-AVI-0001",
            "titre": "Avis de sécurité Microsoft",
            "type": "avis",
            "date_publication": "2024-01-02",
            "lien": "https://www.cert.ssi.gouv.fr/avis/CERTFR-2024-AVI-0001/",
            "mode": "remote",
            "dossier": "avis"
        }
    ]

    donnees_globales = []

    for b_info in bulletins_a_traiter:
        print(f"[*] TRAITEMENT : {b_info['id']} ({b_info['type'].upper()})")

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

        print(f"  -> {len(liste_cves)} CVE(s) extrait(s) : {liste_cves}")

        for cve_id in liste_cves:
            infos_cve = get_cve_scores(cve_id)

            if infos_cve:
                bulletin_complet["cves_enrichis"].append(infos_cve)

        donnees_globales.append(bulletin_complet)
        print("-" * 50)

    print("\n=== GÉNÉRATION DU DATAFRAME ET EXPORT CSV ===")
    df_final = consolider_en_dataframe(donnees_globales, nom_fichier_csv="donnees_enrichies.csv")

    if not df_final.empty:
        print(f"SUCCÈS ! Fichier 'donnees_enrichies.csv' généré.")
        print(f"Dimensions : {df_final.shape[0]} lignes générées à partir des combinaisons.")
    else:
        print("ÉCHEC : Le DataFrame est vide.")


if __name__ == "__main__":
    executer_pipeline()

    print("Hello World!")
