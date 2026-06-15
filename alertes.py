import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pandas as pd


def filtrer_cves_critiques(df, produits_cibles=None, seuil_cvss=7.0, seuil_epss=0.3):
    df["Score CVSS"] = pd.to_numeric(df["Score CVSS"], errors="coerce")
    df["Score EPSS"] = pd.to_numeric(df["Score EPSS"], errors="coerce")

    # ET logique : la faille doit être grave ET réellement menacée
    masque = (df["Score CVSS"] >= seuil_cvss) & (df["Score EPSS"] >= seuil_epss)

    if produits_cibles:
        masque_produit = df["Produit"].str.lower().isin([p.lower() for p in produits_cibles])
        masque = masque & masque_produit

    # Déduplique par CVE + Produit pour ne pas perdre les CVE multi-produits
    return df[masque].drop_duplicates(subset=["Identifiant CVE", "Produit"])


def generer_email(df_critique):
    """Génère le sujet et le corps HTML de l'email d'alerte."""
    sujet = f"FR-ALERT - {len(df_critique)} vulnerabilite(s) critique(s) detectee(s)"

    corps = "<h2>Alerte CVE - FR-ALERT</h2>"
    corps += "<p>Les vulnérabilités suivantes ont été détectées avec un score CVSS ≥ 7.0 et un score EPSS ≥ 0.3 :</p>"
    corps += "<table border='1' cellpadding='6' style='border-collapse:collapse'>"
    corps += "<tr style='background:#c0392b;color:white'>"
    corps += "<th>CVE</th><th>CVSS</th><th>Sévérité</th><th>EPSS</th><th>Produit</th><th>Éditeur</th><th>Bulletin</th>"
    corps += "</tr>"

    for _, row in df_critique.iterrows():
        corps += "<tr>"
        corps += f"<td>{row['Identifiant CVE']}</td>"
        corps += f"<td>{row['Score CVSS']}</td>"
        corps += f"<td>{row.get('Base Severity', 'N/A')}</td>"
        corps += f"<td>{row['Score EPSS']}</td>"
        corps += f"<td>{row['Produit']}</td>"
        corps += f"<td>{row.get('Éditeur (Vendor)', 'N/A')}</td>"
        corps += f"<td><a href='{row['Lien']}'>{row['ID ANSSI']}</a></td>"
        corps += "</tr>"

    corps += "</table>"
    corps += "<p><i>Merci de traiter ces vulnérabilités en priorité.</i></p>"

    return sujet, corps


def envoyer_alerte_email(df_critique, destinataire, expediteur, mot_de_passe):
    sujet, corps = generer_email(df_critique)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = sujet
    msg["From"] = expediteur
    msg["To"] = destinataire
    msg.attach(MIMEText(corps, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(expediteur, mot_de_passe)
            server.sendmail(expediteur, destinataire, msg.as_string())
        print(f"Email envoyé à {destinataire}")
    except smtplib.SMTPAuthenticationError:
        print("Erreur : identifiants Gmail incorrects")
    except smtplib.SMTPException as e:
        print(f"Erreur SMTP : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")


if __name__ == "__main__":
    df = pd.read_csv("donnees_enrichies.csv")

    df_critique = filtrer_cves_critiques(df, seuil_cvss=7.0, seuil_epss=0.3)

    print(f"{len(df_critique)} CVE critique(s) détectée(s)\n")

    for _, row in df_critique.iterrows():
        print(f"  {row['Identifiant CVE']} - CVSS {row['Score CVSS']} - EPSS {row['Score EPSS']} - {row['Produit']}")

    # Affichage du sujet et corps du mail (sans envoi réel)
    if not df_critique.empty:
        print("\n--- Aperçu de l'email ---")
        sujet, corps = generer_email(df_critique)
        print(f"Sujet : {sujet}")
        print(f"Corps HTML généré ({len(corps)} caractères)")
        print("(Pour envoyer réellement, appeler envoyer_alerte_email() avec les identifiants Gmail)")
