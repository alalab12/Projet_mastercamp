import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pandas as pd


def filtrer_cves_critiques(df, produits_cibles=None, seuil_cvss=7.0, seuil_epss=0.1):
    df["Score CVSS"] = pd.to_numeric(df["Score CVSS"], errors="coerce")
    df["Score EPSS"] = pd.to_numeric(df["Score EPSS"], errors="coerce")

    masque = (df["Score CVSS"] >= seuil_cvss) | (df["Score EPSS"] >= seuil_epss)

    if produits_cibles:
        masque_produit = df["Produit"].str.lower().isin([p.lower() for p in produits_cibles])
        masque = masque & masque_produit

    return df[masque].drop_duplicates(subset=["Identifiant CVE"])


def envoyer_alerte_email(df_critique, destinataire, expediteur, mot_de_passe):
    corps = "<h2>Alerte CVE - FR-ALERT</h2><table border='1' cellpadding='6'>"
    corps += "<tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>Produit</th><th>Bulletin</th></tr>"

    for i in range(len(df_critique)):
        row = df_critique.iloc[i]
        corps += f"<tr><td>{row['Identifiant CVE']}</td>"
        corps += f"<td>{row['Score CVSS']}</td>"
        corps += f"<td>{row['Score EPSS']}</td>"
        corps += f"<td>{row['Produit']}</td>"
        corps += f"<td><a href='{row['Lien']}'>{row['ID ANSSI']}</a></td></tr>"

    corps += "</table>"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"FR-ALERT - {len(df_critique)} vulnerabilite(s) critique(s) detectee(s)"
    msg["From"] = expediteur
    msg["To"] = destinataire
    msg.attach(MIMEText(corps, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(expediteur, mot_de_passe)
        server.sendmail(expediteur, destinataire, msg.as_string())

    print(f"Email envoyé à {destinataire}")


if __name__ == "__main__":
    df = pd.read_csv("donnees_enrichies.csv")

    df_critique = filtrer_cves_critiques(df, seuil_cvss=7.0, seuil_epss=0.1)

    print(f"{len(df_critique)} CVE critique(s) détectée(s)")
    print("")

    for i in range(len(df_critique)):
        row = df_critique.iloc[i]
        print(f"  {row['Identifiant CVE']} - CVSS {row['Score CVSS']} - {row['Produit']}")
