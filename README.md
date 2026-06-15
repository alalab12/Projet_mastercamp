# Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

Outil d'extraction, d'enrichissement et d'analyse des bulletins de sécurité publiés par l'ANSSI (CERT-FR), avec visualisation des données et génération d'alertes personnalisées.

---

## Prérequis

- Python 3.10 ou supérieur
- pip

Installer les dépendances :

```bash
pip install -r requirements.txt
```

Si aucun `requirements.txt` n'est présent, installer manuellement :

```bash
pip install feedparser requests pandas matplotlib seaborn scikit-learn
```

---

## Structure du projet

```
projet/
│
├── data/                        # Données pré-téléchargées (fournies dans le zip)
│   ├── alertes/                 # Bulletins d'alertes ANSSI (78 fichiers JSON)
│   ├── Avis/                    # Bulletins d'avis ANSSI (~4000 fichiers JSON)
│   ├── mitre/                   # Données CVE MITRE (~37 000 entrées)
│   └── first/                   # Scores EPSS FIRST (~37 000 entrées)
│
├── get_bulletin.py              # Étape 1 : extraction des flux RSS ANSSI
├── cve_extraction.py            # Étape 2 : identification des CVE dans les bulletins
├── get_cve_score.py             # Étape 3 : enrichissement via MITRE et EPSS
├── dataframe.py                 # Étape 4 : consolidation en DataFrame pandas
├── build_csv.py                 # Pipeline complet (mode local)
├── main_test.py                 # Pipeline complet (mode remote, flux RSS live)
├── alertes.py                   # Étape 7 : génération d'alertes et notifications email
│
├── donnees_enrichies.csv        # Fichier CSV généré par le pipeline
├── analyse.ipynb                # Notebook : visualisations + Machine Learning
├── analyse.html                 # Export HTML du notebook
└── README.md
```

---

## Lancement

### Mode local (recommandé)

Utilise les données pré-téléchargées dans `data/` sans faire d'appels réseau.

```bash
python build_csv.py
```

Génère le fichier `donnees_enrichies.csv`.

### Mode remote (flux RSS live)

Interroge directement les flux RSS de l'ANSSI et les API MITRE / EPSS.
Un délai de 2 secondes entre chaque requête est appliqué automatiquement.

```bash
python main_test.py
```

---

## Analyse et visualisations

Ouvrir le notebook Jupyter :

```bash
jupyter notebook analyse.ipynb
```

Le notebook charge `donnees_enrichies.csv` et produit :

- Distribution des scores CVSS et EPSS
- Top 10 des éditeurs et produits les plus touchés
- Scatter CVSS vs EPSS
- Répartition des niveaux de sévérité
- Évolution temporelle des vulnérabilités
- Heatmap des corrélations
- Boxplot CVSS par éditeur
- Analyse par type CWE
- Modèle non supervisé : clustering KMeans (avec validation silhouette)
- Modèle supervisé : Random Forest (avec rapport de classification)

---

## Génération d'alertes

```bash
python alertes.py
```

Filtre les CVE critiques selon deux seuils combinés :

- Score CVSS ≥ 7.0
- Score EPSS ≥ 0.3

L'envoi d'email est optionnel. Le sujet et le corps HTML du mail sont affichés dans la console même sans configuration SMTP.

Pour activer l'envoi réel, renseigner les paramètres dans `alertes.py` :

```python
envoyer_alerte_email(
    df_critique=df_critique,
    destinataire="destinataire@email.com",
    expediteur="votre_email@gmail.com",
    mot_de_passe="mot_de_passe_application"
)
```

> L'envoi Gmail nécessite un mot de passe d'application (pas le mot de passe du compte). À générer dans les paramètres de sécurité Google.

---

## Données

Le dossier `data/` est fourni directement dans le zip. Il contient des copies statiques des flux ANSSI et des réponses API, permettant de faire tourner le pipeline sans accès réseau et sans surcharger les serveurs externes.

| Dossier | Contenu |
|---|---|
| `data/alertes/` | 78 bulletins d'alertes ANSSI |
| `data/Avis/` | ~4 000 bulletins d'avis ANSSI |
| `data/mitre/` | ~37 000 fiches CVE (MITRE) |
| `data/first/` | ~37 000 scores EPSS (FIRST) |

---

## Sources

- Flux RSS ANSSI : https://www.cert.ssi.gouv.fr/alerte/feed/ et https://www.cert.ssi.gouv.fr/avis/feed/
- API CVE MITRE : https://cveawg.mitre.org/api/cve/
- API EPSS FIRST : https://api.first.org/data/v1/epss
