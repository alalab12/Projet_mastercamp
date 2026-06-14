import feedparser
from datetime import datetime


def get_bulletin(url, limit=10):
    feed = feedparser.parse(url)
    bulletins = []
    for entry in feed.entries[:limit]:
        lien = entry.link

        if "alerte" in lien:
            type_b = "alerte"
            dossier = "alertes"
        else:
            type_b = "avis"
            dossier = "avis"

        date_str = str(entry.get("published", "")[:16])
        parsed_date = datetime.strptime(date_str, "%a, %d %b %Y")
        date = parsed_date.strftime("%Y-%m-%d")

        bulletins.append({
            "id": entry.id.split("/")[-2],
            "titre": entry.title,
            "type": type_b,
            "date_publication": date,
            "lien": lien,
            "mode": "remote",
            "dossier": dossier
        })
    return bulletins


FEED_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
FEED_AVIS    = "https://www.cert.ssi.gouv.fr/avis/feed/"
