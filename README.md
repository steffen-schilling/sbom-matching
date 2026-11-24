# SBOM-Matching: OSV und NVD im Vergleich
In diesem Projekt wird eine Schwachstellenanalyse von Softwarekomponenten, welche in der durch Syft erzeugten SBOM aufgelistet sind, durchgeführt. Im Speziellen geht es um die verschiedenen Zustände der OSV und NVD Datenbanken bezüglich der erkannten CVEs der betreffenden Softwarekomponenten.

# Fragestellung
Jede Komponente kann zwei Kennungen haben: eine PURL (Package URL), die eindeutig angibt, aus welcher Paketverwaltung ein Paket stammt, und eine CPE, das Namensschema der NVD aus Hersteller, Produkt und Version. OSV wird über die PURL abgefragt, die NVD über die CPE. Die Frage ist, ob beide Datenbanken dieselben Schwachstellen finden und woran es liegt, wenn nicht.

# Vorgehen
1. Syft erzeugt aus den in `testtarget/.venv` installierten Paketen eine SBOM
2. Das Python Skript `compare.py` fragt für jedes gefundene Paket aus der SBOM die beiden Datenbanken OSV und NVD ab. OSV benötigt dafür die purl und NVD die CPE
3. Für Anfragen an NVD müssen Wartezeiten in das Skript mit eingebaut werden, da an diese Datenbank nicht zu viele Anfragen nacheinander in kurzer Zeit gestellt werden darf
4. Doppelt erkannte Schwachstellen werden zusammengefasst durch Abgleich der CVEs, was eindeutige Kennungen von Schwachstellen sind
5. Für das `django` Paket wurde von Syft eine falsche CPE geraten wodurch dafür eine Korrekturtabelle benötigt wird, welche die richtige CPE enthält
6. Zuletzt werden die beiden Mengen von CVEs verglichen um die Unterschiede zwischen der OSV und NVD Datenbank zu verdeutlichen

# Testziel
Damit es sicher bekannte Schwachstellen gibt, gegen die sich die Ergebnisse prüfen lassen, verwende ich bewusst veraltete Versionen: `requests 2.31.0`, `django 3.2` und `urllib3 1.26.5`. Die übrigen Pakete hat pip automatisch als Abhängigkeiten installiert. Alle genauen Versionen stehen in `testtarget/requirements.txt`, sodass sich das Testziel exakt nachbauen lässt.

# Ergebnisse
Stand: 24.11.2026. Geprüft mit den Skripten in `investigations/`.

Ausgabe von `compare.py` in Tabelle:

| Paket | OSV | NVD | Nur OSV | Nur NVD |
| --- | --- | --- | --- | --- |
|asgiref 3.13.0|0|0|0|0|
|certifi 2026.11.20|0|0|0|0|
|charset-normalizer 3.5.3|0|0|0|0|
|django 3.2|38|27|12|1|
|idna 3.20|0|0|0|0|
|pip 26.2.1|0|0|0|0|
|pytz 2026.6|0|0|0|0|
|requests 2.31.0|3|1|2|0|
|sqlparse 0.6.1|0|0|0|0|
|urllib3 1.26.5|10|10|0|0|

## Abweichungen bei `django` und `requests`
- `django` Schwachstellen nur in OSV: ['CVE-2021-33203', 'CVE-2024-45231', 'CVE-2025-48432', 'CVE-2025-57833', 'CVE-2025-64458', 'CVE-2025-64459', 'CVE-2026-48587', 'CVE-2026-48588', 'CVE-2026-53877', 'CVE-2026-53878', 'CVE-2026-6873', 'CVE-2026-8404']
- `django` Schwachstellen nur in NVD: ['CVE-2026-15337']
- `requests` Schwachstellen nur in OSV: ['CVE-2024-35195', 'CVE-2024-47081']
- `requests` Schwachstellen nur in NVD: []

# Analyse der Abweichungen

In den Ergebnissen haben sich wie oben aufgeführt zwei Pakete mit Abweichungen ergeben. Diese haben verschiedene Gründe die ich mit genannten Skripten genauer untersucht habe. Die Ergebnisse davon sind in der nachfolgenden Tabelle aufgeführt.

| Abweichung | Ursache | Folge |
| --- | --- | --- |
| requests: CVE-2024-35195 und CVE-2024-47081 nur in OSV | In der NVD „Deferred", also ohne CPE-Zuordnung | übersehen über NVD |
| django: ohne Korrektur 0 statt 27 Treffer in der NVD | Syft rät den Hersteller `django_software_foundation_project`, die NVD nutzt `djangoproject` | ganze Komponente unsichtbar |
| django: CVE-2021-33203 nur in OSV | Die NVD behandelt `3.2` nicht wie `3.2.0` | übersehen über NVD |
| django: CVE-2026-6873 nur in OSV | Django 3.2 wird nicht mehr unterstützt; GitHub wertet es als betroffen, PyPI und NVD nicht | nicht entscheidbar |
| django: CVE-2026-15337 nur in der NVD | OSV kennt die CVE nur über Git-Commits, ohne Paketzuordnung | übersehen über OSV |
| Kopien in `pip/_vendor` fehlen in der SBOM | Syft erkennt Pakete nur an ihren `dist-info`-Ordnern | übersehen über beide |

Keine Datenbank ist allein vollständig. Die meisten Abweichungen entstehen nicht durch fehlendes Wissen über die Schwachstelle, sondern durch eine fehlende oder falsche Zuordnung zwischen Schwachstelle und Produkt.


# Verbesserungsideen
- **Mehrere Quellen abfragen:** Da keine Datenbank vollständig ist, sollten OSV und NVD immer zusammen abgefragt und die Ergebnisse über die CVE-Nummer zusammengeführt werden.
- **Herstellername aus der Homepage ableiten:** Bei Django steht in den Paketdaten die Homepage `djangoproject.com`, was genau dem Herstellernamen der NVD entspricht. Bei Projekten mit einer GitHub-Seite als Homepage funktioniert das allerdings nicht.
- **Versionen vereinheitlichen:** Vor der Anfrage an die NVD sollten Versionen wie `3.2` zu `3.2.0` ergänzt oder beide Schreibweisen abgefragt werden.

# Grenzen des Projekts
- Es wurden nur Python-Pakete und ein kleines Testziel untersucht.
- Von Syft wird nur die Haupt-CPE abgefragt, nicht die weiteren geratenen Varianten.
- Die Korrekturtabelle enthält nur einen Eintrag für `django`.
- Es wird nicht geprüft, ob der fehlerhafte Code in einem Paket tatsächlich enthalten ist.
- Das Problem der fehlenden Kopien in `pip/_vendor` wird nur beschrieben, nicht gelöst.
- Die Ergebnisse sind eine Momentaufnahme, da sich beide Datenbanken laufend ändern.

# Nutzung
Voraussetzungen: Python 3.10 oder neuer und [Syft](https://github.com/anchore/syft) (auf macOS: `brew install syft`).

```bash
# Umgebung einrichten
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Testziel aufbauen und SBOM erzeugen
python3 -m venv testtarget/.venv
testtarget/.venv/bin/pip install -r testtarget/requirements.txt
syft dir:testtarget/.venv -o cyclonedx-json=testtarget/sbom.json

# Vergleich ausführen
python compare.py testtarget/sbom.json

# Einzelne Abweichungen untersuchen
python investigations/nvd_cve_details.py CVE-2024-35195
python investigations/nvd_version_spelling.py cpe:2.3:a:djangoproject:django 3.2 3.2.0
python investigations/osv_cve_lookup.py CVE-2026-15337 pkg:pypi/django@6.0.7
```

Die Abfragen an die NVD dauern etwas länger, da zwischen zwei Anfragen jeweils 6 Sekunden gewartet wird.

# Entstehung
Dieses Projekt ist ein Lernprojekt, das ich mit KI-Unterstützung (Claude Opus 5.5) als Tutor umgesetzt habe. Der Code und Teile dieser README wurden mit KI erstellt. Die Untersuchungen habe ich selbst durchgeführt, jeden Schritt nachvollzogen und alle Ergebnisse mit eigenen Abfragen überprüft.

