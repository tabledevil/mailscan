# TODO: MATT-Kern, Reporting, TUI und Worker-Pools

Status: **Backlog** (2026-11-23), aus dem Feldtest mit dem großen PST.
Verwandt: [`MAIL_ARCHITECTURE_TODO.md`](MAIL_ARCHITECTURE_TODO.md) (Mail-Schichten),
[`PST_CACHE_AND_LAZY_ACCESS.md`](PST_CACHE_AND_LAZY_ACCESS.md) (Lazy/Hintergrund in pstforensic).

## Befunde aus dem Feldtest

1. **Großes PST:** MATT gibt lange nichts aus und wirkt eingefroren. Der Report
   entsteht erst am Ende, und Text/Rich-Ausgabe sind für ~10 000 Mails mit
   ~30 000 Anhängen ungeeignet.
2. **Dispatch-Lücken:** Einige DOC-Dateien landen beim generischen Analyzer
   statt bei `OLEOfficeAnalyzer`. Ursache noch offen: MIME-Erkennung oder `can_handle`.
3. **exiftool:** Die Ausgabe wird als Textblock angehängt (`structure.py`,
   `_report_exiftool`), statt ausgewertet zu werden. Gemeint sind z. B. Autor,
   Erstell-/Änderungszeit, erzeugende Software, Widersprüche zum Container,
   GPS und eingebettete Thumbnails.
4. **Capability-Meldungen pro Objekt:** „magika / python-magic not installed“
   hängt an jedem Objekt (`Utils/filetype.py`). Richtig wäre: einmal beim Start
   prüfen, einmal im Lauf-Kopf melden, pro Objekt nur verfügbare Analysen anhängen.
5. **Weitere Kernel-Produkte als Toleranz-Referenz:** Die Free-Tools-Seite von
   Nucleus (2026-11-23) führt 48 Tools. Für MATT relevant:

   | Produkt | Format | Bezug zu MATT |
   |---|---|---|
   | OST Viewer | OST | pstforensic kann OST schon |
   | **NST Viewer** | NST (Outlook-Gruppen-Speicher) | gleiche NDB/LTP-Basis wie PST/OST, billigste Erweiterung von pstforensic |
   | **OLM Viewer** | OLM (Outlook für Mac) | ZIP plus XML/Quellen, eigene kleine Library |
   | **Exchange EDB Viewer** | EDB (ESE/JET Blue) | großes Vorhaben: ESE-Seiten, Recovery, MAPI-Mapping |
   | NSF Viewer | NSF (Lotus Notes) | eigenes, großes Format |
   | DBX Viewer | DBX (Outlook Express) | klein, Altbestände in Leaks |
   | MBOX / EML / EMLX / MSG Viewer | Mail-Einzelformate | MATT hat MBOX/EML/MSG, EMLX fehlt (trivial) |
   | XLS/XLSX Viewer, Document Viewer | Office, auch beschädigt | Toleranz-Referenz für Office-Analyzer |
   | VHD/VMDK, BKF | Container | später, Container-Analyzer |

   Ohne Beispieldateien des Nutzers testen wir gegen öffentliche Korpora und
   synthetische Fixtures; echte Proben werden nur in Docker geparst.

## Leitsätze

- **Wir zeigen nicht alles, was ein Analyzer findet, aber wir können nur zeigen,
  was gefunden wurde.** Analyzer liefern vollständige, typisierte Ergebnisse.
  Auswahl und Verdichtung macht die Darstellung.
- **Library macht alles, Policy beim Konsumenten.** Das gilt wie bei pstforensic.
- **Asynchron und inkrementell:** Objekte, Kinder und Findings erscheinen,
  sobald sie da sind. Ein Batch-Report ist nur ein Konsument, der auf „fertig“ wartet.

## Zielarchitektur

### 1. Analyse-Kern als Ereignisstrom
- Jede `Structure` hat einen Lebenszyklus:
  `queued → running → analyzed → children_done` bzw. `failed`, `skipped`, `waiting_password`.
- Der Kern sendet Ereignisse: `object_added(parent)`, `state_changed`,
  `finding_added`, `child_added`, `progress(phase, done, total)`.
- **Konsumenten:**
  - Batch-Renderer (json/md/html/text) warten auf das Ende. Die Ausgabe ist
    wie heute, nur verdichtet.
  - Die TUI zeigt live an.
  - Ein JSONL-Stream ist für Pipelines gedacht.
- Der Passwort-Broker wird ein normaler Ereignis-Teilnehmer.

### 2. Worker-Pools
- Es gibt einen globalen Scheduler mit Prioritätswarteschlange. Flach vor tief:
  zuerst die erste Ebene sichtbar machen.
- Jeder Analyzer erklärt, wie er laufen kann:
  - `concurrency`: `thread`, `process` oder `io`;
  - `max_parallel`, z. B. für YARA, exiftool oder pstforensic;
  - Speicherbedarf.
- **Container mit Massen-Kindern** (PST, Mbox, ZIP):
  - Kinder werden als Stream geliefert, nicht als Liste.
  - Ist die Warteschlange voll, bremst der Container (Backpressure).
  - Kinder werden lazy materialisiert, nur Referenz plus Abruf (pstforensic
    `item(record)`).
- Abbruch, Zeit- und Größenlimits gelten pro Objekt. Ein hängender Analyzer
  blockiert den Lauf nicht.

### 3. Fähigkeiten einmal ermitteln
- Beim Start entsteht ein Capability-Snapshot: Python-Pakete, Systemtools,
  Regelstände (`--check` gibt es schon).
- Analyzer fragen den Snapshot ab. Ist eine Fähigkeit nicht verfügbar,
  erscheint im Objekt keine Fehlermeldung, sondern nur ein Zähler im Lauf-Kopf
  („exiftool fehlt: 312 Objekte ohne Metadaten“).

### 4. Reporting-Modell
- Findings sind typisiert: Code, Schweregrad, Objekt-Referenz, strukturierte
  Felder und optional ein Beleg. Freitext gibt es nur als Zusammenfassung.
- **Verdichtung:**
  - gleiche Findings über viele Objekte gruppieren;
  - Top-N nach Schwere;
  - IOC-Aggregat;
  - „Unauffällig: 9 812 Mails“ statt 9 812 Einträge.
- exiftool und Ähnliches werden zu ausgewerteten Feldern und Findings; die
  Rohdaten bleiben im Detail abrufbar.

### 5. TUI (Textual, Extra `tui` existiert)
- **Virtualisierter Baum:** Gerendert wird nur, was auf den Bildschirm passt.
  Kinder werden lazy aufgeklappt, standardmäßig nur die erste Ebene.
- **Status am Knoten:**
  - idle;
  - Spinner, solange der eigene Analyzer läuft;
  - ✓ für den eigenen Analyzer fertig;
  - ✓✓ für den ganzen Teilbaum fertig, als Zähler „12/40“;
  - Fehler bzw. 🔒 bei Passwort.
- Findings erscheinen als Tags oder Badges am Knoten mit Schweregrad-Farbe.
  Details stehen im Seitenpanel oder lassen sich aufklappen.
- Filter nach Schwere, Typ, Status und Suche. Sprung zum nächsten Finding.
- Mit Export lässt sich aus der TUI jederzeit ein Batch-Report schreiben.
- **Alternative bzw. Ergänzung:** eine Shell (`cd`, `ls`, `show`, `find`,
  `extract`) auf demselben Ereignis- und Objektmodell. Sie ist billiger zu
  bauen und gut skriptbar.
- **Designsprache:** Farben, Symbole, Schweregrade und Begriffe werden einmal
  festgelegt und gelten für TUI, Rich, HTML und Markdown gleichermaßen.

## Vorgeschlagene Reihenfolge

0. **Schnelle Fixes mit großem Effekt, ohne Umbau:**
   - Capability-Snapshot und Meldung einmal pro Lauf;
   - DOC-Dispatch-Lücke mit Regressionstest;
   - exiftool-Auswertung (Felder und Findings).
1. **Ereignis-Kern und Lebenszyklus** in `structure.py`, Batch-Renderer
   unverändert darauf. Danach Streaming-Kinder für PST/Mbox.
2. **Scheduler und Pools** mit Limits pro Analyzer.
3. **Reporting-Modell und Verdichtung**, Renderer umstellen.
4. **Designsprache, dann TUI.** Die Shell optional, früh als Prototyp.
5. **Weitere Formate:** zuerst NST (in pstforensic), dann OLM, dann EDB als
   eigene Library nach dem Muster von pstforensic (eigene Planung).

Die Mail-Schichten aus `MAIL_ARCHITECTURE_TODO.md` passen in Schritt 1 und 3:
Das logische `MailMessage` ist dort ein Objekt im Ereignisbaum.
