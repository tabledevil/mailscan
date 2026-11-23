# pstforensic: Cache, wahlfreier Zugriff, Carving im Hintergrund

Stand 2026-11-23. Gilt für `pstforensic` (Library) und MATT (`PstAnalyzer`).

## Warum

Kernel PST Viewer zeigt den Ordnerbaum nach Schritt 1 (B-Tree) an. Erst danach
baut sein Lost/Deleted-Scan einen reinen Index in einem einzigen Durchlauf. Den
Scan kann man überspringen. Inhalte liest Kernel erst beim Öffnen einer Mail.
Wir haben bisher bei jedem Start alles neu gerechnet und erst am Ende etwas
ausgegeben.

## 1. Strukturindex-Cache

**Was gecacht wird, pro Store und Version:**
- `btree`: NBT/BBT-Einträge, Seitenurteile, übersprungene Seiten
- `scan`: der `ScanIndex` (Seiten, NBT-Slots, Blockkandidaten)
- `carving`: welche BIDs Carving-Treffer waren
- `items`: ein Record pro Item (Status, Provenienz, NID/BID, Ordner-NID, NBT-Eintrag)

**Inhaltsfrei.** Im Cache stehen nur Offsets, IDs, Größen, Prüfergebnisse und
Statusnamen. Keine Property-Werte, Ordnernamen, Betreffs oder Dateinamen.
Ein Test sichert das ab (`test_cache.py`).

**Schlüssel nach Inhalt, nicht nach Name.** In einem Leak mit vielen gleich
benannten PSTs (`outlook.pst`, `archive.pst` …) kollidiert deshalb nichts.
Byte-identische Duplikate teilen sich dagegen einen Eintrag, das ist der Mehrwert.
- **Standard:** ein gesampelter Fingerprint aus
  - Größe,
  - den ersten 64 KiB (Header/ROOT),
  - dem letzten MiB,
  - 64 gleichmäßig verteilten Fenstern zu je 4 KiB,
  - Format- und Library-Version.

  Die mtime fließt **nicht** ein, damit Kopien treffen.
- **Pipeline:** `open_store(path, cache_key=sha256)` übernimmt den Hash, den
  die Pipeline ohnehin berechnet. Das ist exakt und kostet nichts.
- **Zusätzlich beim Laden:** Die gespeicherten ersten 4 KiB müssen mit der
  Datei übereinstimmen, sonst wird der Eintrag ignoriert.

**Plattenplatz:**
- Einträge sind zlib-komprimiert.
- Obergrenze für das Verzeichnis: 4 GiB (`PSTFORENSIC_CACHE_MAX_MB`).
  Darüber werden die am längsten ungenutzten Einträge verdrängt (LRU über die
  mtime des Eintragsverzeichnisses, die bei jedem Laden aufgefrischt wird).
- Bei weniger als 2 GiB freiem Platz wird nichts geschrieben.
- Ein einzelner Eintrag über der halben Obergrenze wird nicht gespeichert.

**Paralleler Betrieb (mehrere Prozesse, ein Cache-Verzeichnis):**
- Schreiben geht über eine Temp-Datei mit anschließendem `os.replace`. Leser
  sehen nie halbe Einträge.
- Zwei Prozesse, die denselben Schlüssel rechnen, schreiben identische Daten.
  Der letzte gewinnt, ohne Schaden.
- Die Verdrängung läuft unter einem nicht-blockierenden Lockfile. Ist es
  belegt, wird die Verdrängung übersprungen. Ein verwaister Lock gilt nach
  10 Minuten als veraltet.
- Ein verschwundener Eintrag ist einfach ein Cache-Miss.
- Ein Test mit 4 Prozessen sichert das ab.

**Sicherheit:** Gelesen wird mit einem eingeschränkten Unpickler, der nur
pstforensic-Records und Builtins zulässt. Ein manipulierter Eintrag wird
abgelehnt und neu gerechnet (Test).

**Einschalten:**
- Library: opt-in über `cache_dir=` oder `PSTFORENSIC_CACHE_DIR`. Eine
  Forensik-Library schreibt nicht ungefragt.
- Tools: standardmäßig an (`~/.cache/pstforensic`), abschaltbar mit `--no-cache`.
- MATT: über `--cache-path DIR`, der Cache liegt dann in `DIR/pstforensic`.

## 2. Wahlfreier Zugriff

- `store.item_index()` liefert die Strukturrecords aller Items. Mit Cache kommt
  das sofort, ohne Enumeration.
- `store.item(record)`, `store.item(nid=…)` und `store.item(bid=…)` bauen genau
  eine Mail, also PC, Empfänger und Anhänge nur dieses Items.
- Beim Wiederaufbau fehlen Historie und Supersession-Verweise, die nur eine
  vollständige Enumeration liefert.

## 3. Carving im Hintergrund

`iter_items(carving=…)`:
- **`"inline"`** (Standard): Carving-Treffer kommen am Ende des Streams, die
  Liste ist vollständig.
- **`"background"`:**
  - Der Stream endet nach den strukturellen Items (live, gelöscht, orphan,
    superseded, lost).
  - Das Carving läuft in einem Thread weiter und ruft `on_carved(item)` pro
    Fund auf, etwa um eine Untersuchung anzustoßen. Ein fehlerhafter Hook
    stoppt das Carving nicht, sondern landet in der Diagnose.
- **`"skip"`:** Das Carving startet erst, wenn `store.carved_items()` aufgerufen wird.

`store.carved_items()` blockt, bis der Carving-Index vollständig ist.
`store.carving.done` und `.wait(timeout)` zeigen den Zustand ohne zu blockieren.
Das Carving dedupliziert gegen alle strukturellen Items und muss deshalb nach
ihnen laufen. Im Cache stehen die Treffer-BIDs, beim zweiten Lauf werden nur
diese gelesen.

**Grenze:** Ein Thread teilt sich den GIL mit dem Konsumenten. Echte
Parallelität beim Carving bringen erst Worker-Prozesse (Issue #1, nächster
Schritt). Der Scan ist bereits prozessparallel.

## 4. Passt das zur MATT-Philosophie?

- **Library macht alles, Policy beim Konsumenten.** Passt: Cache, Lazy-Zugriff
  und Hintergrund-Carving sind Fähigkeiten der Library. Ob MATT sie nutzt,
  entscheidet der Analyzer.
- **MATT ist ein Batch-Lauf.** Ein Report entsteht einmal am Ende. Deshalb
  nutzt `PstAnalyzer` vorerst `carving="inline"`, also ein vollständiger und
  deterministischer Report. Hintergrund-Carving mit `on_carved` würde in MATT
  wie der Password-Broker funktionieren: Ein Fund erzeugt eine Child-Struktur,
  der Report wartet auf `carved_items()`. Echten Zeitgewinn bringt das erst,
  wenn die Child-Analyse nicht im selben GIL läuft.
- **Bedienoberflächen** (`tui`-Extra, Leak-Pipeline) profitieren direkt: erst
  der Baum, Inhalte bei Bedarf, Carving-Funde als Ereignisse.

## 5. Braucht MATT allgemein einen Cache?

Ja, als eigener, opt-in Ergebnis-Cache, getrennt vom Library-Cache:
- **Schlüssel:** SHA-256 des Objekts, Analyzer-Name und -Version sowie die
  relevanten Flags (Netzwerk-Policy, YARA-Regelstand). MATT dedupliziert heute
  nur im Speicher und nur innerhalb eines Laufs.
- **Nutzen:** In Leaks wiederholen sich dieselben Anhänge, Signaturbilder und
  Disclaimer tausendfach, über Läufe und parallele Worker hinweg.
- **Unterschied zum Library-Cache:** MATT-Reports **enthalten Inhalt** (IOCs,
  Auszüge, Dateinamen). Ein solcher Cache gehört in einen kontrollierten Ort,
  ist opt-in und braucht eventuell Verschlüsselung und Aufbewahrungsregeln.
- **Mechanik** wie hier: atomar, größenbegrenzt, mehrprozessfähig.
- **Status:** Vorschlag, noch nicht gebaut.
