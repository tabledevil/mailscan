# TODO: Mail-Zerlegung — Schichtenarchitektur (EML / MSG / PST / TNEF / S/MIME)

Status: **zurückgestellt** (2026-11-22), erst PST-Feldtest-Feedback.

## Befund (Review 2026-11-22)

Bestätigt durch Tests:
- RFC 2231 Dateiname (`filename*=UTF-8''…`) → `get_param()` liefert Tupel, `.strip()` crasht → ganze EML `not_parsable`. **Hotfix + Regressionstest, unabhängig vom Umbau.**
- Angehängte `message/rfc822` wird plattgeklopft: innere Header (From, Received, Auth) und Dateiname gehen verloren, EmailAnalyzer sieht die innere Mail nie.
- Python-`email`-Defekte (`msg.defects`) werden nicht gemeldet.
- MsgAnalyzer: eingebettete MSG (`.data` = MSGFile → TypeError) oder Web-Anhang (NotImplementedError) bricht in einem gemeinsamen `try` alle folgenden Anhänge ab.
- `check_sig` / `check_dkim` / `check_spoof` / `check_header` in `eml.py` sind Stubs (`False`).

Durch Inspektion:
- Header-Checks nur für EML; MSG nur Route/Auth; PST-Items bekommen keine Header-Analyse (`PidTagTransportMessageHeaders` 0x007D wird nicht übergeben).
- Kein TNEF (`winmail.dat`), kein S/MIME/PGP (Signer-Zertifikate, opak signierter Inhalt, Verschlüsselung markieren).
- MSG RTF-Body (komprimiertes RTF, encapsulated HTML) nicht übergeben.
- Bounces (`message/delivery-status`, `text/rfc822-headers`) verworfen.
- Referenz-/URL-/OLE-Anhänge (Methoden 2/4/6) nicht gemeldet (IOCs).
- Deklarierter Charset nicht an Kinder weitergegeben (nur Erkennung).
- Inline uuencode/yEnc/BinHex nicht erkannt; Name-Mismatch Content-Type vs. Disposition nicht gemeldet; kaputtes Base64 still.
- Nativer `pstforensic.msg` ungenutzt.

## Ursache

Ein Analyzer pro Dateiobjekt vermischt Format-Parsing, Mail-Logik und Aufbereitung;
Kinder sind nur Bytes, die Semantik (Body von X, Anhang per Referenz, eingebettete Mail) geht verloren.

## Zielarchitektur

1. **Format-Libraries** (verlustfrei, tolerant, Findings, keine Policy — Vertrag wie pstforensic):
   - MAPI-Familie: PST/OST, MSG (CFBF), **TNEF** (ist intern MAPI-Properties → `pstforensic.mapi` wiederverwenden)
   - MIME-Familie: RFC 5322/MIME (stdlib kapseln + eigene Wiederherstellung wo Daten verloren gehen), S/MIME (CMS), PGP, uuencode/yEnc/BinHex
   - Jeder Part adressierbar (Pfad/Offset), roh + dekodiert + Dekodier-Nachweis; Defekte = Findings.
2. **Logisches Modell** (in der Library, nicht in MATT — auch für die Leak-Ingest-Pipeline):
   `MailMessage` mit Headern (roh + geparst), Beteiligten, Zeiten, Bodies (plain/html/rtf mit Herkunft),
   Anhängen (inline/attached/reference/embedded/OLE), eingebetteten Nachrichten (rekursiv),
   Sicherheit (Signatur/Verschlüsselung), Herkunftskette, Integrität.
   Adapter `from_mime()`, `from_mapi()`; MAPI↔MIME-Normalisierung hier (PST-Transport-Header → derselbe Header-Parser).
3. **MATT**: Objekt-Analyzer werden dünn (erkennen, Library aufrufen, Modell weitergeben);
   ein logischer `MessageAnalyzer` für alle Quellen (Header, Auth, Spoofing, Relay, Übergabe der Anhänge).

## MATT-Infrastruktur (minimal-invasiv)

- `Structure` darf ein logisches Objekt tragen (`obj=MailMessage`) mit Pseudo-Typ `x-matt/message`
  → bestehender Multi-Dispatch über `compatible_mime_types` bleibt.
- Cache-Key = Inhalts-Fingerprint des Modells statt SHA-256 der Bytes.
- Große PSTs: Nachrichten lazy als Modell statt Bytes materialisieren.
- Abhängigkeit nur MATT → Library.

## Reihenfolge

0. RFC-2231-Hotfix + Test.
1. MIME-Leser (Schicht 1), dann TNEF, dann CMS.
2. Modell + Adapter, Tests gegen **echte** Mails (Self-Oracle-Lehre aus pstforensic).
3. `MessageAnalyzer`, alte Analyzer zu Adaptern abbauen.
