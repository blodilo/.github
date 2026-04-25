# license-check

Reusable License-Whitelist-Gate für alle Projekte unter `blodilo/`. Konsumenten-Repos
referenzieren den Workflow `.github/workflows/license-check.yml`; die globale
Spec liegt in `~/.claude/CLAUDE.md` → „SBOM-Generierung & License-Check-Gate".

## Was hier liegt

| Datei | Inhalt |
|---|---|
| `check_licenses.py` | Stdlib-only Python-Validator. Liest CycloneDX-SBOM(s) und prüft jeden `component`-Eintrag gegen `license-whitelist.json` + projektlokale `license-exceptions.json`. Exit 1 bei Verstößen. |
| `license-whitelist.json` | **Mirror** von `~/.claude/license-whitelist.json` (Source-of-Truth). Aktuell manuell synchronisiert; Sync-Mechanismus pendend (DevLaunchpad-Ticket). |

## Konsument einbinden

In der `ci.yml` des Konsumenten-Projekts:

```yaml
jobs:
  license-check:
    uses: blodilo/.github/.github/workflows/license-check.yml@v1
    with:
      language: mixed       # oder: node, python, go, kotlin, rust
      frontend-path: ./frontend
      backend-path: ./backend
```

## Was passiert bei rotem Build

1. Workflow-Output liest sich z.B. so:
   ```
   ❌ 2 license violation(s):
     - lightningcss@1.32.0  [YELLOW]  (MPL-2.0)
     - example-pkg@2.1.0    [UNKNOWN] (UNKNOWN)
   ```
2. Drei Auswege:
   - **Paket austauschen** gegen Alternative mit grüner Lizenz
   - **Exception eintragen** in `license-exceptions.json` des Konsumenten-Projekts
     (Format siehe unten) — nur für 🟡 Yellow oder dokumentierte Sonderfälle
   - **Bei 🔴 Rot**: Hard-Fail, kein Auto-Approve. Globale Regel.

## `license-exceptions.json` Format

```json
{
  "project-type": "commercial",
  "package-exceptions": [
    {
      "name": "lightningcss",
      "version": "*",
      "spdx": "MPL-2.0",
      "reason": "Build-time CSS parser. Dynamic linking, no source modifications.",
      "approved-by": "martin.theis",
      "approved-at": "2026-04-25"
    }
  ]
}
```

`version` darf `*` sein (alle Versionen) oder eine konkrete Version. Pfeil-Logik:
exact match zuerst, dann `*`-fallback.

## Verifikation lokal

```bash
python3 check_licenses.py \
  --whitelist license-whitelist.json \
  --exceptions /pfad/zum/projekt/license-exceptions.json \
  --sbom /pfad/zum/projekt/sbom-frontend.json \
  --sbom /pfad/zum/projekt/sbom-backend.json
```

## Updates

- Whitelist-Änderung: lokale `~/.claude/license-whitelist.json` editieren, danach
  diese Mirror-Datei manuell anpassen (PR), nach Merge ziehen Konsumenten den
  neuen Stand mit dem nächsten `@v1`-Pull (kein Tag-Bump nötig, Whitelist-Mirror
  läuft im selben `main`).
- Workflow-Verhaltensänderung: hier ändern, neues Tag (`v2`), Konsumenten ziehen
  einzeln nach (`uses: …@v2`).
