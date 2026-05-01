# blodilo / .github

Org-Profile-Repo. Hostet Reusable GitHub Workflows und gemeinsame
Konfigurations-Snippets, die alle blodilo-Projekte konsumieren.

## Inhalt

| Pfad | Zweck |
|---|---|
| `.github/workflows/license-check.yml` | Reusable License-Whitelist-Gate (siehe `license-check/README.md`) |
| `license-check/check_licenses.py` | Stdlib-only CycloneDX-Validator |
| `license-check/license-whitelist.json` | Mirror der Master-Whitelist aus `~/.claude/license-whitelist.json` |

## Konventionen

- **Sichtbarkeit**: public — der Inhalt (Reusable Workflow + permissive-License-Whitelist) enthält keine Geheimnisse, und Konsumenten-Repos können den Workflow ohne Cross-Repo-PAT verwenden.
- **Versionierung der Workflows**: per Tag. Konsumenten pinnen `@v1` etc.
- **Whitelist**: Single-Source-of-Truth ist die Datei in `~/.claude/`. Hier
  liegt nur der Mirror, weil GitHub Actions auf User-Home keinen Zugriff hat.

## Spec / Hintergrund

Die globale License-Management-Doku liegt in `~/.claude/CLAUDE.md`. Dieser
Repo implementiert das Standardpattern dort.
