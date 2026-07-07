# AGENTS.md

Personal org-mode notes repo (not a software project). No build, test, or lint.

## Structure

- `notes/` — topic-based org notes (Linux internals, compilers, etc.)
- `books/` — book notes and reviews (`.org`)
- `podcasts/` — podcast scripts, show notes, and reviews (mixed `.txt`, `.org`, `.wav`)
- `words/` — vocabulary lookup records (one `.org` per word), plus batch helper `oper.sh`
- `sicp/` — SICP exercise solutions (Scheme `.scm` files, chapter-subdirs: `chap02/`, `chap03/`, etc.)
- `.opencode/skills/emacs-unsave/` — skill for recovering unsaved Emacs buffers

## Conventions

- Do not reformat, rename, or restructure `.org` files unless explicitly asked.
  `notes/` has both top-level `.org` files and topic subdirectories — do not try to normalize this.
- HTML exports (`*.html`) are gitignored; do not commit them.
- `.dir-locals.el` is gitignored (per-project Emacs settings).
- Emacs backup (`*.*~`), auto-save (`#...#`), and lock (`.#...`) files must not be committed.
  Only `*.*~` is currently in `.gitignore` — check before staging.

## Scripts

- `env.sh` — writes `PASSENGER_HOME` to `~/.env` and re-sources `~/.zshrc`.
- `record-word.sh <word>` — looks up a word via Merriam-Webster API and creates `words/<word>.org`. Requires `DICT_TOKEN` env var and `jq`.
- `words/oper.sh` — batch variant that reads words from a file named `words` and calls `record-word.sh` in a loop.

## SICP / Scheme

- Interpreter: **Guile** (`guile <file>` to load a whole file, or eval individual forms in Emacs with Geiser).
- No build step; `.scm` files are interactively evaluated, not compiled as a project.
- Guile auto-compiles and caches `.go` files under `~/.cache/guile/ccache/`. If a fix seems to have no effect, the stale cache may be loaded instead — delete the cache directory and reload.
- The user edits in Emacs and evaluates forms individually. Unsaved buffer content will not be visible on disk; use the emacs-unsave skill to recover unsaved edits.
- Exercises are grouped by chapter section: e.g. `chap02_03.scm` covers exercises in §2.3. Each exercise may redefine procedures from earlier exercises (the file is progressive, not a library).
