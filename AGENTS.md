# AGENTS.md

Personal org-mode notes repo (not a software project). No build, test, or lint.

## Structure

- `notes/` — topic-based org notes (Linux internals, compilers, etc.)
- `books/` — book notes and reviews
- `podcasts/` — podcast scripts, show notes, and reviews
- `words/` — vocabulary lookup records (one `.org` per word)
- `sicp/` — SICP exercise solutions (Scheme)

## Conventions

- Do not reformat, rename, or restructure `.org` files unless explicitly asked.
- HTML exports (`*.html`) are gitignored; do not commit them.
- `.dir-locals.el` is gitignored (per-project Emacs settings).
- Emacs backup files (`*.*~`) are gitignored.

## Scripts

- `env.sh` — writes `PASSENGER_HOME` to `~/.env` and re-sources `~/.zshrc`.
- `record-word.sh <word>` — looks up a word via Merriam-Webster API and creates `words/<word>.org`. Requires `DICT_TOKEN` env var and `jq`.
