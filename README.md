# VaultCorp Hard CTF — Exam 2

**IMPORTANT:** this repository must be **PRIVATE** on GitHub. Trainees never read this source. They get the Docker image and a brief only.

A blackbox penetration-testing exam. 10 hard chains, each 3-5 steps. 2 hours, open book (slides, notes, PortSwigger Academy), closed to AI assistants and other trainees.

## Running

```bash
cd exam2-ctf-hard
docker compose up -d --build
```

Portal at `http://127.0.0.1:5000`. The source is baked into the image; trainees never see a Python file.

## Flag format

`VenD{<theme>_<hex>}`. All 10 are generated at first container start, written to `/opt/flags/.answers.txt` inside the container, and never committed to the repo.

```bash
docker exec vaultcorp-hard cat /opt/flags/.answers.txt
```

## What makes it hard

- Source is not public — AI cannot read the vuln patterns.
- Every endpoint of interest is undocumented. Trainees find them through recon.
- Textbook signatures replaced with less-common ones: SSTI, pickle, race condition, SVG XXE, JWT alg confusion, Zip Slip, YAML unsafe load, Host header bypass, second-order SQLi, and a final chain that needs outputs of three prior flags.
- Rate limiting (10 req/sec per IP). Honeypot paths that temp-ban. Anti-automation on the auth endpoint.
- Per-container randomised flag paths and secret endpoint names: every deployment is different; sharing a solve URL between trainees does not work.
- Flags live in files or responses only after a successful exploit, never in a Set-Cookie on login.

## Trainer materials

`trainer/` (gitignored): answer key and grading rubric.
