# Exam 2 · VaultCorp HARD · Capture the Flag

**Format:** 10 flags, 100 points, 2 hours. Blackbox pentesting.
**Covers:** S6-S8 plus REST API, with harder vulnerability classes.

## What you have

A single Flask application served at `http://127.0.0.1:5000`. You **do not**
have the source. Everything you learn, you learn from HTTP responses, from
tools you bring, and from your own reasoning.

Seed accounts:

| Username | Password |
|---|---|
| arturo.vega | arturo2026 |
| priya.kapoor | priya_rules |

Register your own account to work from.

## Rules

- 2 hours, open book (slides, notes, PortSwigger Academy), **AI assistants
  forbidden**, no collaboration.
- Target the local container only.
- Tools: Burp, curl, your own scripts.
- No denial-of-service. If something looks rate-limited, it is. Specific
  paths temp-ban your IP for 5 minutes (honeypots).
- 15 req/second default rate limit. A few specific paths are exempt.

## What you're looking for

Ten flags, each in the format `VenD{<theme>_<hex>}`. Vulnerabilities are not
all textbook. Expect:

- Template injection in unexpected places
- Weak crypto-flavoured auth bypass
- Native-object deserialization
- Concurrency-dependent attacks
- Blind injections where the useful output lives on a separate page
- File-write primitives rather than file-read
- Routing that depends on a header you'd normally not touch
- A capstone that only works if you've broken several others first

Nothing is in the open. Several endpoints are not linked. Standard recon
paths (`robots.txt`, `/.well-known/`, JS files, error pages) are honest
friends.

## Deliverable

One report per flag:

- Endpoint
- Discovery narrative (how you found it)
- Exploit payload / steps
- Flag value
- Impact
- Remediation

Plus one paragraph at the end: which flag's technique you want to learn more
about.

## Scoring

Per flag:

- 5 pts: correct flag
- 3 pts: methodology write-up
- 2 pts: impact + remediation

Pass: 30. Ceiling: 100.

Good luck.
