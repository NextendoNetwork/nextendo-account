<h1 align="center">nextendo-account</h1>

<p align="center">
  <b>The Nextendo Network account server: identities, friends, presence, and BCAT.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-PolyForm%20Shield%201.0.0-orange" alt="License: PolyForm Shield 1.0.0">
  <img src="https://img.shields.io/badge/go-1.21%2B-00ADD8" alt="Go 1.21+">
</p>

---

## What is this?

**nextendo-account** is the identity and social backend for [Nextendo Network](https://nextendo.network).
It issues and validates the account tokens the game servers trust, and serves the website's account
API. In one Go process it provides:

- **Accounts**: registration, e-mail verification, password reset, sign-in tokens (web + NEX).
- **Friends & presence**: the unified friend graph and online status shared across the games.
- **BCAT**: the schedule/data cache titles download (e.g. Splatoon 2's VS/Coop schedule).
- **Sessions & security**: active-session management, bans, rate limiting, an admin space.
- **Signing**: signs the `nx2.` NEX login tokens the game servers verify.

It is stdlib-only apart from `golang.org/x/crypto`, and stores its state as JSON files under a
data directory.

## Running

```sh
cp example.env .env    # then edit .env
go run .
```

Everything is configured through environment variables: see [`example.env`](example.env). **No
secrets, keys, credentials, or personal data are baked into the source**: the token-signing secret,
internal key, SMTP credentials, and admin list are all read from the environment (or files) at
startup, and the admin space is closed until you configure `NEXTENDO_ADMIN_EMAILS`.

## Internal routes

`/api/*` routes are public; `/internal/*` routes (identity, login, presence) are a control plane that
must never be reachable from the internet. `internal_guard.go` enforces this in the application layer
by checking the real TCP source address (never a spoofable header) plus a shared internal key.

## What this is not

Ships **no** Nintendo code, keys, or copyrighted assets, and no captured data. Independent
reimplementation for a community-run service; not affiliated with, endorsed by, or associated with
Nintendo.

## License

Released under the **[PolyForm Shield License 1.0.0](LICENSE.md)**, source-available: read, use,
modify, and self-host, but do not use it to provide a product that competes with Nextendo Network.
