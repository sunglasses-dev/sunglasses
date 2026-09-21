# Configuring credentials

> Fixture, written 2026-09-21, not fetched from a repository. It exists because
> of a gap in this corpus rather than because of a repository we scan.
>
> `GLS-SD-010` is line anchored, so an assignment embedded in a JSON string or
> behind a quote is not matched on any channel. Closing that needs a
> content-boundary anchor, and the variants measured for it fire on the shapes
> below — documentation telling a reader which environment variable to set.
>
> **This document must scan clean.** A rule that blocks it blocks the ordinary
> README of every project that documents an environment variable, which is the
> same cost the `-API` siblings already disclosed for AWS's published example
> key. A future embedded-content rule is licensed by this file staying green,
> not by a reviewer remembering the trade-off.

## Quick start

Copy the sample file and fill in your own values:

```bash
cp .env.example .env
```

Then open `.env` and set the key for whichever provider you use. The docs say
"API_KEY=<your key>" goes in .env, and the loader reads it at boot; if you would
rather not keep a file on disk, export it in your shell instead.

Add `OPENAI_API_KEY=sk-...` to your `.env` file so that the client picks it up
automatically, or `ANTHROPIC_API_KEY=sk-ant-...` if you are calling Claude. For
a self-hosted deployment set `DATABASE_URL=postgres://user:password@host/db`
and leave the rest at their defaults.

## The variables

| Variable | Required | Notes |
|---|---|---|
| `API_KEY=` | yes | Any supported provider. Set one of the provider-specific names below instead if you use more than one. |
| `SECRET_KEY=` | yes | Used to sign sessions. Generate a fresh one per deployment. |
| `ACCESS_KEY=` | no | Only for the object-store integration. |
| `TOKEN=` | no | Legacy name, still read for compatibility. |
| `PASSWORD=` | no | Prefer a connection string. |
| `DATABASE_URL=` | yes | A standard DSN. |

## Passing them through a container

The compose file forwards the same names, so a value set in your shell reaches
the service without being written down anywhere:

```yaml
services:
  app:
    environment:
      - "API_KEY=${API_KEY}"
      - "DATABASE_URL=${DATABASE_URL}"
```

A CI job can do the same from its secret store. The point is that the variable
NAME is public and belongs in documentation like this page; only the value is a
secret, and no value on this page is one.

## Troubleshooting

If the client reports a missing credential, check that the line in `.env` has no
leading spaces — `API_KEY=` must start the line, and a copied snippet sometimes
carries indentation from the page it came from. Quoting is optional; both
`API_KEY=abc` and `API_KEY="abc"` are read the same way.

A common mistake is pasting the whole JSON blob from a provider dashboard, which
looks like `{"API_KEY":"...","expires":0}` rather than a plain assignment. Unwrap
it first; the loader does not parse JSON.
