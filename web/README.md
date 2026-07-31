# Frontend tooling

The console's *served* files live inside the API package
(`apps/api/src/iceberg_api/web/`), because the API serves them and they ship in
its image. This directory holds the one thing that is build-time rather than
run-time: the asset vendoring script.

```
uv run python web/vendor_assets.py
```

It pins exact versions of the Alpine CSP build, HTMX, and the three self-hosted
font families, downloads them from `registry.npmjs.org` and Google Fonts into
`apps/api/src/iceberg_api/web/static/`, and writes `static/assets.lock.json` with
a `sha384` integrity for each. `base.html` reads that lock to emit `integrity=`
attributes, which is what lets the Content-Security-Policy stay at
`script-src 'self'`.

Run it deliberately when bumping a pin, review the diff, and commit the
regenerated files together with `assets.lock.json`.
`apps/api/tests/test_web_invariants.py` verifies the committed files against the
lock offline, so CI notices a hand-edited vendor file without a network call.

There is no CSS build step and no Node toolchain — see
[`docs/web.md`](../docs/web.md) § Asset pipeline for why.
