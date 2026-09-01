# Contributing

Thanks for looking. The fastest way to help is to finish an adapter, and the second fastest is to
tell us where the tool lied to you: an error message that did not say what to do is a bug here.

## Getting set up

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The tests need no network and no database server. The frontend is `cd frontend && npm install && npm run dev`.

## Writing a new adapter

An adapter is one file in `backend/vulncano/adapters/` and one line in
`backend/vulncano/adapters/__init__.py`. Nothing else. The settings form, the scan screen and the
CLI pick it up from the class attributes.

```python
class MyScannerConfig(BaseModel):
    base_url: str = Field(default="https://example.com", description="shown as the form label")
    api_key: str = Field(default="", description="never returned by the API",
                         json_schema_extra={"secret": True})


class MyScannerAdapter(ScannerAdapter):
    tool = "myscanner"                  # unique, appears in the API and the CLI
    label = "My Scanner"                # what the UI shows
    config_schema = MyScannerConfig     # drives the settings form
    accepts = ("requirements.txt", "image", "path")
    needs_credentials = True
    install_hint = "How to get the binary or the credentials, in one sentence."

    def validate(self, config) -> tuple[bool, str | None]:
        """Called by the test-credentials button. Return (ok, message)."""

    def run(self, config, target: ScanTarget) -> RawResult:
        """Produce the tool's native output. Raise ScannerError with an actionable message."""

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        """Turn that output into normalized findings. No database access, no side effects."""
```

Rules that keep the set of adapters readable:

1. **`parse` is pure.** Bytes in, findings out. No HTTP, no database, no filesystem. That is why it
   can be tested against a fixture.
2. **`run` never blocks a request.** It is called from the background job runner. A long running
   service should return a `RawResult` carrying `remote_id` and be resumable by polling.
3. **Errors name the fix.** `ScannerError("trivy is not on PATH, install it from …")`, never
   `ScannerError("scan failed")`. A missing binary, an expired credential, a rate limited service and
   a malformed manifest each get their own message.
4. **Do not parse manifests yourself.** Call `target.manifests()` and you get every ecosystem
   Vulncano understands, plus the warnings for lines it could not read.
5. **Mark secrets** with `json_schema_extra={"secret": True}`. The API then filters them out of every
   response and only reports `credential_set`.
6. **Set `implemented = False`** if the run step is not finished. The UI shows "under development"
   and explains what to do instead, which is much better than a stack trace.

Then add the fixture and the test:

```
backend/fixtures/scanners/myscanner.json     # a real output, trimmed, no customer data
backend/tests/test_adapters.py               # one test for parse, one for the run error path
```

The parse test runs for real. The run test stubs the transport (`httpx.MockTransport` or
`monkeypatch.setattr` on the module's `httpx.post`), see the existing OSV and SCANOSS tests.

## Two adapters are waiting for you

`trivy.py` and `checkmarx.py` ship with their config schema, their parser and their tests already
written. Only `run` (and `poll` for Checkmarx) raise `NotImplementedYet`. Finishing one is a
self-contained pull request:

- **Trivy**: shell out to the binary with `--format json`, support `trivy fs` on an uploaded manifest
  or extracted archive, `trivy image` on an image reference and `trivy sbom` on a CycloneDX or SPDX
  file. Honour the offline, cache dir, severity floor and custom db repository settings. The parser
  for `Results[].Vulnerabilities[]` and `Results[].Misconfigurations[]` is already there.
- **Checkmarx One**: authenticate against the tenant, zip and upload the sources or reference an
  existing project id, trigger a scan with the requested engines, return the remote scan id, and
  implement `poll` so the job runner can resume. Never block. The SAST and SCA result parser is
  already there.

## Adding a manifest parser

`backend/vulncano/manifests.py`, one function returning a `ManifestResult`, one entry in `PARSERS`,
one test in `test_manifests.py` with a fixture under `backend/fixtures/manifests/`. Unparseable lines
go into `result.warnings` with the line number. They must never disappear.

## Changing the schema

There is no Alembic. Edit `backend/vulncano/models.py`, then:

```bash
python scripts/generate_schema.py
```

and add a numbered file under `scripts/migrations/` for people who already have data. See
`scripts/migrations/README.md`.

## Style

The code should read like one engineer wrote it in a sitting.

- Comments explain why, never what. Most code needs none.
- No abstraction without a second real user. No interface with one implementation.
- Errors are honest and specific. A generic message is worse than a stack trace.
- Frontend: plain JavaScript, plain React, no component library, no state management library. If a
  new dependency is the answer, say why in the pull request.
- Python is formatted at 110 columns. Keep imports at the top of the file.

## Pull requests

Small and focused beats large and complete. Say what you changed and why in two sentences, run
`pytest`, and mention anything you deliberately left out. Bug reports are welcome with the exact
command, the exact output and what you expected instead.

By contributing you agree that your work is licensed under Apache-2.0.
