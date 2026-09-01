<p align="center">
  <img src="frontend/public/logo-wordmark.svg" alt="Vulncano" width="300">
</p>

<p align="center">
  <strong>One place where every scanner finding lives: deduplicated, scored, triaged, fixed and reported.</strong><br>
  The easy alternative to DefectDojo. Four tables, five minutes, and the scanners run from the tool.
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#the-data-model-in-five-minutes">Data model</a> ·
  <a href="#scanners">Scanners</a> ·
  <a href="#worked-examples">Worked examples</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="LICENSE">Apache-2.0</a>
</p>

---

## Why this exists

DefectDojo does everything, and that is the problem. Before it is useful you have to learn product
types, products, engagements, tests, findings, endpoints, 180 parsers and a permission matrix. Most
teams want something much smaller: a place where scanner output lands, gets deduplicated, gets a
score they can prioritise with, and turns into a fix that somebody is accountable for.

Vulncano keeps the value and drops the ceremony:

- **Four tables.** Project, finding, patch, plan. There is no hierarchy above a project.
- **Nothing is written behind your back.** Every scan produces an editable preview; only an explicit
  confirm inserts rows.
- **Scanners are launched from the tool**, not only imported after the fact. OSV.dev needs no
  credentials, so the tool is useful the second it is installed.
- **Fixing is tracked with the finding.** A patch record carries the fixing version, the upstream
  release date, the functional and operational impact, the regression tests and the schedule.
- **Reports are documents**, not a CSV. Jinja2 templates, HTML and PDF output, and a refusal to
  print a report whose remediation story has holes.

## Quick start

### With docker compose

```bash
git clone https://github.com/storesm/vulncano.git
cd vulncano
cp .env.example .env
python -c "import secrets;print('VULNCANO_SECRET_KEY=' + secrets.token_urlsafe(32))" >> .env
docker compose up --build
```

Then open <http://localhost:8080>. The API and its OpenAPI page are on <http://localhost:8000/docs>.

### By hand, no database server

```bash
# backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
export VULNCANO_SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
uvicorn vulncano.main:app --reload            # http://localhost:8000

# frontend, in another shell
cd frontend
npm install
npm run dev                                    # http://localhost:5173, proxies /api
```

The database is a SQLite file under `~/.vulncano/` unless you point `VULNCANO_DATABASE_URL` at
MySQL or MariaDB. The schema is created on startup; `scripts/schema.mysql.sql` and
`scripts/schema.sqlite.sql` are there if you pre-create it with a DBA account.

Want data to look at straight away?

```bash
python scripts/seed_demo.py
```

### Your first scan, from the command line

```bash
vulncano project create BACKEND "Backend service"
vulncano scan --project BACKEND --tool osv --file requirements.txt
```

## The data model in five minutes

```mermaid
erDiagram
    PROJECT ||--o{ FINDING : "groups"
    PROJECT ||--o{ PLAN : "groups"
    PROJECT ||--|| CVSS_CONFIG : "temporal and environmental metrics"
    FINDING ||--o| PATCH : "the fix for it"
    FINDING ||--o| CVSS_OVERRIDE : "per finding metric override"
    PLAN ||--o{ PATCH : "one remediation wave"
    SCAN ||--o{ FINDING : "where it came from"
```

| Table | What it is | Human id |
|---|---|---|
| `projects` | The only grouping level. Carries a short key used in filenames and reports, plus the SLA window in days for each severity. | `BACKEND` |
| `findings` | One vulnerability in one project. Several affected components live on the same row, one `component@version` per line, because a single CVE usually hits several artifacts. | `VLN-0001` |
| `patches` | The fix for one finding: fixing version, upstream release date, functional and operational impact, regression tests, schedule, applied date. | `PATCH-0001` |
| `plans` | A remediation wave. The twenty upgrades that ship in the next release, with a target version, a target date and an owner. | `PLAN-0001` |
| `scans` | One scanner run: tool, target, status, log tail, raw output. | `SCAN-0001` |

Supporting tables: `cvss_project_config` and `cvss_finding_overrides` for the temporal and
environmental metrics, `scanner_configs` for credentials (encrypted at rest, never returned by the
API), `api_tokens` for CI pushes, `report_jobs` for generated documents.

That is the whole model. There is no product type, no engagement, no test.

## Scanners

One adapter is one file under `backend/vulncano/adapters/`. The contract is small enough to read in
a minute:

```python
class ScannerAdapter:
    tool = "trivy"
    config_schema = TrivyConfig          # pydantic model, drives the settings form
    accepts = ("requirements.txt", "pom.xml", "package-lock.json", "image", "path")

    def validate(self, config) -> tuple[bool, str | None]: ...
    def run(self, config, target: ScanTarget) -> RawResult: ...
    def parse(self, raw: RawResult) -> list[NormalizedFinding]: ...
```

| Adapter | Runs | Parses | Credentials |
|---|---|---|---|
| **OSV.dev** | ✅ | ✅ | none, this is the default |
| **SCANOSS** | ✅ | ✅ | free API key, the dependency endpoint requires one |
| **SARIF** | import | ✅ | none |
| **CycloneDX** (with a vulnerabilities section) | import | ✅ | none |
| **Grype JSON** | import | ✅ | none |
| **OWASP Dependency-Check JSON** | import | ✅ | none |
| **Spreadsheet** (CSV from a security team) | import | ✅ | none |
| **Trivy** | 🚧 under development | ✅ | none |
| **Checkmarx One** | 🚧 under development | ✅ | OAuth client id and secret |

Trivy and Checkmarx One ship as complete, readable stubs: the config schema, the settings form and
the result parser are real and tested, only the step that launches the tool is missing. The UI says
so instead of pretending. Finishing either one is a single file and a very welcome first pull
request, see [CONTRIBUTING.md](CONTRIBUTING.md).

### Manifest parsing

Manifest parsing is its own module, independent of the adapters, so any adapter that only needs a
dependency list supports every ecosystem for free:

`requirements.txt` · `pyproject.toml` · `poetry.lock` · `pom.xml` · `package.json` ·
`package-lock.json` · `yarn.lock` · `go.mod` · `go.sum` · `Cargo.lock` · `Gemfile.lock` ·
`composer.lock` · `*.csproj`

Lines that cannot be understood are reported, never silently dropped:

```
requirements line 6: urllib3>=1.26.4 is not pinned with ==, using 1.26.4
requirements line 7: cryptography has no version, skipped
pom.xml: org.springframework:spring-core has no resolved version (inherited from a parent pom), skipped
```

## Worked examples

Every example below uses a file from [`backend/fixtures/`](backend/fixtures), which is also the test
input for the parsers.

### OSV.dev on a requirements.txt

```bash
vulncano project create BACKEND "Backend service"
vulncano scan --project BACKEND --tool osv --file backend/fixtures/manifests/requirements.txt
```

```
parsed 5 dependencies from requirements.txt
requirements line 6: urllib3>=1.26.4 is not pinned with ==, using 1.26.4
requirements line 7: cryptography has no version, skipped
queried 5 packages, 42 advisories so far
resolved 21 advisories
 + VLN-0001  Low       CVE-2026-27205     Flask@2.0.1
 + VLN-0002  High      CVE-2023-30861     Flask@2.0.1
 + VLN-0004  Medium    CVE-2020-28493     Jinja2@2.11.2
 + VLN-0012  Critical  CVE-2020-14343     PyYAML@5.3.1
 + VLN-0019  High      CVE-2021-33503     urllib3@1.26.4
   …
0 duplicates skipped
imported 21
```

OSV answers with both the GHSA id and its CVE alias; they are merged into one finding before you
ever see them.

### SCANOSS on a pom.xml

```bash
vulncano scan --project BACKEND --tool scanoss --file backend/fixtures/manifests/pom.xml \
  --config '{"api_url": "https://api.osskb.org", "api_key": "…"}'
```

The SCANOSS dependency endpoint needs an API key even on the free `api.osskb.org` host; without one
it answers `403` and Vulncano says exactly that. Request one at <https://www.scanoss.com/>, then put
it in the scanner settings rather than on the command line: it is encrypted at rest and the API only
ever answers `credential_set: true`.

SCANOSS replies with a CycloneDX shaped document, dependencies plus vulnerabilities. The
`affects[].ref` entries are resolved back to `component@version`, so a finding names the artifact and
not a bom-ref. Running the parser over the checked-in fixture:

```
 + Medium    CVE-2020-28493   jinja2@2.11.2       fixed in 2.11.3
 + Critical  CVE-2020-14343   pyyaml@5.3.1        fixed in 5.4
 + Critical  CVE-2021-44228   log4j-core@2.14.1   fixed in 2.17.1
```

### Importing what you already have

```bash
vulncano ingest backend/fixtures/scanners/grype.json           --project PLATFORM
vulncano ingest backend/fixtures/scanners/semgrep.sarif        --project PLATFORM
vulncano ingest backend/fixtures/scanners/cyclonedx.json       --project BACKEND
vulncano ingest backend/fixtures/scanners/dependency-check-report.json --project BACKEND
vulncano ingest backend/fixtures/scanners/security-team.csv    --project BACKEND
```

The format is detected from the file, you never have to say which importer to use. The spreadsheet
importer accepts the columns a security team actually mails around:
`CVE, PACKAGE, PURL, CWE, DESCRIPTION, BASE_SCORE, CVSS_VECTOR, REMEDIATION` (plus a few common
aliases).

### Trivy and Checkmarx One today

```bash
$ vulncano scan --project BACKEND --tool trivy --path .
Error: the Trivy adapter is under development. Install Trivy from
https://trivy.dev/latest/getting-started/installation/ and make sure the binary is on PATH …
```

Until the run step lands, produce the file yourself and import it:

```bash
trivy fs --format cyclonedx -o result.json .
vulncano ingest result.json --project BACKEND
```

## The preview step

Scanner output never goes straight into the archive. A finished scan produces an editable table:

- Duplicates are detected against the stored findings **and** against the batch itself, keyed by
  advisory + project + component. The same CVE in two projects is two findings, not a duplicate.
- Duplicates are unticked by default, and a skipped row does not consume an id. The suggested ids
  reflow live as you tick and untick, so `VLN-0001, VLN-0002, VLN-0003` has no holes.
- Every field is editable inline: severity, components, mitigation, scan type, status, project.
- One patch and one plan can be attached to the whole batch in the same submit, which is how a scan
  of twenty outdated libraries becomes one upgrade wave in a single action.
- Several uploads merge into one preview. Four manifests from four repositories scan together, and
  each row takes its project from the filename when it matches a project key
  (`SATVIS-requirements.txt` lands in `SATVIS`).
- A finding that was closed as Fixed and comes back is flagged as a **regression** rather than being
  silently deduplicated into the closed row.

## Scoring

CVSS v3.1 is implemented in this repository, with no external scoring dependency. Base, temporal and
environmental scores, the specification roundup, the severity bands. The maths is checked against the
published examples and cross-checked against an independent implementation in the test suite.

- The **base score** comes from the scanner when it provides one, otherwise from an NVD lookup by CVE
  id. Score, severity, vector and fetch timestamp are cached on the finding. Set `VULNCANO_NVD_API_KEY`
  for the higher rate limit; there is a bulk refresh in the UI and on `POST /api/cvss/refresh`.
- On top of that, the project level temporal and environmental metrics (E, RL, RC, CR, IR, AR, MAV,
  MAC, MPR, MUI, MS, MC, MI, MA) are merged with any per finding override to produce the **adapted
  score**. A null override falls back to the project value.
- Changing a project metric recomputes every finding in that project, and says how many it touched.
- Both scores are shown side by side and the full vector is exposed, so nobody has to trust a bare
  number.
- Severity is a single field. It follows the adapted score when a vector exists and is editable by
  hand when there is none. There is no "scanner severity" column competing with a computed one.

## Remediation plans

Tracking vulnerabilities is worthless if the fixing is not tracked with them.

- Filter the findings list, select the rows that ship together, create a plan in one action. Missing
  patch records are created for you.
- A plan view lists its findings with their patch state and says what is missing: findings with no
  fixed version, patches with no regression test defined.
- Marking a plan **Done** sets its findings to Fixed and stamps `applied_at` on their patches.
  Findings marked **Risk accepted** are left alone, so a plan can close with some findings
  deliberately unfixed, recorded as such with a justification in the mitigation field.
- Ageing is computed, never typed: days since publication, days since detection, and the SLA window
  configured per severity on the project.

## Reports

```bash
vulncano report --plan PLAN-0001 --format pdf --out remediation-2.4.pdf
```

- Scope is a project, a plan or an explicit selection of findings.
- Rendering is Jinja2. `default.html` produces the HTML and the PDF, `default.md` the markdown
  export. Templates live in `backend/vulncano/templates/` and are meant to be replaced: point
  `VULNCANO_REPORT_TEMPLATES_DIR` at your own directory and your files win. Adding a template does
  not touch the backend.
- Generation is a job. Submit returns a job id, the status is pollable, and the result downloads as
  the rendered document plus a zip of the template sources used, so the output can be reproduced or
  hand edited.
- The report carries the finding table with both scores and the affected components, plus a
  remediation section built from the patches and the plan.
- After a successful generation you can mark the included findings as reported, so the next report
  scopes to what is new.
- A report whose remediation state has holes is **refused**, with the offending ids named:

```
Error: not ready to report: VLN-0012 is still New, triage it first;
VLN-0007 is still New, triage it first; …
```

PDF output uses WeasyPrint. It is installed in the docker image; for a manual install add
`pip install "vulncano[pdf]"`, or generate HTML or markdown instead.

## Automation

### CLI

The CLI shares the exact code the API uses, there is no second implementation.

```bash
vulncano project create BACKEND "Backend service"
vulncano project list
vulncano scan --project BACKEND --tool osv --file requirements.txt
vulncano ingest results.sarif --project BACKEND --origin "gha/build#412"
vulncano findings --project BACKEND --severity Critical,High
vulncano plan --project BACKEND --name "2.4 upgrade wave" --finding VLN-0004 --finding VLN-0012
vulncano report --plan PLAN-0001 --format pdf --out report.pdf
vulncano recompute --project BACKEND
vulncano dump --out backup.sql
vulncano restore backup.sql
```

Every command takes the database from `--database-url` or `VULNCANO_DATABASE_URL`.

### CI push

Create a token in Settings, scoped to a project, then push from the build:

```bash
curl -X POST http://vulncano.internal:8000/api/findings/ingest \
  -H "Authorization: Bearer $VULNCANO_TOKEN" \
  -F "origin=gha/${GITHUB_REPOSITORY}#${GITHUB_RUN_ID}" \
  -F "file=@grype.json"
```

Rows arriving this way get `origin` set to the job identifier and status `New`, and never overwrite a
human triage decision. Copy-paste workflows for GitHub Actions and Jenkins are in
[docs/ci.md](docs/ci.md).

## API

REST under `/api`, OpenAPI at `/docs`.

```
/api/projects                      CRUD
/api/findings                      list with filters, get, create, update, delete
/api/findings/batch-update         bulk status, severity, reported
/api/findings/batch-delete
/api/findings/preview              parse uploads into the editable preview
/api/findings/import               confirm the preview, optionally with one patch and one plan
/api/findings/ingest               CI push, API token
/api/findings/dashboard            counts, SLA breaches, overdue plans
/api/patches                       list, upsert by finding, delete
/api/plans                         CRUD, /{id}/findings to attach and detach
/api/scanners/adapters             what is installed and its config schema
/api/scanners/configs              credentials CRUD plus /{id}/test
/api/scans                         create, get, /{id}/log, /{id}/results
/api/cvss/project/{id}             project metrics, recomputes on save
/api/cvss/finding/{id}/override    per finding override
/api/cvss/refresh                  bulk NVD lookup
/api/reports/generate              job, /{id}, /{id}/download, /{id}/bundle
/api/tokens                        create, list, revoke
/api/dump                          full SQL dump, /restore to load one back
```

## Configuration

| Variable | Default | What it does |
|---|---|---|
| `VULNCANO_DATABASE_URL` | `sqlite:///~/.vulncano/vulncano.db` | SQLAlchemy url. MySQL: `mysql+pymysql://user:pass@host/vulncano` |
| `VULNCANO_DATA_DIR` | `~/.vulncano` | Raw scanner output, rendered reports |
| `VULNCANO_SECRET_KEY` | *(empty)* | Required before any scanner credential can be stored |
| `VULNCANO_AUTH_ENABLED` | `false` | Single user basic auth. Off so a laptop install just works |
| `VULNCANO_AUTH_USER` / `VULNCANO_AUTH_PASSWORD` | `admin` / *(empty)* | The one account, when auth is on |
| `VULNCANO_NVD_API_KEY` | *(empty)* | Raises the NVD limit from 5 requests / 30s to 50 |
| `VULNCANO_CORS_ORIGINS` | `http://localhost:5173` | Comma separated |
| `VULNCANO_REPORT_TEMPLATES_DIR` | *(unset)* | Your templates, they win over the packaged ones |

## Development

```bash
cd backend
pip install -e ".[dev]"
pytest                      # 86 tests, no network access needed
python ../scripts/generate_schema.py     # after any model change
```

The suite covers the CVSS maths against the published spec examples, every manifest parser, every
adapter parse step against its fixture, the deduplication and id assignment rules, the SLA and
overdue computations, and the whole API flow from upload to report. Adapter run steps are tested with
the tool stubbed out; parse steps run for real.

## What Vulncano will not grow

Said no to on purpose, they are the reason this exists:

- No product type / product / engagement / test hierarchy.
- No role and permission matrix. Optional single user auth, plus API tokens for CI.
- No ticketing integrations, notification engine, questionnaires, metrics warehouse or benchmark
  modules.
- No plugin marketplace. Five adapters plus the generic importers, each in one readable file.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
