# Pushing findings from CI

Create a token in Settings → tokens, scoped to the project the build belongs to. The plaintext token
is shown once. Rows arriving through the ingest endpoint are stamped with the job identifier, land as
`New`, and never overwrite a triage decision a human already made.

```
POST /api/findings/ingest
Authorization: Bearer vlc_…
multipart: file=@<scanner output>, origin=<job identifier>
```

The format is detected from the file: SARIF, CycloneDX, Grype JSON, OWASP Dependency-Check JSON or a
CSV. Add `-F tool=grype` to force one.

## GitHub Actions

```yaml
name: security

on:
  push:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan the filesystem with Grype
        uses: anchore/scan-action@v4
        with:
          path: .
          output-format: json
          fail-build: false

      - name: Push the findings to Vulncano
        env:
          VULNCANO_URL: ${{ vars.VULNCANO_URL }}
          VULNCANO_TOKEN: ${{ secrets.VULNCANO_TOKEN }}
        run: |
          curl --fail-with-body -X POST "$VULNCANO_URL/api/findings/ingest" \
            -H "Authorization: Bearer $VULNCANO_TOKEN" \
            -F "origin=gha/${GITHUB_REPOSITORY}#${GITHUB_RUN_ID}" \
            -F "file=@results.json"
```

Any tool works the same way. A SARIF producing job pushes its `.sarif` unchanged:

```yaml
      - name: Semgrep
        run: semgrep --config auto --sarif --output semgrep.sarif || true

      - name: Push
        run: |
          curl --fail-with-body -X POST "$VULNCANO_URL/api/findings/ingest" \
            -H "Authorization: Bearer $VULNCANO_TOKEN" \
            -F "origin=gha/${GITHUB_REPOSITORY}#${GITHUB_RUN_ID}" \
            -F "file=@semgrep.sarif"
```

## Jenkins

```groovy
pipeline {
    agent any

    environment {
        VULNCANO_URL = 'https://vulncano.internal'
    }

    stages {
        stage('Scan') {
            steps {
                sh 'grype dir:. -o json > grype.json'
            }
        }

        stage('Push to Vulncano') {
            steps {
                withCredentials([string(credentialsId: 'vulncano-token', variable: 'TOKEN')]) {
                    sh '''
                        curl --fail-with-body -X POST "$VULNCANO_URL/api/findings/ingest" \
                          -H "Authorization: Bearer $TOKEN" \
                          -F "origin=jenkins/${JOB_NAME}#${BUILD_NUMBER}" \
                          -F "file=@grype.json"
                    '''
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'grype.json', allowEmptyArchive: true
        }
    }
}
```

## GitLab CI

```yaml
vulncano:
  stage: test
  image: alpine:3.20
  before_script:
    - apk add --no-cache curl
  script:
    - >
      curl --fail-with-body -X POST "$VULNCANO_URL/api/findings/ingest"
      -H "Authorization: Bearer $VULNCANO_TOKEN"
      -F "origin=gitlab/${CI_PROJECT_PATH}#${CI_PIPELINE_ID}"
      -F "file=@gl-dependency-scanning-report.json"
```

## From the CLI instead

If the build machine can reach the database directly, skip the token and use the CLI. It runs the
same code as the API.

```bash
vulncano ingest grype.json --project BACKEND --origin "jenkins/${JOB_NAME}#${BUILD_NUMBER}" --yes
```

## Failing a build on new critical findings

The ingest response lists what it created, so a build can decide for itself:

```bash
created=$(curl -sS -X POST "$VULNCANO_URL/api/findings/ingest" \
  -H "Authorization: Bearer $VULNCANO_TOKEN" \
  -F "origin=gha/${GITHUB_REPOSITORY}#${GITHUB_RUN_ID}" \
  -F "file=@grype.json" | python -c "import json,sys; print(len(json.load(sys.stdin)['created']))")

echo "$created new findings"
test "$created" -eq 0
```
