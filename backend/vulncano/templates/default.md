# {{ title }}

{% if project %}**Project:** {{ project.name }} ({{ project.key }}){% else %}**Projects:** {{ projects | map(attribute='key') | join(', ') }}{% endif %}

| | |
|---|---|
| Document code | {{ document_code or '-' }} |
| Version | {{ version }} |
| Authors | {{ authors or '-' }} |
| Software version | {{ software_version or '-' }} |
| Analysis date | {{ analysis_date }} |
| Generated | {{ generated_at }} by Vulncano |

## Summary

{% for severity in ['Critical', 'High', 'Medium', 'Low', 'Info'] %}
- {{ severity }}: {{ counts.get(severity, 0) }}
{% endfor %}

Total: {{ total }} findings.

## Findings

| Id | CVE | Severity | Base | Adapted | Components | Status |
|---|---|---|---|---|---|---|
{% for finding in findings %}
| {{ finding.ref }} | {{ finding.cve_id or finding.external_id or '-' }} | {{ finding.severity }} | {{ '%.1f' | format(finding.cvss_base_score) if finding.cvss_base_score is not none else '-' }} | {{ '%.1f' | format(finding.adapted_score) if finding.adapted_score is not none else '-' }} | {{ finding.components | replace('\n', ', ') }} | {{ finding.status }} |
{% endfor %}

## Detail

{% for finding in findings %}
### {{ finding.ref }} - {{ finding.title }}

`{{ finding.adapted_vector or finding.cvss_vector or 'no CVSS vector' }}`

{{ finding.description or 'No description provided.' }}

- Affected components: {{ finding.components | replace('\n', ', ') }}
- Detected by: {{ finding.tool or 'manual entry' }} ({{ finding.scan_type }})
- Published: {{ finding.cve_pub_date or '-' }}
- Age: {{ finding.age_days }} days, SLA {{ finding.sla_days }} days{% if finding.sla_overdue %} (overdue){% endif %}
{% if finding.mitigation %}
- Mitigation: {{ finding.mitigation }}
{% endif %}

{% endfor %}

## Remediation

{% if remediation %}
| Id | Component | Fixed in | Published | Schedule | Regression tests |
|---|---|---|---|---|---|
{% for finding in remediation %}
| {{ finding.ref }} | {{ finding.components | replace('\n', ', ') }} | {{ finding.patch.fixed_version }} | {{ finding.patch.patch_pub_date or '-' }} | {{ finding.patch.schedule or '-' }} | {{ finding.patch.regression_tests or '-' }} |
{% endfor %}

{% for finding in remediation %}
{% if finding.patch.functional_impact or finding.patch.operational_impact %}
**{{ finding.ref }}**
{% if finding.patch.functional_impact %}
Functional impact: {{ finding.patch.functional_impact }}
{% endif %}
{% if finding.patch.operational_impact %}
Operational impact: {{ finding.patch.operational_impact }}
{% endif %}
{% endif %}
{% endfor %}
{% else %}
No patches recorded for this scope.
{% endif %}

{% if accepted %}
## Accepted risks

| Id | Severity | Justification |
|---|---|---|
{% for finding in accepted %}
| {{ finding.ref }} | {{ finding.severity }} | {{ finding.mitigation }} |
{% endfor %}
{% endif %}
