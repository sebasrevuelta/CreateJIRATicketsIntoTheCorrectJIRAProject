# Semgrep → JIRA Ticket Automation

This project contains a Python script that automatically creates JIRA tickets from **Semgrep findings** for a subset of repositories inside a Semgrep deployment.

The script performs the following workflow:

1. Retrieves all projects from a Semgrep deployment.
2. Filters only projects whose name starts with a specific prefix (e.g. `sebasrevuelta/`).
3. Retrieves findings for each filtered project.
4. Selects only **High** and **Critical** severity findings.
5. Creates JIRA tickets through the Semgrep Tickets API.
6. Uses a CSV file to map **JIRA project names → JIRA project IDs**.

---

## Requirements

- Python **3.9+**
- `pip`
- A Semgrep API token
- Access to the Semgrep deployment APIs
- A CSV file with JIRA project mappings

### Python Dependencies

```bash
pip install requests
```

---

## Environment Variables

You must define the following environment variables before running the script:

| Variable | Description |
|--------|-------------|
| `SEMGREP_TOKEN` | Semgrep API token |
| `DEPLOYMENT_SLUG` | Your Semgrep deployment slug |
| `SEMGREP_BASE_URL` | (Optional) Defaults to `https://semgrep.dev` |

Example:

```bash
export SEMGREP_TOKEN="xxxxx"
export DEPLOYMENT_SLUG="my-deployment"
```

---

## Configuration (Top of Script)

The script contains configurable constants at the top:

| Constant | Description |
|---------|-------------|
| `PROJECT_PREFIX` | Repository prefix filter, e.g. `sebasrevuelta/` |
| `TARGET_SEVERITIES` | Severities that trigger tickets (`high`, `critical`) |
| `JIRA_MAPPING_CSV_PATH` | Path to CSV mapping file |
| `DRY_RUN` | If `True`, no tickets are created |
| `GROUP_ISSUES` | Group multiple findings into a single ticket |
| `TICKET_LIMIT` | Maximum findings per ticket |

---

## JIRA Mapping CSV

The script needs a CSV file to map **JIRA project names → JIRA project IDs**.

### Example `jira_project_mapping.csv`

```csv
jira_project_name,jira_project_id
pb-core,12345
platform,23456
security,34567
```

---

## How JIRA Project Name is Derived

Given a Semgrep project name like:

```
sebasrevuelta/pb-core/ddex-team/clo-holdings-service
```

The script extracts the **JIRA project name** as:

```
pb-core
```

It always takes the segment **after the first slash**.

---

## Running the Script

```bash
python semgrep_to_jira.py
```

---

## Dry Run Mode

Enable dry run to test without creating tickets:

```python
DRY_RUN = True
```

This will log actions without sending POST requests.

---

## Ticket Creation Logic

Tickets are created when:

- Finding severity is **High** or **Critical**
- A valid JIRA project ID exists
- The finding has a valid issue ID
- The repository matches the prefix filter

Tickets are **grouped** by:

- Severity
- Rule ID
- Issue Type
- Confidence

This avoids excessive JIRA noise.

---

## API Endpoints Used

### List Projects
```
GET /api/v1/deployments/{deploymentSlug}/projects
```

### List Findings
```
GET /api/v1/deployments/{deploymentSlug}/findings?repos=<repo_name>
```

### Create Tickets
```
POST /api/v1/deployments/{deploymentSlug}/tickets
```

---

## Best Practices

- Use grouping to avoid creating hundreds of tickets.
- Avoid populating ticket fields with guessed data.
- Keep CSV mappings updated.
- Use `DRY_RUN` in CI tests.
- Consider adding deduplication logic if running frequently.

---

## Common Pitfalls

| Problem | Cause |
|--------|------|
| No tickets created | Missing JIRA mapping |
| Too many tickets | Grouping disabled |
| API errors | Invalid token or slug |
| Wrong JIRA project | Incorrect repo naming |

---

## Future Improvements Ideas

- Persistent state file to avoid duplicate tickets
- Slack/Email notifications
- Ticket update instead of create
- Dependency reachability analysis
- Severity escalation rules

---

## Summary

This automation bridges Semgrep security findings with JIRA workflows by:

- Filtering repositories
- Selecting critical findings
- Mapping projects correctly
- Creating structured tickets automatically

It reduces manual triage effort while maintaining control and accuracy.
