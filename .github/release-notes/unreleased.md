## Upgrade notes

- **YARA severity and active response:** file and process-memory alerts use the first valid rule metadata value from `severity`, `level`, then `score`.
  Rules without recognized metadata default to `high` instead of `critical`, and active response uses the resulting alert severity.
  Deployments with `response.min_severity = "critical"` must add `severity = "critical"` to rules intended to trigger response, or lower the response threshold after reviewing their rules.
