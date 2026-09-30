# Forward alerts

Rustinel writes one JSON alert per line to `alerts.json.<date>` in the alert directory.
Forward them with any shipper that tails NDJSON files, or have Rustinel POST each alert to a [webhook](#webhooks).
The fields are described in [Alert format](output.md).

The repository has runnable demos for Elastic and Splunk.
Generate a test alert first with the [Quickstart](getting-started.md).

## Elastic

`examples/siem/elastic` starts Elasticsearch, Kibana, and Filebeat:

```bash
cd examples/siem/elastic
docker compose up -d elasticsearch kibana
RUSTINEL_ALERTS_DIR=/path/to/rustinel/logs docker compose up filebeat
```

Open Kibana at <http://localhost:5601>, create a data view for `rustinel-alerts-*`, and search `event.kind : "alert"`.

The Filebeat input it uses:

```yaml
filebeat.inputs:
  - type: filestream
    paths:
      - /rustinel-logs/alerts.json.*
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
```

## Splunk

`examples/siem/splunk` starts Splunk with the HTTP Event Collector enabled and sends each alert as one event:

```bash
cd examples/siem/splunk
docker compose up -d
python3 send-alerts.py /path/to/rustinel/logs/alerts.json.$(date +%Y-%m-%d)
```

Open <http://localhost:8000> (user `admin`, password `ChangeMe123!`) and search:

```text
index=main source=rustinel sourcetype=_json event.kind=alert
```

The demo HEC token is `rustinel-demo-token`.
In production, create your own index and token and keep the token in a secret manager.

## Webhooks

Add one `[[alerts.webhook]]` table per endpoint, then restart Rustinel:

```toml
[[alerts.webhook]]
url = "https://collector.example/rustinel"
secret = "<shared secret>"
```

Each alert is sent as one JSON `POST`, signed with `secret`, and retried on failure.
The alert file is always written first, so a failing endpoint never loses an alert from it.
Options are in [Webhook destinations](configuration.md#webhook-destinations), and the request format and a receiver example in [Webhooks](output.md#webhooks).

## Production tips

- Keep the alert directory on persistent storage.
- Ship the operational log (`rustinel.log.<date>`) to a separate index from alerts.
- Repeated identical alerts are collapsed, see [Deduplication](detection.md#deduplication).
  Sum `event.count` to get true volumes.
- On Linux and macOS the log directory is readable by root only, so the shipper must run as root.
