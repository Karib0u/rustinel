# SIEM Demos

Rustinel writes alerts as ECS NDJSON in `logs/alerts.json.<date>`. That makes
the first SIEM trial a file shipping problem: run the agent, trigger the bundled
demo rule, then tail or import the alert file.

## Generate A Test Alert

Start Rustinel from an extracted release package:

=== "Linux"

    ```bash
    sudo ./rustinel run
    whoami
    cat logs/alerts.json.*
    ```

=== "Windows"

    ```powershell
    .\rustinel.exe run
    whoami /all
    Get-Content .\logs\alerts.json.*
    ```

=== "macOS"

    ```bash
    sudo ./rustinel run
    whoami
    cat logs/alerts.json.*
    ```

## Elastic

The demo in `examples/siem/elastic` starts Elasticsearch, Kibana, and Filebeat.
Filebeat tails Rustinel alert files and writes them into `rustinel-alerts-*`.

```bash
cd examples/siem/elastic
docker compose up -d elasticsearch kibana

export RUSTINEL_ALERTS_DIR=/path/to/rustinel/logs
docker compose up filebeat
```

Open Kibana at <http://localhost:5601>, create a data view for
`rustinel-alerts-*`, then search:

```text
event.kind : "alert"
```

Filebeat config used by the demo:

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

The demo in `examples/siem/splunk` starts a local Splunk Enterprise container
with HTTP Event Collector enabled, then sends each Rustinel alert line as one
HEC event.

```bash
cd examples/siem/splunk
docker compose up -d
python3 send-alerts.py /path/to/rustinel/logs/alerts.json.$(date +%Y-%m-%d)
```

Open Splunk Web at <http://localhost:8000> with:

```text
admin / ChangeMe123!
```

Search:

```text
index=main source=rustinel sourcetype=_json event.kind=alert
```

Default HEC endpoint and token:

```text
http://localhost:8088/services/collector/event
rustinel-demo-token
```

For a real deployment, create a dedicated index and HEC token, keep the token in
your secret manager, and run the sender or your log forwarder under your normal
host telemetry pipeline.

## Production Notes

- Keep `alerts.directory` on persistent storage.
- Use absolute paths in `config.toml` when Rustinel runs as a service.
- Keep operational logs and alert output separate in your SIEM.
- Start with the bundled `whoami` rule, then add your own Sigma, YARA, and IOC
  content once ingestion is confirmed.
