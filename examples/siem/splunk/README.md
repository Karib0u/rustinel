# Splunk Demo

This demo starts a local Splunk Enterprise container and sends Rustinel ECS
NDJSON alerts through HTTP Event Collector.

## Start Splunk

From this directory:

```bash
docker compose up -d
```

Splunk Web will be available at <http://localhost:8000>.

Default demo credentials:

```text
admin / ChangeMe123!
```

HEC listens on <http://localhost:8088> with token `rustinel-demo-token`.

## Send Rustinel Alerts

Trigger the bundled demo rule in one terminal:

```bash
cd /path/to/rustinel
sudo ./rustinel run
whoami
```

Send the generated alert file in another terminal:

```bash
python3 send-alerts.py /path/to/rustinel/logs/alerts.json.$(date +%Y-%m-%d)
```

Search in Splunk:

```text
index=main source=rustinel sourcetype=_json event.kind=alert
```

## Stop

```bash
docker compose down
```
