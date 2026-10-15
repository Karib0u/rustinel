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

Start Rustinel in one terminal:

```bash
cd /path/to/rustinel
sudo ./rustinel run
```

Trigger the bundled demo rule in a second terminal:

```bash
whoami
```

Send the generated alert file. The log folder is readable by root only, and
the file name carries the UTC date:

```bash
sudo python3 send-alerts.py /path/to/rustinel/logs/alerts.json.$(date -u +%Y-%m-%d)
```

Search in Splunk:

```text
index=main source=rustinel sourcetype=_json event.kind=alert
```

## Stop

```bash
docker compose down
```
