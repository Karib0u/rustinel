# Elastic Demo

This demo starts a local Elasticsearch, Kibana, and Filebeat stack, then tails
Rustinel ECS NDJSON alerts from a host directory.

## Start Elastic

From this directory:

```bash
docker compose up -d elasticsearch kibana
```

Kibana will be available at <http://localhost:5601>.

## Ship Rustinel Alerts

Set `RUSTINEL_ALERTS_DIR` to the directory that contains `alerts.json.<date>`,
then start Filebeat:

```bash
export RUSTINEL_ALERTS_DIR=/path/to/rustinel/logs
docker compose up filebeat
```

Trigger the bundled demo rule in another terminal:

```bash
cd /path/to/rustinel
sudo ./rustinel run
whoami
```

Search in Kibana Discover:

```text
data view: rustinel-alerts-*
query: event.kind : "alert"
```

## Stop

```bash
docker compose down
```
