# NxtFireGuard Threat Feed Aggregator

The **NxtFireGuard Threat Feed Aggregator** forwards threat data to the NxtFireGuard threat collector. It runs two relays in Docker, and the NxtFireGuard dashboard switches each one on or off:

| Relay | Listens on | Forwards to |
|---|---|---|
| Cisco FTD (Firepower) syslog | UDP 514 | `/firepower` |
| Cisco ISE syslog | UDP 1025 | `/ise` |
| OPNsense Suricata EVE (syslog) | UDP 1026 | `/opnsense` |
| Suricata syslog | UDP 1027 | `/suricata` |
| pfSense Suricata EVE (syslog) | UDP 1028 | `/pfsense` |
| T-Pot (Logstash, reads T-Pot's Elasticsearch) | — | `/t-pot` |

The syslog relays run in one `nfg-syslog` container (syslog-ng). The T-Pot relay runs in an `nfg-logstash` container. That container joins T-Pot's `tpotce_nginx_local` Docker network, so it has to run on the T-Pot host. The OPNsense and pfSense relays forward only Suricata EVE JSON and drop every other line.

## Install

Download the archive for your platform from the releases page: `nfgtfa-linux-amd64.tar.gz`, `nfgtfa-linux-arm64.tar.gz`, `nfgtfa-darwin-amd64.tar.gz`, `nfgtfa-darwin-arm64.tar.gz` or `nfgtfa-windows-amd64.zip`.

```bash
tar -xf nfgtfa-linux-amd64.tar.gz
```

Requirements:

* Docker, running, with the `docker` CLI on `PATH`.
* The values from the NxtFireGuard dashboard: aggregator name, auth secret and heartbeat identifier.

## Configuration

The aggregator reads its settings from environment variables. If a `.env` file exists in the working directory, it is read too; real environment variables take precedence over it. See [`.env.example`](.env.example).

| Variable | Default | |
|---|---|---|
| `AGGREGATOR_NAME` | — | required |
| `AUTH_SECRET` | — | required |
| `HEARTBEAT_IDENTIFIER` | — | if empty, no heartbeats are sent |
| `HEARTBEAT_URL` | `https://heartbeat.nxtfireguard.de` | |
| `NFG_TFA_CONTROLLER_URL` | `https://controller.collector.nxtfireguard.de` | the update stream URL is derived from it (`https` becomes `wss`) |
| `NFG_TFA_CONTROLLER_HOST` | — | optional; replaces only the update stream's host |
| `THREAT_LOG_COLLECTOR_URL` | `https://threat.collector.nxtfireguard.de` | |
| `SKIP_VERIFY_TLS` | `false` | turns off certificate checks for the controller and the heartbeat |
| `NFG_STATE_DIR` | `./nfgtfa-state` | holds the generated configs and the last dashboard settings |
| `ELASTICSEARCH_TARGETS` | — | JSON list of `{"url","user","pass"}`, used only by the T-Pot relay; entries without `url` or `user` are skipped |
| `DEBUG` | `false` | turns on debug logging |

`LOG_TO_LOKI` and `LOKI_ADDRESS` are no longer used. Logs are written to stdout as JSON.

## Running

```bash
./nfgtfa-linux-amd64
```

On startup, and again after every reconnect of the update stream, the aggregator loads its settings from the controller. Pushes from the dashboard are applied immediately. A full resync also runs every hour. The last settings it received are saved in the state directory, so after a restart the relays come back even while the controller can't be reached.

Every minute the aggregator checks the containers:

* Containers the settings no longer ask for are removed.
* A container is recreated only when its configuration changed.
* A container is restarted if it stopped, if its Docker health check fails, or (for Logstash) if its recent logs show `UnknownHostException`. Repeated restarts wait 30 s, then twice as long each time, up to 10 minutes.
* A heartbeat is sent only when every container the settings ask for is running and healthy.

On `SIGINT`/`SIGTERM` the aggregator removes its containers.

Credentials are never written to disk or passed on a command line. The generated syslog-ng and Logstash configs reference environment variables (`NFG_AUTH_KEY`, `NFG_ES_PASS_<n>`). `docker run -e NAME` passes those variables to the containers from the aggregator's own environment.

Containers created by older versions (docker compose, `nfgtfa-*_default` networks) are cleaned up on the first start.

## Development

```bash
make test         # vet + unit tests with the race detector
make lint         # golangci-lint
make docker-test  # starts the real syslog-ng image (needs Docker)
```

The tests for the syslog-ng and Logstash config compare the output with the configs the previous implementation generated, for every combination of relays (`internal/render/testdata`).

| Package | |
|---|---|
| `cmd/aggregator` | wiring: settings sync, update stream, the reconcile loop, heartbeat |
| `internal/config` | environment variables; `Secret` never prints its value |
| `internal/services` | the table of syslog relays |
| `internal/render` | the syslog-ng and Logstash configs |
| `internal/nfg` | the controller API, the update stream and the heartbeat |
| `internal/docker` | container specs and the docker CLI |
| `internal/reconcile` | desired containers vs. running ones |
| `internal/state` | files in the state directory |

## License

This project is part of the **NxtFireGuard** suite developed by **NxtGenIT**. All rights reserved.
