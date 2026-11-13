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
| `AUTH_SECRET` | — | required. The syslog relays cannot use a secret containing `"`, `\`, a backtick or a line break |
| `HEARTBEAT_IDENTIFIER` | — | if empty, no heartbeats are sent |
| `HEARTBEAT_URL` | `https://heartbeat.nxtfireguard.de` | |
| `NFG_TFA_CONTROLLER_URL` | `https://controller.collector.nxtfireguard.de` | the update stream URL is derived from it (`https` becomes `wss`) |
| `NFG_TFA_CONTROLLER_HOST` | — | optional; replaces only the update stream's host |
| `THREAT_LOG_COLLECTOR_URL` | `https://threat.collector.nxtfireguard.de` | |
| `SKIP_VERIFY_TLS` | `false` | turns off certificate checks for the controller and the heartbeat |
| `NFG_STATE_DIR` | `./nfgtfa-state` | holds the generated configs and the last dashboard settings. The configs are bind-mounted into the containers, so on macOS the directory must be inside a folder the Docker VM shares (colima and Docker Desktop share only your home directory by default) |
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
* A container is restarted if it stopped, if its Docker health check fails, or (for Logstash) if its recent logs show `UnknownHostException`. Repeated restarts wait 30 s, then twice as long each time, up to 10 minutes. The wait goes back to zero only after the container has stayed healthy for 10 minutes, so a container that crashes shortly after every start keeps backing off.
* syslog-ng's health check is `syslog-ng-ctl stats`; it fails if syslog-ng did not accept its config. syslog-ng's own messages are in `docker logs nfg-syslog`; they are no longer sent to the collector.
* Every docker call has a time limit (2 minutes, 15 for `docker run`, which may pull the image). A hung Docker daemon shows up as a `timed out` problem in the log and stops heartbeats, instead of freezing the aggregator.
* A heartbeat is sent only when every container the settings ask for is running and healthy.

On `SIGINT`/`SIGTERM` the aggregator removes its containers.

Credentials are never written to disk or passed on a command line. The generated syslog-ng and Logstash configs reference environment variables (`NFG_AUTH_KEY`, `NFG_ES_PASS_<n>`). `docker run -e NAME` passes those variables to the containers from the aggregator's own environment.

Containers created by older versions (docker compose) are removed on the first check, then their `nfgtfa-*_default` networks. If Docker is unavailable then, the cleanup is retried on every check until it succeeds, and heartbeats wait for it.

## Development

```bash
make test         # vet + unit tests with the race detector
make lint         # golangci-lint
make docker-test  # starts the real syslog-ng image (needs Docker)
make e2e          # end-to-end tests (needs Docker on Linux), see Testing
```

The tests for the syslog-ng and Logstash config compare the output with the configs the previous implementation generated (minus its `internal()` sources), for every combination of relays (`internal/render/testdata`).

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

## Testing

| Suite | Command | Needs | What it covers |
|---|---|---|---|
| unit | `make test` | Go | every package, with fakes for docker and the backend |
| docker | `make docker-test` | Docker | the real syslog-ng image accepts the generated config and its health check passes |
| end-to-end | `make e2e` | Docker, Linux | the real binary end to end, see below |

The end-to-end tests (`e2e/`, build tag `e2e`) build `nfgtfa` and run it against a fake NxtFireGuard backend: one HTTP server playing the tfa-controller (`/sync/config` and the `/sync/ws/updates` stream), the heartbeat monitor (`/ping/<id>`) and the threat collector. It records every request and can script failures. Everything else is real: the docker daemon, the syslog-ng, Logstash and Elasticsearch images, UDP syslog sent to the published ports, and the HTTP requests syslog-ng and Logstash make. Containers reach the fake through the docker bridge gateway, which is why the suite needs Linux. The binary is built with `-X main.checkEveryOverride=2s`, so the check loop runs every 2 s instead of every minute.

| Test | Checks |
|---|---|
| `TestColdStart` | settings sync with credentials, all relays and ports, heartbeat only after the container started, each relay's route, headers and body, the OPNsense/pfSense EVE-only filter, the docker health check |
| `TestSettingsPushed` | pushes over the update stream: unchanged settings keep the container, a changed set recreates it, disabling removes it |
| `TestControllerOutage` | relays and heartbeats continue while the controller is down; on reconnect the settings changed meanwhile are applied without a push |
| `TestRestartWithoutController` | after a crash the aggregator starts from its saved settings without the controller and keeps the running container |
| `TestContainerRecovery` | a stopped container is restarted; a second stop backs off 30 s with heartbeats paused |
| `TestCollectorErrors` | the collector's 5xx and 429 are retried until accepted, a 400 is dropped once and does not hold up later messages |
| `TestShutdown` | SIGTERM removes the containers and exits 0 |
| `TestUnsafeSecret` | a secret syslog-ng cannot carry starts nothing and sends no heartbeat |
| `TestUpgradeFromV1` | a real v1.0.9 killed mid-run (its compose container and network left behind) is replaced cleanly; set `NFGTFA_V1_BINARY` to the old binary, otherwise skipped |
| `TestTPot` | without T-Pot's network the problem is reported and no heartbeat is sent; with the network and an Elasticsearch on it, Logstash forwards new documents to `/t-pot` |

CI runs them on every pull request and nightly, as two parallel jobs (`syslog` and `tpot`). The tests remove the `nfg-syslog` and `nfg-logstash` containers and the `tpotce_nginx_local` network, so do not run them on a host that runs a real aggregator or T-Pot.

## License

This project is part of the **NxtFireGuard** suite developed by **NxtGenIT**. All rights reserved.
