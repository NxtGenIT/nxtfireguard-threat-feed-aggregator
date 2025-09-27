# NxtFireGuard Threat Feed Aggregator

The **NxtFireGuard Threat Feed Aggregator (NFGTFA)** relays threat intelligence feeds to NxtFireGuard and currently supports Cisco Firepower, Cisco ISE and T-Pot.

---

## Download & Install

Download the prebuilt executable release for your platform:

* **Linux:** `nfgtfa-linux-amd64.tar.gz`
* **macOS:** `nfgtfa-darwin-amd64.tar.gz`
* **Windows:** `nfgtfa-windows-amd64.zip`

Extract the archive:

```bash
# Linux / macOS
tar -xf nfgtfa-linux-amd64.tar.gz
```

(Optional) Remove the archive after extraction:

```bash
rm nfgtfa-linux-amd64.tar.gz
```

For Windows, unzip the archive using the standard unzip tool or Explorer.

---

## Prerequisites

* Supported OS: **Linux, macOS, or Windows**
* **Docker** installed and running
* Access to **NxtFireGuard dashboard** to retrieve environment variables

---

## Configuration

Create a `.env` file in the same directory as the executable with the following variables:

```dotenv
DEBUG=false

AGGREGATOR_NAME=
AUTH_SECRET=

HEARTBEAT_IDENTIFIER=
HEARTBEAT_URL=https://heartbeat.nxtfireguard.de

NFG_TFA_CONTROLLER_URL=https://controller.collector.nxtfireguard.de
NFG_TFA_CONTROLLER_HOST=controller.collector.nxtfireguard.de
SKIP_VERIFY_TLS=false

LOG_TO_LOKI=true
LOKI_ADDRESS=https://loki.nxtfireguard.de

THREAT_LOG_COLLECTOR_URL=https://threat.collector.nxtfireguard.de

# Only required if "Run Logstash" is enabled in the NxtFireGuard dashboard
ELASTICSEARCH_TARGETS='[{"url":"http://es1:9200","user":"foo","pass":"bar"},{"url":"http://es2:9200","user":"baz","pass":"qux"}]'
```

> **Note:** Missing environment variable values can be obtained from your **NxtFireGuard dashboard**.

---

## Running the Aggregator

Run the executable:

```bash
./nfgtfa-linux-amd64
```

You may also manage the executable using a **systemd service** for automatic startup and monitoring.

---

## Notes

* The `ELASTICSEARCH_TARGETS` variable is **only required** if you enable **Run Logstash** in the NxtFireGuard dashboard.
* All other variables are required to connect to NxtFireGuard, send heartbeats, and forward logs to Loki if configured.

---

## Application Info

**Name:** NxtFireGuard Threat Feed Aggregator
**Purpose:** Forward threat intelligence feeds to NxtFireGuards Threat Collector.

---
