# Xray Autoswitch Help

`xray_autoswitch.py` keeps one stable local SOCKS and HTTP proxy open while it
tests a list of unstable VLESS configs, connects to the fastest working one,
and switches again when the active config becomes unhealthy.

## Basic Usage

```bash
./xray_autoswitch.py -l vless_configs.txt
```

Default local proxy outputs:

```text
SOCKS: 127.0.0.1:10808
HTTP:  127.0.0.1:10809
```

The config list file must contain one `vless://...` link per line. Empty lines
and lines starting with `#` are ignored.

## How It Works

1. Reads VLESS links from the file passed with `-l`.
2. Starts temporary Xray instances on random local ports.
3. Sends a real HTTP(S) request through each candidate.
4. Measures real delay from the proxy request start to a successful response.
5. Selects the fastest working candidate.
6. Starts Xray on stable local SOCKS/HTTP ports.
7. Runs periodic health checks through the stable HTTP proxy.
8. If health checks fail enough times, it tests candidates again and switches.

By default, testing uses fast race mode: after the first working candidate is
found, the script waits only a short settle window for faster candidates instead
of waiting for every slow or dead config.

## Common Commands

Fast switching:

```bash
./xray_autoswitch.py -l vless_configs.txt \
  --check-interval 5 \
  --fail-threshold 1 \
  --health-retries 1 \
  --test-timeout 2
```

Balanced mode:

```bash
./xray_autoswitch.py -l vless_configs.txt \
  --check-interval 5 \
  --fail-threshold 2 \
  --health-retries 1 \
  --test-timeout 2
```

Faster initial testing:

```bash
./xray_autoswitch.py -l vless_configs.txt \
  --concurrency 12 \
  --probe-settle 0.4 \
  --test-timeout 2 \
  --warmup-timeout 2
```

Full scan, slower but more complete:

```bash
./xray_autoswitch.py -l vless_configs.txt --full-scan
```

Comprehensive colored logs:

```bash
./xray_autoswitch.py -l vless_configs.txt --log-mode comprehensive
```

Validate generated Xray configs without connecting:

```bash
./xray_autoswitch.py -l vless_configs.txt --config-test-only
```

## Parameters

### Config Input

`-l, --list`

Required. Path to the text file containing VLESS links.

Example:

```bash
-l vless_configs.txt
```

### Xray Binary

`--xray-bin`

Default: `xray`

Path or command name for the Xray binary. Use this if `xray` is not in `PATH`.

Example:

```bash
--xray-bin /usr/local/bin/xray
```

### Local Bind Address

`--bind`

Default: `127.0.0.1`

Address used for local proxy ports. Keep the default if only local apps should
connect. Use `0.0.0.0` only if other devices on your network must connect.

Example:

```bash
--bind 127.0.0.1
```

### SOCKS Port

`--socks-port`

Default: `10808`

Stable SOCKS proxy port exposed by the script.

Example:

```bash
--socks-port 10808
```

### HTTP Port

`--http-port`

Default: `10809`

Stable HTTP proxy port exposed by the script. Health checks also use this port
while a candidate is active.

Example:

```bash
--http-port 10809
```

### Log Mode

`--log-mode`

Default: `minimal`

Allowed values:

```text
minimal
comprehensive
```

`minimal` shows candidate tests, selected config, health failures, and retest
events. It hides traffic logs.

`comprehensive` shows colored logs for tests, selection, health checks, retests,
and Xray traffic. Traffic lines include the active config name.

Example:

```bash
--log-mode comprehensive
```

### Disable Colors

`--no-color`

Default: disabled

Turns off ANSI colors in logs.

Example:

```bash
--no-color
```

### Test URL

`--test-url`

Default:

```text
https://www.gstatic.com/generate_204
https://cp.cloudflare.com/generate_204
```

URL used for real-delay tests and health checks. Can be repeated. The first
successful URL wins.

Example:

```bash
--test-url https://www.gstatic.com/generate_204 \
--test-url https://cp.cloudflare.com/generate_204
```

### Test Timeout

`--test-timeout`

Default: `2.5`

Timeout in seconds for each real HTTP(S) request through a candidate.

Lower values make switching faster but may mark slow configs as dead. Higher
values are more tolerant but slower.

Examples:

```bash
--test-timeout 2
--test-timeout 4
```

### Warmup Timeout

`--warmup-timeout`

Default: `2.5`

How long to wait for a temporary or active Xray instance to open its local port.

Lower values make testing faster. Increase this if Xray starts slowly on your
machine.

Examples:

```bash
--warmup-timeout 2
--warmup-timeout 5
```

### Health Check Interval

`--check-interval`

Default: `15.0`

Seconds between health check rounds while connected.

Switch delay is mostly controlled by:

```text
check-interval * fail-threshold
```

Example:

```bash
--check-interval 5
```

### Failure Threshold

`--fail-threshold`

Default: `3`

Number of failed health rounds required before retesting and switching.

Lower values switch faster. Higher values reduce false switching during short
network hiccups.

Examples:

```bash
--fail-threshold 1
--fail-threshold 2
--fail-threshold 3
```

### Health Retries

`--health-retries`

Default: `2`

Number of attempts inside each health check round.

If `health-retries` is greater than `1`, one bad request does not immediately
count as a failed health round.

Example:

```bash
--health-retries 1
```

### Health Retry Delay

`--health-retry-delay`

Default: `0.8`

Delay in seconds between attempts inside the same health check round.

Example:

```bash
--health-retry-delay 0.5
```

### Concurrency

`--concurrency`

Default: `8`

Number of candidates tested in parallel.

Higher values make initial testing faster, but they also start more temporary
Xray processes at the same time.

Examples:

```bash
--concurrency 8
--concurrency 12
--concurrency 20
```

### Probe Settle

`--probe-settle`

Default: `0.8`

In fast race mode, after the first working candidate is found, the script waits
this many more seconds for faster candidates before selecting.

Lower values connect sooner. Higher values may find a better candidate but take
longer.

Examples:

```bash
--probe-settle 0.3
--probe-settle 0.8
--probe-settle 1.5
```

### Full Scan

`--full-scan`

Default: disabled

Waits for every candidate to finish testing instead of using fast race mode.
This gives a more complete ranking but can be much slower with dead configs.

Example:

```bash
--full-scan
```

### Retry Interval

`--retry-interval`

Default: `10.0`

Seconds to wait before retesting when no live candidate is found, or when a
candidate fails to start.

Example:

```bash
--retry-interval 5
```

### Xray Log Level

`--xray-log-level`

Default:

```text
warning in minimal mode
info in comprehensive mode
```

Allowed values:

```text
debug
info
warning
error
none
```

Use `info` if you want Xray traffic lines in comprehensive mode. Use `warning`,
`error`, or `none` to reduce Xray output.

Example:

```bash
--xray-log-level info
```

### Config Test Only

`--config-test-only`

Default: disabled

Generates Xray JSON configs from the VLESS links and validates them with
`xray run -test`. It does not connect or run health checks.

Example:

```bash
./xray_autoswitch.py -l vless_configs.txt --config-test-only
```

## Recommended Presets

### Fastest Failover

Use this when configs are very unstable and fast switching matters more than
avoiding false switches.

```bash
./xray_autoswitch.py -l vless_configs.txt \
  --check-interval 3 \
  --fail-threshold 1 \
  --health-retries 1 \
  --test-timeout 1.5 \
  --warmup-timeout 2 \
  --concurrency 12 \
  --probe-settle 0.3
```

### Balanced Daily Use

Use this as a practical starting point.

```bash
./xray_autoswitch.py -l vless_configs.txt \
  --check-interval 5 \
  --fail-threshold 2 \
  --health-retries 1 \
  --test-timeout 2 \
  --warmup-timeout 2 \
  --concurrency 12 \
  --probe-settle 0.5
```

### Conservative Stability

Use this if brief network drops are common and you do not want frequent switches.

```bash
./xray_autoswitch.py -l vless_configs.txt \
  --check-interval 10 \
  --fail-threshold 3 \
  --health-retries 2 \
  --test-timeout 3 \
  --probe-settle 1
```

### Debug Traffic

Use this when you want to see tests, health checks, selected config, and traffic.

```bash
./xray_autoswitch.py -l vless_configs.txt \
  --log-mode comprehensive \
  --xray-log-level info
```

## Reading Logs

Minimal mode log categories:

```text
[TEST]    Candidate real-delay test result
[SELECT]  Selected and connected config
[HEALTH]  Health check failures
[RETEST]  Retest and failover events
[ERROR]   Invalid configs or startup errors
```

Comprehensive mode also includes:

```text
[TRAFFIC] Xray traffic line, prefixed with active config name
```

Example:

```text
[2026-05-16 03:52:15] [TEST] OK #9 VL_NF6_example 240 ms
[2026-05-16 03:52:16] [SELECT] Connected to #9 VL_NF6_example; SOCKS=127.0.0.1:10808, HTTP=127.0.0.1:10809
[2026-05-16 03:53:01] [HEALTH] Health check failed (1/2): timed out
[2026-05-16 03:53:06] [RETEST] Failure threshold reached; retesting candidates
```

## Failover Timing

Approximate failover time:

```text
(check-interval * fail-threshold)
+ health retry time
+ candidate testing time
+ Xray restart time
```

For example:

```bash
--check-interval 5 --fail-threshold 2 --health-retries 1
```

Usually detects failure in about 10 seconds, then starts retesting.

For faster detection:

```bash
--check-interval 3 --fail-threshold 1 --health-retries 1
```

For fewer false switches:

```bash
--check-interval 10 --fail-threshold 3 --health-retries 2
```

## Requirements

Required:

```text
Python 3
Xray core
```

macOS example:

```bash
brew install xray
```

Ubuntu example:

```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
```

Then verify:

```bash
xray version
python3 --version
```

## AI Assistance

This project was primarily generated and iterated using OpenAI Codex.
Human review, testing, and architecture decisions were applied throughout development.