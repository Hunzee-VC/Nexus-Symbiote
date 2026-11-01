# Reference gateway admission benchmark

From a development checkout with the test dependencies installed, run

```sh
python -m tests.bench_admission --samples 200 --output admission-results.json
```

The harness uses the signed deployment fixture from the admission regression
suite, ephemeral Ed25519 keys, two independent SQLite databases and an in-memory
callback. Each request has a fixed expected outcome. The harness verifies the
signed receipt, exact intent, expected decision and callback count before adding
the measurement. A mismatch aborts the run. The output path must be new.

Durations cover the synchronous `dispatch_call` boundary, including SQLite and
the adapter's receipt handling. The harness's independent receipt check happens
after the timer. One process executes one call at a time. The output includes
raw monotonic nanoseconds and nearest-rank percentiles for repeated cases.
The committed sample is one local run. It excludes transport, upstream
authentication, backend I/O, concurrent workers and fleet policy distribution.

The connected gateway receives a new signed revocation bundle. Its next call
must deny, and a subsequent older bundle must also deny. The disconnected
gateway retains its old signed bundle. The test advances a simulated clock
and checks behavior before and after the operator's trust-age limit. In a
real deployment, provision the allowed age for each action class through
trusted configuration. The Python adapter accepts `max_trust_age`; the CLI
accepts `--max-trust-age-seconds`. Signed policy expiry can shorten either
window. Production revocation propagation requires timestamps from the
publisher and each deployed gateway.
