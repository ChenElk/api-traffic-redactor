# API Traffic Redactor

Redacts sensitive data from API traffic logs in NDJSON format. Detection is
driven by a YAML rules file. It runs as a command-line tool or as an HTTP
service, processes input as a stream, and reports redactions counts per rule.

**Language.** The tool is written in Python rather than Go. Go is new to me, and
I preferred to submit code I can explain, defend and change.

## Setup, run and test

Requires Python 3.11 or later.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
```

### Command line

```
redactor [--rules rules.yaml] [input-file]
```

Reads NDJSON from `input-file`, or from stdin when no file is given.

Use `--rules PATH` to load a custom YAML rules file. If omitted, the tool
loads `rules.yaml` from the current working directory. The custom file must
follow the supported rules format.

```bash
redactor --rules rules.yaml input.ndjson > output.ndjson
cat input.ndjson | redactor --rules rules.yaml
redactor --rules configs/production.yaml input.ndjson > output.ndjson

```

- **stdout** carries the redacted records and nothing else.
- **stderr** carries one summary after the last record: line counts, replaced
  records per reason, and redactions per rule. It never contains record contents.

```
redactor: 50 lines: 45 processed, 2 blank, 3 replaced (invalid_json: 3)
redactor: redactions by rule:
  auth-headers        9
  ...
```

| Exit code | Meaning |
|---|---|
| 0 | Every record was processed. |
| 1 | I/O failure: unreadable input file, or the reader closed the pipe. |
| 2 | Invalid arguments, or the rules file could not be loaded or validated Nothing is written to stdout. |
| 3 | Finished, but at least one record was replaced by a placeholder. |

### Service mode

```
redactor --serve [--addr HOST:PORT] [--rules rules.yaml]
```
By default, the service listens on 0.0.0.0:8080. Use --addr 127.0.0.1:8080 to accept local connections only.
The rules are loaded
and validated before the port is opened.

| Endpoint | What it does |
|---|---|
| `POST /redact` | NDJSON in, redacted NDJSON out, streamed in both directions. |
| `GET /healthz` | `200 {"status":"ok"}` while the service is up. |

```bash
redactor --serve --addr 127.0.0.1:8080 --rules rules.yaml

curl -s http://127.0.0.1:8080/healthz
curl -s -X POST --data-binary @input.ndjson http://127.0.0.1:8080/redact > output.ndjson
```

- **Health endpoint.** `GET /healthz` returns `200 {"status":"ok"}` when the
  service is responsive. Rules are validated at startup; the service does not
  start if validation fails. No external dependency checks are needed.
- **Response.** POST /redact streams an application/x-ndjson response with status 200. Each input line produces one output line; records that cannot be safely processed are replaced by placeholders.
- **Rules cannot be loaded:** the process exits with code 2 and never opens
  the port. There is no state in which it accepts traffic without rules.
- **Logging:** one summary line per /redact request on stderr, containing counts and fixed diagnostic labels, never record contents.

## Docker

Build the image from the project root:

```bash
docker build -t api-traffic-redactor:dev .
```

Start the HTTP service on port 8080. Run the HTTP examples above in a separate
terminal; press Ctrl+C to stop the container.

```bash
docker run --rm -p 8080:8080 api-traffic-redactor:dev
```

Alternatively, process a local file in CLI mode (Bash syntax):

```bash
docker run --rm -i api-traffic-redactor:dev --rules /etc/redactor/rules.yaml < input.ndjson > output.ndjson
```

This uses the rules bundled in the image. The input and output files remain
on the host; their contents pass through stdin and stdout. The summary is
written to stderr. `--rm` removes the container when it exits, but keeps the image.

## Design decisions and trade-offs

The code is split by responsibility: `rules.py` loads and validates the rules,
`actions.py` holds the four actions, `engine.py` redacts one record,
`stream.py` turns bytes into records, and `cli.py` and `server.py` handle command-line and HTTP input/output without implementing redaction logic.

### Rule loading: fail closed

The rules are loaded and every regex compiled once, before any input is read.
Anything the loader does not fully understand rejects the whole file (exit 2):
an unknown field (`actoin: mask`), action, scope or validator; an invalid
regex or a value-rule pattern that matches the empty string; duplicate rule names; a key
written twice in one YAML mapping; or a file with no rules at all.

*Why:* a typo that silently disables a rule can leak sensitive data with no visible error.

### Rule matching

| Decision | Why | Cost |
|---|---|---|
| `exact` names match case-insensitively | HTTP header names are case-insensitive; the sample has `authorization` and `AUTHORIZATION`. | A body key that differs only in case is matched too. |
| When multiple key rules match the same key in the same scope, the strictest action wins (`remove` > `mask` > `hash` > `partial`); ties are resolved by YAML file order | Uses the same action priority as overlapping value rules. | Rule order matters only when matching key rules have the same strictness. |
| A key rule owns everything under its key; value rules are not consulted there | A matching key rule determines how the entire value is redacted; value rules are not applied within it. | |
| Scopes: keys of `headers` and `response.headers` are `headers`; every other name, at any depth (including form fields and query parameters), is `body` | The record layout is the only schema the engine knows, so it stays generic. | A `headers` object inside a body is body scope. |
| Value rules scan strings only, never JSON numbers | Turning numbers into masked strings breaks the schema. | A card stored as a JSON number is not found. |
\| Patterns compiled with `re.ASCII` | Ensures `\b` uses ASCII-based word boundaries and `\d` matches ASCII digits. This allows card numbers adjacent to non-ASCII text, such as `カード4012888888881881です`, to be detected. |
| Overlapping value matches are merged and the strictest action is applied once (`remove` > `mask` > `hash` > `partial`) | Text matched by any rule is never left readable because another rule won the overlap: `sk_live_abc@example.com` becomes one `****`. | The merged range is counted under one rule only. |

The four supported actions are mask, partial, hash and remove. `partial` hides a value of 4 characters or fewer
completely, since keeping "the last 4" of `1234` would redact nothing. For `hash`, see [Hashing and idempotency](#hashing-and-idempotency).

For `mask`, `partial` and `hash`, a key rule applied to a nested object or
array preserves its structure and redacts the string and number values inside
it. 

For example, a `mask` key rule matching `password` transforms:

```json
{"password":{"first":"abc","attempts":123,"history":["old","older"]}}
```

into:

```json
{"password":{"first":"****","attempts":"****","history":["****","****"]}}
```

Key names and array structure are preserved; the number `123` becomes the
string `"****"`.

Values such as `null`, `true`, `false` and empty strings remain unchanged. A `remove`
key rule drops the entire key, including any nested content.


### Recursion and embedded content

- **Parsing.** The standard `json` module with two hooks: an object becomes a
  list of `(key, value)` pairs and a number keeps its original text. A plain
  `loads`/`dumps` round trip would turn `10.50` into `10.5`, `1e3` into
  `1000.0`, and drop one value of a duplicated key.
- **One recursive walk** applies the rules and writes the output. If no redaction is needed, the original record text is preserved.
- **Structure inside strings.** Key rules need structure, so a string is first
  checked for embedded JSON (`"{\"token\":\"abc\"}"`) and for form/query
  syntax (`email=a%40b.com&password=x`). Both are redacted with the same rules.
  Embedded JSON is processed recursively. Otherwise, the engine attempts form/query parsing and then applies value rules to the resulting text.
- **Nesting limit.** Strings are decoded at most five layers deep, which limits repeated decoding within a record. Structure beyond that is refused (`too_deep`).
- **Broken JSON in a string.** Text such as `{"password":"hunter2"` cannot be
  parsed, and no value rule recognises `hunter2`. If unparseable text that
  starts with `{` or `[` shows a quoted key that a key rule targets, the record
  is refused (`invalid_embedded_json`); otherwise it is plain text such as
  `[INFO] started`(value rules still scan this text and redact matches without
  requiring valid JSON). *Trade-off:* a record with a truncated body that names a
  sensitive field is replaced by a placeholder, instead of leaking it.

### Streaming

- **One output line per input line, in order.** Output line N belongs to input
  line N, so any loss is visible and placeholders point at the right line.
  Blank lines stay blank.
- **Memory** does not grow with the input. The stream buffers at most one incomplete line, up to
  1 MiB by default; a longer line is discarded as it
  arrives, and replaced by a placeholder. Input is read in 64 KiB chunks and each result is written before the
  next read.
Processing a single record requires additional memory for the parsed JSON and
redacted output. Both CLI and HTTP modes use a fixed 1 MiB line limit; lines
exceeding it are replaced by placeholders. This limit is not configurable
through the command line.
- **Time.** The stream does constant work per byte. Overall time also depends
  on the number of rules and on how their regexes behave on the data, so it is
  not linear by construction (see "Known limitations"). 

### Failure handling

A line that cannot be processed is **replaced** by a valid JSON record built
only from its line number and a fixed reason code:

```json
{"redactor_error":"invalid_json","line":20}
```

- *Not passed through:* a truncated line can cut a secret in half.
- *Not dropped:* the record would disappear silently and later line numbers
  would shift.
- *Not echoed:* nothing from the line reaches stdout or stderr. Python exception
  messages are not printed either, since they often quote the offending value.

Reason codes: `invalid_json`, `invalid_embedded_json`, `too_deep`,
`invalid_utf8`, `line_too_long`, `internal_error`. Unexpected exceptions during record processing also produce placeholders, allowing subsequent lines to be processed. Replaced
records are counted in the summary. In CLI mode, exit code 3 indicates that at
least one record was replaced. In HTTP mode, replacements are reported through
placeholders in the response and counts in the request log summary; there is
no per-request process exit code. Running the tool on its own output returns 0, since placeholders are
valid records.

### The HTTP service

`server.py` moves bytes between the network and the
same stream object the command line uses.

| Decision | Why | Cost |
|---|---|---|
| FastAPI and uvicorn rather than `http.server` | uvicorn handles chunked bodies, malformed requests, keep-alive and orderly shutdown; with `http.server` that HTTP parsing would be hand-written. | Additional dependencies and asynchronous code. |
| A new `Redactor` and stream per request; only the read-only rules are shared | One client's partial line, line numbers and counters cannot reach another client. | |
| Read a piece, redact at most 64 KiB, send the output | The body is never buffered whole, in either direction. | Clients must read the response while uploading the request body to avoid stalling on large inputs. |
| A custom response class instead of `StreamingResponse` | Avoids competing reads from the ASGI `receive` channel while processing the request body and streaming the redacted response. | Uses the ASGI `receive`/`send` channels directly. |
| uvicorn's access log off | It prints the URL, and a query string can hold a secret. | No per-request URL in the log. |
| A small uvicorn override (`_HttpProtocol`) | Closes the connection if sending a 400 response fails; see malformed HTTP handling below. | Overrides a library method; covered by integration tests. |

**Malformed HTTP requests.** Before the response starts, malformed HTTP
requests receive `400 Bad Request`. If malformed HTTP framing is detected
after streaming has started, the status cannot be changed. A small
`_HttpProtocol` override closes the connection if uvicorn's attempt to send
a 400 response fails. The client therefore receives an incomplete response
rather than a normally completed stream. Invalid NDJSON records are handled
separately using placeholders.

### Hashing and idempotency

`mask`, `partial` and `remove` give the same result on their own output. `hash`
does not: a key rule matches the key *name*, so on a second run it fires again
on `X-Api-Key` and would hash the hash. A bare SHA-256 digest cannot be
recognised safely, because an ordinary API key can also be 64 hex characters.

**Decision:** two output forms, chosen by the kind of rule.

- **Key rule:** `sha256:<64 hex>`. A value already in exactly this form is left
  as is.
- **Value rule:** the bare digest, as the brief words it. A digest no longer
    looks like an e-mail address, so the rule does not fire again and nothing has
    to be recognised. This holds for the current e-mail rule; custom value-rule
    patterns may match a digest, so idempotency must be checked when changing
    the rules.

*Trade-off:* the tagged form deviates from the brief's wording for key rules.

## The JWT report

**Cause.** The provided pattern describes JWT parts with the standard base64
alphabet (`+`, `/`, `=`). JWTs use *base64url* without padding (RFC 7515):
`-` and `_` instead of `+` and `/`. Only tokens whose bytes happen to produce
`-` or `_` were affected, which is why *some* JWTs were missed. It failed in two
ways:

| Where the `-` or `_` is | Result with the provided pattern | Sample lines |
|---|---|---|
| header or payload | no match, the whole token stayed readable | 11, 16 |
| signature | matched only up to that character, the tail stayed: `****_adQssw5c` | 15 |

The second case looks redacted and is easy to miss.

**Fix.** One line in `rules.yaml`;

```
before: eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]*
after:  eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*
```

**Result.** The rule fires 4 times instead of 2 on the sample, and no `eyJ` is
left in the output. Regression tests in `tests/test_detection_patterns.py`
 cover `-` and `_` in each part, tokens in
headers, cookies, query strings, free text and nested JSON, unsigned tokens
(empty signature), look-alikes that must stay, and a second run.

### Related fix: card numbers

The provided pattern `\b\d{13,19}\b` missed cards written in groups, including
the brief's own example `4111 1111 1111 1111` (sample lines 1, 6, 36, 44).

**Principle: structure and Luhn must both agree.** The configured patterns
identify candidate numbers in the supported layouts below. A candidate is
redacted only if it also passes the Luhn checksum. Luhn does not establish
whether a number belongs to an issued or active card.

Accepted layouts, groups separated by one space or hyphen:

| Layout | Example |
|---|---|
| 13–19 digits, no separators | `4111111111111111` |
| 4-4-4-4 (Visa, Mastercard, Discover) | `4111 1111 1111 1111` |
| 4-6-5 (American Express) | `3782 822463 10005` |
| 4-6-4 (Diners Club) | `3056 930902 5904` |
| 4-4-4-4-3 (19 digits) | `6304 0000 0000 0000 000` |

The 19-digit layout is a separate rule because `4111 1111 1111 1111 123` can be
a 19-digit card or a 16-digit card followed by a CVV. Both readings are checked
with Luhn and the engine merges valid overlapping matches found by the rules.
The engine cannot distinguish a card's digits from adjacent CVV digits by
meaning: if the combined number matches a supported layout and passes Luhn,
those adjacent digits can be included in the redaction.

**Idempotency.** `partial` keeps the last four digits. When a card is written in groups and its last group also
starts another valid card, both candidates are found on the first run and merged into one redaction, so a second
run changes nothing:

```
input   4111 1111 1111 1111 3129 3741 1406
run 1   ******************************1406
run 2   ******************************1406
```

One exception remains. When the kept four digits are not a group of their own in the input (a card written without
separators, or an American Express number, whose last group has five digits), there is no word boundary in front of
them until the digits before them are masked, so the candidate they begin is only found on the second run, and one
such input in ten changes again:

```
input   4111111111111111 2222 3333 0004
run 1   ************1111 2222 3333 0004
run 2   ***************************0004
```

In this example, the second run masks additional digits, and subsequent runs leave the output unchanged. A guard
that skips digits right after `*` would fix this, but it would also leave a
real card readable when the input happens to look like that. Such a guard is not used because it could allow sensitive data to pass through unredacted.

Non-card identifiers can also match these layouts and pass Luhn, causing false positives. This can remove useful non-sensitive information from the logs.

## Deployment notes

### Dockerfile
The Dockerfile uses a two-stage build with python:3.14-slim and runs the application as a non-root user. It includes a default rules file at /etc/redactor/rules.yaml and starts in HTTP service mode. Health checks are configured in the Kubernetes manifest through /healthz.

**Docker validation performed:** image build, container startup, a successful
`/healthz` check, and password masking through `POST /redact`. 

### Kubernetes manifests

The `k8s/redactor.yaml` manifest contains a Deployment and a ClusterIP Service.

The Deployment runs one replica of the redactor on port 8080. A readiness probe checks /healthz; the Service routes traffic only to ready Pods. The Service provides a stable internal endpoint.

The manifest uses the rules file already packaged in the Docker image. Before deployment, the image must be available to the cluster nodes, either through a container registry or by loading it directly.

The manifest has not been tested on a running Kubernetes cluster.

## Known limitations and what I would do with more time

**Detection**
- **Regex backtracking.** The provided e-mail pattern is quadratic on a long run
  of letters; the JWT pattern is
  quadratic on repeated `eyJ`. *Next:* bound the e-mail parts to the limits of
  the standard, and add a length limit or boundary guard to the JWT pattern.
- **Key-based detection in free text.** Key rules apply to parsed JSON keys and
  form/query field names, not arbitrary field-like text within sentences.
  Sensitive values in free text are redacted only when they match a value rule.
  For example, `login attempt password=hunter2 for user=zed` (sample line 41)
  is not redacted: whitespace prevents form parsing, and `hunter2` does not
  match any configured value rule.

**Hashing**
- Unsalted SHA-256 is pseudonymisation, not anonymisation: guessable values
  such as e-mail addresses can be recovered by hashing candidates. *Next:*
  HMAC-SHA-256 with a key stored outside the logs.
- The `sha256:` tag is not authenticated: a value already in that form passes a
  `hash` key rule unchanged.
- Value-rule digests stay stable only while no value pattern matches hex
  digests (for example an unanchored `\d{13,19}`). The tests check this for
  the provided rules; a new rules file needs the same check.

**Service**
- Long-running regex searches can delay concurrent requests, including health checks. Process isolation is a possible future improvement.

**Resources**
Memory usage depends on record size, parsed structure and concurrent requests.
The fixed 1 MiB line limit does not cap total process memory; deployment memory
limits should account for parsing overhead and concurrent requests.

## Sub-millisecond inline processing

If this tool had to run inline on live production traffic with a sub-millisecond latency budget, I would first focus on reducing the cost of rule matching, especially the value-rule regex searches, which can become a performance bottleneck.

I would introduce safe pre-filtering to avoid unnecessary regex searches. For example, an email regex does not need to run on a string that contains no @ character. I would also optimize patterns that cause excessive backtracking, while verifying that these changes do not reduce sensitive-data detection.

Finally, I would define input-size limits and a fail-closed policy for requests that cannot be inspected within the required time budget, rather than allowing uninspected data through. A sub-millisecond target may be achievable for bounded workloads, but cannot be guaranteed for arbitrarily large or complex requests.
