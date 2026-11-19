# Differential results: origin/main, PR 255 (credential_exposure), PR 259 (literal_credential)

- main: `/home/user/wt/coord-cred-main/src/nexus_symbiote/__init__.py`, 1437 cases
- pr255: `/home/user/wt/coord-cred-pr255/src/nexus_symbiote/__init__.py`, 1437 cases
- pr259: `/home/user/wt/credential-findings/src/nexus_symbiote/__init__.py`, 1437 cases
- corpus: 1437 cases, 476 labelled credential, 961 labelled benign

| origin | credential | benign |
| --- | --- | --- |
| files | 43 | 21 |
| matrix | 143 | 148 |
| own | 67 | 114 |
| r259 | 126 | 491 |
| t255 | 34 | 32 |
| t259 | 63 | 155 |

Credential findings on main: 0 cases.
Severities of the credential findings on pr255: {'high': 1006}; findings per flagged case: {1: 1006}.
Severities of the credential findings on pr259: {'high': 554}; findings per flagged case: {1: 554}.

## Cases a tree did not inventory (scan failure)

| case | origin | label | shape | position | main | pr255 | pr259 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| c1389 | files | benign | ref-client | gemini_server_command | .gemini/settings.json: MCP server command 'mcp' is not ... inventoried | .gemini/settings.json: MCP server command 'mcp' is not ... inventoried | .gemini/settings.json: MCP server command 'mcp' is not ... inventoried |

1 cases.

## Labelled credentials, by shape

| group | cases | both | only 255 | only 259 | neither | 255 total | 259 total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| arg-embedded | 5 | 1 | 2 | 1 | 1 | 3 | 2 |
| arg-header-line | 10 | 8 | 2 | 0 | 0 | 10 | 8 |
| connection-string | 5 | 0 | 2 | 0 | 3 | 2 | 0 |
| cookie-session | 2 | 0 | 2 | 0 | 0 | 2 | 0 |
| inline-script | 10 | 8 | 1 | 0 | 1 | 9 | 8 |
| mixedcase-letters-value | 1 | 1 | 0 | 0 | 0 | 1 | 1 |
| passphrase-words | 4 | 2 | 2 | 0 | 0 | 4 | 2 |
| password-non-ascii | 1 | 1 | 0 | 0 | 0 | 1 | 1 |
| password-punctuation | 18 | 10 | 5 | 3 | 0 | 15 | 13 |
| password-short | 15 | 10 | 0 | 3 | 2 | 10 | 13 |
| password-uppercase-underscore | 2 | 0 | 1 | 0 | 1 | 1 | 0 |
| password-wordy | 48 | 42 | 0 | 6 | 0 | 42 | 48 |
| private-key | 13 | 2 | 2 | 6 | 3 | 4 | 8 |
| random-starts-with-slash | 1 | 0 | 1 | 0 | 0 | 1 | 0 |
| random-under-credential-name | 107 | 88 | 3 | 12 | 4 | 91 | 100 |
| random-under-key-like-name | 13 | 4 | 8 | 0 | 1 | 12 | 4 |
| random-unmarked-position | 3 | 0 | 0 | 0 | 3 | 0 | 0 |
| random-with-chance-mark | 1 | 0 | 1 | 0 | 0 | 1 | 0 |
| scheme-authorization-variant | 13 | 13 | 0 | 0 | 0 | 13 | 13 |
| scheme-basic | 7 | 6 | 1 | 0 | 0 | 7 | 6 |
| scheme-bearer | 23 | 16 | 7 | 0 | 0 | 23 | 16 |
| scheme-other | 3 | 3 | 0 | 0 | 0 | 3 | 3 |
| sentinel-uppercase-name | 18 | 0 | 15 | 0 | 3 | 15 | 0 |
| synthetic-colon-chain | 3 | 3 | 0 | 0 | 0 | 3 | 3 |
| synthetic-repetitive | 2 | 0 | 2 | 0 | 0 | 2 | 0 |
| token-shaped-name | 2 | 0 | 2 | 0 | 0 | 2 | 0 |
| url-password | 16 | 5 | 0 | 7 | 4 | 5 | 12 |
| url-path-token | 3 | 0 | 0 | 1 | 2 | 0 | 1 |
| url-query-token | 16 | 2 | 0 | 9 | 5 | 2 | 11 |
| url-userinfo-user-only | 3 | 0 | 0 | 1 | 2 | 0 | 1 |
| user-colon-password | 5 | 5 | 0 | 0 | 0 | 5 | 5 |
| uuid-as-token | 15 | 12 | 0 | 3 | 0 | 12 | 15 |
| vendor-token | 87 | 74 | 0 | 12 | 1 | 74 | 86 |
| vendor-token-unlisted | 1 | 1 | 0 | 0 | 0 | 1 | 1 |
| **all** | **476** | **317** | **59** | **64** | **36** | **376** | **381** |

## Labelled credentials, by position

| group | cases | both | only 255 | only 259 | neither | 255 total | 259 total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Claude Code settings env | 6 | 0 | 0 | 6 | 0 | 0 | 6 |
| Gemini mcpServerCommand | 1 | 1 | 0 | 0 | 0 | 1 | 1 |
| URL fragment, matrix or path: endpoint field | 4 | 0 | 0 | 1 | 3 | 0 | 1 |
| URL query: argument | 12 | 11 | 1 | 0 | 0 | 12 | 11 |
| URL query: endpoint field | 23 | 0 | 0 | 19 | 4 | 0 | 19 |
| URL query: env value | 12 | 11 | 1 | 0 | 0 | 12 | 11 |
| URL user information: argument | 13 | 12 | 1 | 0 | 0 | 13 | 12 |
| URL user information: endpoint field | 21 | 0 | 0 | 15 | 6 | 0 | 15 |
| URL user information: env value | 14 | 12 | 1 | 0 | 1 | 13 | 12 |
| argument: --name VALUE | 27 | 22 | 3 | 1 | 1 | 25 | 23 |
| argument: --name=VALUE | 17 | 15 | 2 | 0 | 0 | 17 | 15 |
| argument: JSON text | 4 | 1 | 2 | 0 | 1 | 3 | 1 |
| argument: NAME=VALUE word | 22 | 16 | 2 | 4 | 0 | 18 | 20 |
| argument: header line | 12 | 11 | 1 | 0 | 0 | 12 | 11 |
| argument: other (embedded, positional, raw) | 7 | 3 | 0 | 1 | 3 | 3 | 4 |
| command field | 13 | 0 | 0 | 12 | 1 | 0 | 12 |
| env or header NAME | 2 | 0 | 2 | 0 | 0 | 2 | 0 |
| env value | 162 | 116 | 30 | 5 | 11 | 146 | 121 |
| header value | 71 | 62 | 9 | 0 | 0 | 71 | 62 |
| inline cmd or PowerShell script | 4 | 4 | 0 | 0 | 0 | 4 | 4 |
| inline sh -c script | 26 | 20 | 4 | 0 | 2 | 24 | 20 |
| oauth or auth object | 3 | 0 | 0 | 0 | 3 | 0 | 0 |
| **all** | **476** | **317** | **59** | **64** | **36** | **376** | **381** |

## Labelled credentials, by origin

| group | cases | both | only 255 | only 259 | neither | 255 total | 259 total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| files | 43 | 34 | 0 | 6 | 3 | 34 | 40 |
| matrix | 143 | 100 | 10 | 30 | 3 | 110 | 130 |
| own | 67 | 32 | 21 | 7 | 7 | 53 | 39 |
| r259 | 126 | 75 | 13 | 15 | 23 | 88 | 90 |
| t255 | 34 | 19 | 15 | 0 | 0 | 34 | 19 |
| t259 | 63 | 57 | 0 | 6 | 0 | 57 | 63 |
| **all** | **476** | **317** | **59** | **64** | **36** | **376** | **381** |

## Benign values, by shape

| group | cases | flagged by 255 | flagged by 259 | flagged by both | flagged by neither |
| --- | --- | --- | --- | --- | --- |
| colon-text-under-plain-name | 6 | 6 | 0 | 0 | 0 |
| default-word | 33 | 24 | 0 | 0 | 9 |
| env-name-only | 2 | 0 | 0 | 0 | 2 |
| explanatory-text | 29 | 28 | 24 | 23 | 0 |
| hash-not-secret | 3 | 1 | 0 | 0 | 2 |
| identifier-or-setting | 88 | 40 | 12 | 12 | 48 |
| image-digest | 10 | 4 | 4 | 4 | 6 |
| image-tag | 3 | 3 | 0 | 0 | 0 |
| inline-code-env-read | 7 | 7 | 5 | 5 | 0 |
| keyfile-path-abs | 48 | 44 | 0 | 0 | 4 |
| keyfile-path-rel | 50 | 48 | 32 | 31 | 1 |
| literal-plus-reference | 4 | 4 | 0 | 0 | 0 |
| locator-url | 28 | 0 | 3 | 0 | 25 |
| noncredential-name | 76 | 66 | 0 | 0 | 10 |
| package-requirement | 4 | 0 | 0 | 0 | 4 |
| partial-reference | 2 | 2 | 0 | 0 | 0 |
| passphrase-doc-example | 1 | 1 | 0 | 0 | 0 |
| placeholder-after-scheme | 30 | 29 | 10 | 10 | 1 |
| placeholder-marked | 117 | 90 | 4 | 4 | 27 |
| placeholder-phrase | 30 | 30 | 18 | 18 | 0 |
| placeholder-token-format | 39 | 36 | 11 | 11 | 3 |
| plain-launch | 7 | 0 | 0 | 0 | 7 |
| prose-with-scheme-word | 16 | 13 | 1 | 0 | 2 |
| public-material | 10 | 8 | 1 | 1 | 2 |
| random-under-noncredential-name | 17 | 10 | 0 | 0 | 7 |
| ref-client | 104 | 9 | 0 | 0 | 95 |
| ref-cmd-subst | 13 | 11 | 0 | 0 | 2 |
| ref-code | 11 | 11 | 8 | 8 | 0 |
| ref-in-url | 7 | 0 | 0 | 0 | 7 |
| ref-lowercase-or-empty | 3 | 0 | 0 | 0 | 3 |
| ref-secret-store | 50 | 36 | 21 | 21 | 14 |
| ref-shell-default | 5 | 1 | 0 | 0 | 4 |
| ref-template | 34 | 18 | 5 | 5 | 16 |
| ref-windows | 20 | 19 | 0 | 0 | 1 |
| secret-helper-command | 17 | 7 | 5 | 5 | 10 |
| short-word | 1 | 0 | 0 | 0 | 1 |
| var-name-as-value | 5 | 5 | 0 | 0 | 0 |
| weak-or-doc-password | 31 | 19 | 9 | 9 | 12 |
| **all** | **961** | **630** | **173** | **167** | **325** |

## Benign values, by position

| group | cases | flagged by 255 | flagged by 259 | flagged by both | flagged by neither |
| --- | --- | --- | --- | --- | --- |
| Claude Code settings env | 3 | 0 | 0 | 0 | 3 |
| Gemini mcpServerCommand | 1 | 0 | 0 | 0 | 1 |
| URL query: argument | 5 | 3 | 0 | 0 | 2 |
| URL query: endpoint field | 21 | 0 | 1 | 0 | 20 |
| URL query: env value | 5 | 3 | 0 | 0 | 2 |
| URL user information: argument | 11 | 4 | 1 | 1 | 7 |
| URL user information: endpoint field | 14 | 0 | 0 | 0 | 14 |
| URL user information: env value | 13 | 4 | 1 | 1 | 9 |
| another server field | 3 | 0 | 0 | 0 | 3 |
| argument: --name VALUE | 98 | 77 | 16 | 15 | 20 |
| argument: --name=VALUE | 30 | 22 | 3 | 3 | 8 |
| argument: JSON text | 2 | 1 | 0 | 0 | 1 |
| argument: NAME=VALUE word | 29 | 22 | 2 | 2 | 7 |
| argument: header line | 4 | 0 | 0 | 0 | 4 |
| argument: other (embedded, positional, raw) | 51 | 21 | 14 | 14 | 30 |
| command field | 12 | 0 | 1 | 0 | 11 |
| endpoint field, whole URL | 12 | 0 | 3 | 0 | 9 |
| env value | 523 | 389 | 115 | 115 | 134 |
| header value | 100 | 67 | 15 | 15 | 33 |
| inline cmd or PowerShell script | 3 | 3 | 0 | 0 | 0 |
| inline sh -c script | 20 | 14 | 1 | 1 | 6 |
| oauth or auth object | 1 | 0 | 0 | 0 | 1 |
| **all** | **961** | **630** | **173** | **167** | **325** |

## Benign values, by origin

| group | cases | flagged by 255 | flagged by 259 | flagged by both | flagged by neither |
| --- | --- | --- | --- | --- | --- |
| files | 21 | 0 | 0 | 0 | 21 |
| matrix | 148 | 87 | 13 | 12 | 60 |
| own | 114 | 93 | 0 | 0 | 21 |
| r259 | 491 | 342 | 160 | 155 | 144 |
| t255 | 32 | 1 | 0 | 0 | 31 |
| t259 | 155 | 107 | 0 | 0 | 48 |
| **all** | **961** | **630** | **173** | **167** | **325** |

## Planted value in any output

Searched per case and tree: native JSON, CycloneDX, SPDX, SARIF, VEX, `risk` text, `risk --json-output`, and what each command printed. Kinds: the whole value, its first or last six characters (extent = how many characters of that end are present), its percent-encoded form, SHA-256, SHA-1, MD5.


### credential cases

| tree | cases with any hit | whole value | prefix or suffix only | digest |
| --- | --- | --- | --- | --- |
| main | 27 | 0 | 27 | 0 |
| pr255 | 27 | 0 | 27 | 0 |
| pr259 | 27 | 0 | 27 | 0 |

### benign cases

| tree | cases with any hit | whole value | prefix or suffix only | digest |
| --- | --- | --- | --- | --- |
| main | 119 | 1 | 118 | 0 |
| pr255 | 135 | 1 | 134 | 0 |
| pr259 | 133 | 1 | 132 | 0 |


## pr255 misses: 100 of 476 labelled credentials

| group | cases | of them PR 259 reports | stated in PR 255's docs/known-limitations.md | example cases |
| --- | --- | --- | --- | --- |
| endpoint URL, query, fragment or path | 27 | 20 | WRONG: the same sentence, but transport_security reads user information only, so nothing is raised | c0011, c0024, c0037, c0050 |
| endpoint URL, user information | 21 | 15 | yes: "in an endpoint URL (`transport_security` covers that)"; transport_security is raised | c0008, c0021, c0034, c0047 |
| command field | 13 | 12 | yes: "A credential in the `command` field itself ... raises no `credential_exposure` finding" | c0007, c0020, c0033, c0046 |
| private key block or key file text under a name without a credential word | 9 | 6 | no | c0691, c0692, c0693, c0694 |
| Claude Code settings env | 6 | 6 | yes: "in a Claude Code settings `env` value" | c1390, c1391, c1393, c1394 |
| container --env=NAME=VALUE | 4 | 4 | no | c0404, c0652, c1434, c1435 |
| credential inside a longer argument (a=1,token=V; JSON; --token:V) | 4 | 1 | no | c0645, c0646, c0663, c0665 |
| key=value text inside a value (JDBC ;password=, netrc, AccountKey= under a plain name) | 3 | 0 | no | c0638, c1218, c1242 |
| no name marks the position (-t VALUE, positional, echo VALUE | ...) | 3 | 0 | no | c0644, c0647, c0674 |
| oauth or auth object | 3 | 0 | yes: "in an `oauth` or `auth` object" | c1399, c1400, c1401 |
| value shorter than eight characters | 2 | 0 | no (the eight-character floor is stated only for placeholders) | c1236, c1237 |
| URL password cut at ; , or ' in an env value | 1 | 0 | no | c0636 |
| `NAME = value` with spaces in a script | 1 | 0 | no | c0673 |
| secret in the path of a URL in an env value | 1 | 0 | yes: "a URL counts only for a credential in its user information or query" | c0699 |
| password that reads as $NAME | 1 | 0 | no (follows from "`$NAME` ... count as references") | c1199 |
| name without a credential word (TOTP_SEED) | 1 | 0 | no | c1214 |

## pr255 false positives: 630 of 961 benign values

| shape | flagged of cases | of them PR 259 flags too | stated in PR 255's docs/known-limitations.md | example cases |
| --- | --- | --- | --- | --- |
| placeholder-marked | 90 of 117 | 4 | yes: "a placeholder such as `<your-api-key>` or `YOUR_API_KEY_HERE` of eight or more characters under a credential name" | c0219, c0220, c0221, c0222 |
| noncredential-name | 66 of 76 | 0 | no | c1251, c1252, c1253, c1254 |
| keyfile-path-rel | 48 of 50 | 31 | no | c0282, c0283, c0284, c0285 |
| keyfile-path-abs | 44 of 48 | 0 | no | c0272, c0273, c0274, c0275 |
| identifier-or-setting | 40 of 88 | 12 | no | c1067, c1075, c1079, c1084 |
| ref-secret-store | 36 of 50 | 21 | in part: "Only `${NAME}`, `$NAME` and `{{ name }}` count as references"; not named | c0207, c0208, c0209, c0210 |
| placeholder-token-format | 36 of 39 | 11 | in part: the same sentence; a token-format placeholder is not named | c0375, c0377, c0381, c0383 |
| placeholder-phrase | 30 of 30 | 18 | in part: the same sentence names two placeholder forms | c1011, c1012, c1013, c1014 |
| placeholder-after-scheme | 29 of 30 | 10 | in part: the same sentence; a placeholder after `Bearer` is not named | c0956, c0957, c0958, c0959 |
| explanatory-text | 28 of 29 | 23 | no | c0258, c0259, c0260, c0261 |
| default-word | 24 of 33 | 0 | no | c0263, c0264, c0265, c0266 |
| ref-windows | 19 of 20 | 0 | yes: "a cmd or PowerShell reference (`%API_TOKEN%`, `$env:API_TOKEN`) ... reported as a generic secret-like value" | c0181, c0182, c0183, c0184 |
| weak-or-doc-password | 19 of 31 | 9 | no | c0604, c0605, c0606, c0897 |
| ref-template | 18 of 34 | 5 | in part: "Only `${NAME}`, `$NAME` and `{{ name }}` count as references"; `${{ secrets.TOKEN }}` is named | c0192, c0193, c0194, c0195 |
| prose-with-scheme-word | 13 of 16 | 0 | no | c0512, c0513, c1184, c1185 |
| ref-cmd-subst | 11 of 13 | 0 | in part: "Only `${NAME}`, `$NAME` and `{{ name }}` count as references"; command substitution is not named | c0212, c0213, c0214, c0215 |
| ref-code | 11 of 11 | 8 | in part: "Only `${NAME}`, `$NAME` and `{{ name }}` count as references"; not named | c0779, c0780, c0781, c0782 |
| random-under-noncredential-name | 10 of 17 | 0 | no | c0423, c0557, c0558, c0559 |
| ref-client | 9 of 104 | 0 | NO, and contradicts "A reference or template (`${NAME}`, `$NAME`, `{{ name }}`, also after a scheme word such as `Bearer`) does not count" | c0149, c0162, c0413, c0417 |
| public-material | 8 of 10 | 1 | no | c1160, c1161, c1163, c1164 |
| inline-code-env-read | 7 of 7 | 5 | no | c0790, c0791, c0792, c0793 |
| secret-helper-command | 7 of 17 | 5 | no | c0802, c0803, c0804, c0805 |
| colon-text-under-plain-name | 6 of 6 | 0 | no | c1412, c1413, c1414, c1415 |
| var-name-as-value | 5 of 5 | 0 | no | c1120, c1121, c1122, c1142 |
| literal-plus-reference | 4 of 4 | 0 | in part: "Only `${NAME}`, `$NAME` and `{{ name }}` count as references" | c0508, c0509, c0510, c0511 |
| image-digest | 4 of 10 | 4 | no | c1175, c1178, c1179, c1181 |
| image-tag | 3 of 3 | 0 | no | c1418, c1419, c1420 |
| partial-reference | 2 of 2 | 0 | in part: "Only `${NAME}`, `$NAME` and `{{ name }}` count as references" | c0310, c0363 |
| passphrase-doc-example | 1 of 1 | 0 | no | c0421 |
| ref-shell-default | 1 of 5 | 0 | in part: "Only `${NAME}`, `$NAME` and `{{ name }}` count as references"; not named | c0706 |
| hash-not-secret | 1 of 3 | 0 | no | c1170 |

## Prototype on top of PR 255 (prototype/stage1.patch, stage2.patch, stage3.patch)

| tree | credentials reported (of 476) | benign values reported (of 961) | cases with a hit of the planted value that main lacks |
| --- | --- | --- | --- |
| main | 0 (0.0%) | 0 (0.0%) | whole value or digest of a credential: 0 |
| pr255 | 376 (79.0%) | 630 (65.6%) | whole value or digest of a credential: 0 |
| pr259 | 381 (80.0%) | 173 (18.0%) | whole value or digest of a credential: 0 |
| fix1 | 380 (79.8%) | 608 (63.3%) | whole value or digest of a credential: 0 |
| fix2 | 379 (79.6%) | 329 (34.2%) | whole value or digest of a credential: 0 |
| fix3 | 422 (88.7%) | 340 (35.4%) | whole value or digest of a credential: 0 |

| credential shape | cases | main | pr255 | pr259 | fix1 | fix2 | fix3 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| arg-embedded | 5 | 0 | 3 | 2 | 3 | 3 | 3 |
| arg-header-line | 10 | 0 | 10 | 8 | 10 | 10 | 10 |
| connection-string | 5 | 0 | 2 | 0 | 2 | 2 | 2 |
| cookie-session | 2 | 0 | 2 | 0 | 2 | 2 | 2 |
| inline-script | 10 | 0 | 9 | 8 | 9 | 9 | 9 |
| mixedcase-letters-value | 1 | 0 | 1 | 1 | 1 | 1 | 1 |
| passphrase-words | 4 | 0 | 4 | 2 | 4 | 4 | 4 |
| password-non-ascii | 1 | 0 | 1 | 1 | 1 | 1 | 1 |
| password-punctuation | 18 | 0 | 15 | 13 | 15 | 15 | 17 |
| password-short | 15 | 0 | 10 | 13 | 10 | 10 | 12 |
| password-uppercase-underscore | 2 | 0 | 1 | 0 | 1 | 1 | 1 |
| password-wordy | 48 | 0 | 42 | 48 | 42 | 42 | 46 |
| private-key | 13 | 0 | 4 | 8 | 4 | 4 | 11 |
| random-starts-with-slash | 1 | 0 | 1 | 0 | 1 | 1 | 1 |
| random-under-credential-name | 107 | 0 | 91 | 100 | 95 | 95 | 101 |
| random-under-key-like-name | 13 | 0 | 12 | 4 | 12 | 12 | 12 |
| random-unmarked-position | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| random-with-chance-mark | 1 | 0 | 1 | 0 | 1 | 0 | 0 |
| scheme-authorization-variant | 13 | 0 | 13 | 13 | 13 | 13 | 13 |
| scheme-basic | 7 | 0 | 7 | 6 | 7 | 7 | 7 |
| scheme-bearer | 23 | 0 | 23 | 16 | 23 | 23 | 23 |
| scheme-other | 3 | 0 | 3 | 3 | 3 | 3 | 3 |
| sentinel-uppercase-name | 18 | 0 | 15 | 0 | 15 | 15 | 17 |
| synthetic-colon-chain | 3 | 0 | 3 | 3 | 3 | 3 | 3 |
| synthetic-repetitive | 2 | 0 | 2 | 0 | 2 | 2 | 2 |
| token-shaped-name | 2 | 0 | 2 | 0 | 2 | 2 | 2 |
| url-password | 16 | 0 | 5 | 12 | 5 | 5 | 5 |
| url-path-token | 3 | 0 | 0 | 1 | 0 | 0 | 1 |
| url-query-token | 16 | 0 | 2 | 11 | 2 | 2 | 13 |
| url-userinfo-user-only | 3 | 0 | 0 | 1 | 0 | 0 | 0 |
| user-colon-password | 5 | 0 | 5 | 5 | 5 | 5 | 5 |
| uuid-as-token | 15 | 0 | 12 | 15 | 12 | 12 | 14 |
| vendor-token | 87 | 0 | 74 | 86 | 74 | 74 | 80 |
| vendor-token-unlisted | 1 | 0 | 1 | 1 | 1 | 1 | 1 |

| benign shape | cases | main | pr255 | pr259 | fix1 | fix2 | fix3 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| colon-text-under-plain-name | 6 | 0 | 6 | 0 | 1 | 0 | 0 |
| default-word | 33 | 0 | 24 | 0 | 24 | 21 | 23 |
| env-name-only | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| explanatory-text | 29 | 0 | 28 | 24 | 28 | 27 | 28 |
| hash-not-secret | 3 | 0 | 1 | 0 | 1 | 0 | 0 |
| identifier-or-setting | 88 | 0 | 40 | 12 | 40 | 35 | 35 |
| image-digest | 10 | 0 | 4 | 4 | 4 | 4 | 4 |
| image-tag | 3 | 0 | 3 | 0 | 1 | 1 | 1 |
| inline-code-env-read | 7 | 0 | 7 | 5 | 7 | 6 | 6 |
| keyfile-path-abs | 48 | 0 | 44 | 0 | 44 | 0 | 0 |
| keyfile-path-rel | 50 | 0 | 48 | 32 | 48 | 2 | 2 |
| literal-plus-reference | 4 | 0 | 4 | 0 | 4 | 4 | 4 |
| locator-url | 28 | 0 | 0 | 3 | 0 | 0 | 3 |
| noncredential-name | 76 | 0 | 66 | 0 | 66 | 52 | 57 |
| package-requirement | 4 | 0 | 0 | 0 | 0 | 0 | 0 |
| partial-reference | 2 | 0 | 2 | 0 | 2 | 2 | 2 |
| passphrase-doc-example | 1 | 0 | 1 | 0 | 1 | 1 | 1 |
| placeholder-after-scheme | 30 | 0 | 29 | 10 | 29 | 21 | 21 |
| placeholder-marked | 117 | 0 | 90 | 4 | 90 | 13 | 13 |
| placeholder-phrase | 30 | 0 | 30 | 18 | 30 | 30 | 30 |
| placeholder-token-format | 39 | 0 | 36 | 11 | 36 | 14 | 14 |
| plain-launch | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| prose-with-scheme-word | 16 | 0 | 13 | 1 | 2 | 1 | 1 |
| public-material | 10 | 0 | 8 | 1 | 8 | 8 | 8 |
| random-under-noncredential-name | 17 | 0 | 10 | 0 | 10 | 10 | 10 |
| ref-client | 104 | 0 | 9 | 0 | 6 | 2 | 2 |
| ref-cmd-subst | 13 | 0 | 11 | 0 | 10 | 0 | 0 |
| ref-code | 11 | 0 | 11 | 8 | 11 | 10 | 10 |
| ref-in-url | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| ref-lowercase-or-empty | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| ref-secret-store | 50 | 0 | 36 | 21 | 36 | 31 | 31 |
| ref-shell-default | 5 | 0 | 1 | 0 | 1 | 0 | 0 |
| ref-template | 34 | 0 | 18 | 5 | 18 | 7 | 7 |
| ref-windows | 20 | 0 | 19 | 0 | 19 | 0 | 0 |
| secret-helper-command | 17 | 0 | 7 | 5 | 7 | 5 | 5 |
| short-word | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| var-name-as-value | 5 | 0 | 5 | 0 | 5 | 5 | 5 |
| weak-or-doc-password | 31 | 0 | 19 | 9 | 19 | 17 | 17 |

