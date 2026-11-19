"""PR 255 misses and false positives, grouped, with whether its known-limitations text states them.

    python doc_map.py <corpus dir> <results dir> [tree]
"""
import json, sys
from collections import defaultdict
from pathlib import Path
corpus, results = Path(sys.argv[1]), Path(sys.argv[2])
tree = sys.argv[3] if len(sys.argv) > 3 else "pr255"
manifest = json.loads((corpus / "manifest.json").read_text())
rows = {r["id"]: r for r in map(json.loads, (results / f"{tree}.jsonl").read_text().splitlines()[1:])}
other = {r["id"]: r for r in map(json.loads, (results / "pr259.jsonl").read_text().splitlines()[1:])}
ENDPOINT_OTHER = ("url_query_endpoint", "url_fragment_endpoint", "url_matrix_endpoint", "url_path_endpoint")
def miss_group(c):
    p = c["position"]
    if p == "command": return ("command field", "yes: \"A credential in the `command` field itself ... raises no `credential_exposure` finding\"")
    if p == "url_userinfo_endpoint": return ("endpoint URL, user information", "yes: \"in an endpoint URL (`transport_security` covers that)\"; transport_security is raised")
    if p in ENDPOINT_OTHER: return ("endpoint URL, query, fragment or path", "WRONG: the same sentence, but transport_security reads user information only, so nothing is raised")
    if p == "claude_settings_env": return ("Claude Code settings env", "yes: \"in a Claude Code settings `env` value\"")
    if p in ("oauth_object", "auth_object"): return ("oauth or auth object", "yes: \"in an `oauth` or `auth` object\"")
    if c["shape"] == "private-key": return ("private key block or key file text under a name without a credential word", "no")
    if c["shape"] == "url-path-token": return ("secret in the path of a URL in an env value", "yes: \"a URL counts only for a credential in its user information or query\"")
    if c["shape"] == "password-short": return ("value shorter than eight characters", "no (the eight-character floor is stated only for placeholders)")
    if c["shape"] in ("random-unmarked-position",): return ("no name marks the position (-t VALUE, positional, echo VALUE | ...)", "no")
    if p == "arg_kv" and c["name"] in ("--env",): return ("container --env=NAME=VALUE", "no")
    if c["shape"] in ("connection-string",): return ("key=value text inside a value (JDBC ;password=, netrc, AccountKey= under a plain name)", "no")
    if c["shape"] in ("arg-embedded",) or p == "arg_flag_other": return ("credential inside a longer argument (a=1,token=V; JSON; --token:V)", "no")
    if c["shape"] == "url-password": return ("URL password cut at ; , or ' in an env value", "no")
    if c["shape"] == "password-uppercase-underscore": return ("password that reads as $NAME", "no (follows from \"`$NAME` ... count as references\")")
    if c["shape"] == "random-under-key-like-name": return ("name without a credential word (TOTP_SEED)", "no")
    if c["shape"] == "inline-script": return ("`NAME = value` with spaces in a script", "no")
    return (f"other: {c['shape']} at {p}", "no")
DOC_REF = "in part: \"Only `${NAME}`, `$NAME` and `{{ name }}` count as references\""
FP = {
    "ref-windows": "yes: \"a cmd or PowerShell reference (`%API_TOKEN%`, `$env:API_TOKEN`) ... reported as a generic secret-like value\"",
    "ref-template": DOC_REF + "; `${{ secrets.TOKEN }}` is named",
    "ref-cmd-subst": DOC_REF + "; command substitution is not named",
    "ref-code": DOC_REF + "; not named", "ref-secret-store": DOC_REF + "; not named", "ref-shell-default": DOC_REF + "; not named",
    "partial-reference": DOC_REF, "literal-plus-reference": DOC_REF,
    "placeholder-marked": "yes: \"a placeholder such as `<your-api-key>` or `YOUR_API_KEY_HERE` of eight or more characters under a credential name\"",
    "placeholder-phrase": "in part: the same sentence names two placeholder forms", "placeholder-token-format": "in part: the same sentence; a token-format placeholder is not named",
    "placeholder-after-scheme": "in part: the same sentence; a placeholder after `Bearer` is not named",
    "ref-client": "NO, and contradicts \"A reference or template (`${NAME}`, `$NAME`, `{{ name }}`, also after a scheme word such as `Bearer`) does not count\"",
}
print(f"## {tree} misses: {sum(1 for c in manifest if c['label'] == 'credential' and not rows[c['id']]['findings'])} of {sum(1 for c in manifest if c['label'] == 'credential')} labelled credentials\n")
groups = defaultdict(list)
for c in manifest:
    if c["label"] == "credential" and not rows[c["id"]]["findings"]:
        groups[miss_group(c)].append(c)
print("| group | cases | of them PR 259 reports | stated in PR 255's docs/known-limitations.md | example cases |\n| --- | --- | --- | --- | --- |")
for (group, doc), cases in sorted(groups.items(), key=lambda kv: -len(kv[1])):
    print(f"| {group} | {len(cases)} | {sum(bool(other[c['id']]['findings']) for c in cases)} | {doc} | {', '.join(c['id'] for c in cases[:4])} |")
print(f"\n## {tree} false positives: {sum(1 for c in manifest if c['label'] == 'benign' and rows[c['id']]['findings'])} of {sum(1 for c in manifest if c['label'] == 'benign')} benign values\n")
shapes = defaultdict(lambda: [0, 0, 0, []])
for c in manifest:
    if c["label"] == "benign":
        entry = shapes[c["shape"]]
        entry[1] += 1
        if rows[c["id"]]["findings"]:
            entry[0] += 1
            entry[2] += bool(other[c["id"]]["findings"])
            entry[3].append(c["id"])
print("| shape | flagged of cases | of them PR 259 flags too | stated in PR 255's docs/known-limitations.md | example cases |\n| --- | --- | --- | --- | --- |")
for shape, (hit, total, both, ids) in sorted(shapes.items(), key=lambda kv: -kv[1][0]):
    if hit:
        print(f"| {shape} | {hit} of {total} | {both} | {FP.get(shape, 'no')} | {', '.join(ids[:4])} |")
