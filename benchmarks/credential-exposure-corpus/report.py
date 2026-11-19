"""Merge the three result files into Markdown tables and a per-case table.

    python report.py <corpus dir> <results dir> <out dir>

Reads <results dir>/main.jsonl, pr255.jsonl and pr259.jsonl (written by run_tree.py) and
writes <out dir>/RESULTS.md and <out dir>/cases.tsv.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

corpus, results, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
out.mkdir(parents=True, exist_ok=True)
manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
TREES = ("main", "pr255", "pr259")
data: dict[str, dict[str, dict]] = {}
sources = {}
for tree in TREES:
    lines = (results / f"{tree}.jsonl").read_text(encoding="utf-8").splitlines()
    sources[tree] = json.loads(lines[0])
    data[tree] = {row["id"]: row for row in map(json.loads, lines[1:])}
    assert len(data[tree]) == len(manifest), (tree, len(data[tree]), len(manifest))


def flagged(tree: str, case_id: str) -> bool:
    return bool(data[tree][case_id]["findings"])


def shown(text: str, limit: int = 60) -> str:
    text = text.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t").replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 15] + "..." + text[-12:]


POSITION_GROUP = {
    "env": "env value", "header": "header value", "arg_flag_sep": "argument: --name VALUE", "arg_flag_eq": "argument: --name=VALUE",
    "arg_kv": "argument: NAME=VALUE word", "sh_c": "inline sh -c script", "sh_c_flag": "inline sh -c script", "cmd_c": "inline cmd or PowerShell script",
    "powershell_c": "inline cmd or PowerShell script", "command": "command field", "url_userinfo_endpoint": "URL user information: endpoint field",
    "url_userinfo_env": "URL user information: env value", "url_userinfo_arg": "URL user information: argument", "url_query_endpoint": "URL query: endpoint field",
    "url_query_env": "URL query: env value", "url_query_arg": "URL query: argument", "url_fragment_endpoint": "URL fragment, matrix or path: endpoint field",
    "url_matrix_endpoint": "URL fragment, matrix or path: endpoint field", "url_path_endpoint": "URL fragment, matrix or path: endpoint field",
    "url_endpoint": "endpoint field, whole URL", "arg_header_line": "argument: header line", "arg_json": "argument: JSON text", "arg_embedded": "argument: other (embedded, positional, raw)",
    "arg_positional": "argument: other (embedded, positional, raw)", "arg_raw": "argument: other (embedded, positional, raw)", "arg_flag_other": "argument: other (embedded, positional, raw)",
    "arg_inline_words": "argument: other (embedded, positional, raw)", "inline_code": "argument: other (embedded, positional, raw)", "env_name": "env or header NAME",
    "header_name": "env or header NAME", "field": "another server field", "gemini_server_command": "Gemini mcpServerCommand", "claude_settings_env": "Claude Code settings env",
    "oauth_object": "oauth or auth object", "auth_object": "oauth or auth object",
}  # fmt: skip

lines: list[str] = []
w = lines.append
w("# Differential results: origin/main, PR 255 (credential_exposure), PR 259 (literal_credential)\n")
for tree in TREES:
    w(f"- {tree}: `{sources[tree]['source']}`, {sources[tree]['cases']} cases")
labels = Counter(case["label"] for case in manifest)
w(f"- corpus: {len(manifest)} cases, {labels['credential']} labelled credential, {labels['benign']} labelled benign")
origins = Counter((case["origin"], case["label"]) for case in manifest)
w("\n| origin | credential | benign |\n| --- | --- | --- |")
for origin in sorted({o for o, _ in origins}):
    w(f"| {origin} | {origins[(origin, 'credential')]} | {origins[(origin, 'benign')]} |")

# ---- anything raised on main, severities ----------------------------------------------
main_flagged = [c["id"] for c in manifest if flagged("main", c["id"])]
w(f"\nCredential findings on main: {len(main_flagged)} cases.")
for tree in ("pr255", "pr259"):
    severities = Counter(f["severity"] for row in data[tree].values() for f in row["findings"])
    per_case = Counter(len(row["findings"]) for row in data[tree].values() if row["findings"])
    w(f"Severities of the credential findings on {tree}: {dict(severities)}; findings per flagged case: {dict(sorted(per_case.items()))}.")

# ---- scan failures -------------------------------------------------------------------
w("\n## Cases a tree did not inventory (scan failure)\n")
w("| case | origin | label | shape | position | main | pr255 | pr259 |\n| --- | --- | --- | --- | --- | --- | --- | --- |")
failed = 0
for case in manifest:
    fails = {tree: data[tree][case["id"]]["scan_failures"] for tree in TREES}
    if any(fails.values()):
        failed += 1
        w(f"| {case['id']} | {case['origin']} | {case['label']} | {case['shape']} | {case['position']} | " + " | ".join(shown("; ".join(fails[t]) or "ok", 70) for t in TREES) + " |")
w(f"\n{failed} cases.")


def table(title: str, key, label: str) -> None:
    groups: dict[str, list[dict]] = defaultdict(list)
    for case in manifest:
        if case["label"] == label:
            groups[key(case)].append(case)
    w(f"\n## {title}\n")
    if label == "credential":
        w("| group | cases | both | only 255 | only 259 | neither | 255 total | 259 total |\n| --- | --- | --- | --- | --- | --- | --- | --- |")
        total = Counter()
        for group in sorted(groups):
            tally = Counter()
            for case in groups[group]:
                a, b = flagged("pr255", case["id"]), flagged("pr259", case["id"])
                tally["both" if a and b else "only255" if a else "only259" if b else "neither"] += 1
            total.update(tally)
            n = len(groups[group])
            w(f"| {group} | {n} | {tally['both']} | {tally['only255']} | {tally['only259']} | {tally['neither']} | {tally['both'] + tally['only255']} | {tally['both'] + tally['only259']} |")
        n = sum(len(g) for g in groups.values())
        w(f"| **all** | **{n}** | **{total['both']}** | **{total['only255']}** | **{total['only259']}** | **{total['neither']}** | **{total['both'] + total['only255']}** | **{total['both'] + total['only259']}** |")
    else:
        w("| group | cases | flagged by 255 | flagged by 259 | flagged by both | flagged by neither |\n| --- | --- | --- | --- | --- | --- |")
        total = Counter()
        for group in sorted(groups):
            tally = Counter()
            for case in groups[group]:
                a, b = flagged("pr255", case["id"]), flagged("pr259", case["id"])
                tally["a"] += a
                tally["b"] += b
                tally["both"] += a and b
                tally["neither"] += not a and not b
            total.update(tally)
            w(f"| {group} | {len(groups[group])} | {tally['a']} | {tally['b']} | {tally['both']} | {tally['neither']} |")
        n = sum(len(g) for g in groups.values())
        w(f"| **all** | **{n}** | **{total['a']}** | **{total['b']}** | **{total['both']}** | **{total['neither']}** |")


table("Labelled credentials, by shape", lambda c: c["shape"], "credential")
table("Labelled credentials, by position", lambda c: POSITION_GROUP[c["position"]], "credential")
table("Labelled credentials, by origin", lambda c: c["origin"], "credential")
table("Benign values, by shape", lambda c: c["shape"], "benign")
table("Benign values, by position", lambda c: POSITION_GROUP[c["position"]], "benign")
table("Benign values, by origin", lambda c: c["origin"], "benign")

# ---- leaks ---------------------------------------------------------------------------
w("\n## Planted value in any output\n")
w("Searched per case and tree: native JSON, CycloneDX, SPDX, SARIF, VEX, `risk` text, `risk --json-output`, and what each command printed. Kinds: the whole value, its first or last six characters (extent = how many characters of that end are present), its percent-encoded form, SHA-256, SHA-1, MD5.\n")
for label in ("credential", "benign"):
    w(f"\n### {label} cases\n")
    w("| tree | cases with any hit | whole value | prefix or suffix only | digest |\n| --- | --- | --- | --- | --- |")
    for tree in TREES:
        whole = part = digest = any_ = 0
        for case in manifest:
            if case["label"] != label:
                continue
            kinds = {hit["kind"].split(":")[1] for hit in data[tree][case["id"]]["leaks"]}
            any_ += bool(kinds)
            whole += bool(kinds & {"whole", "percent-encoded"})
            part += bool(kinds & {"prefix6", "suffix6"}) and not kinds & {"whole", "percent-encoded"}
            digest += bool(kinds & {"sha256", "sha1", "md5"})
        w(f"| {tree} | {any_} | {whole} | {part} | {digest} |")
w("\n### Every hit on a credential case\n")
w("| case | origin | shape | position | tree | kinds | outputs | context of the first hit |\n| --- | --- | --- | --- | --- | --- | --- | --- |")
for case in manifest:
    if case["label"] != "credential":
        continue
    for tree in TREES:
        hits = data[tree][case["id"]]["leaks"]
        if hits:
            kinds = sorted({h["kind"] + (f"({h['extent']})" if "extent" in h else "") for h in hits})
            outputs = sorted({h["output"] for h in hits})
            w(f"| {case['id']} | {case['origin']} | {case['shape']} | {case['position']} | {tree} | {', '.join(kinds)} | {', '.join(outputs)} | `{shown(hits[0]['context'], 110)}` |")

# ---- what else changed against main -----------------------------------------------------
w("\n## Findings other than the credential finding, against main\n")
for tree in ("pr255", "pr259"):
    changed = []
    deltas = Counter()
    for case in manifest:
        mine = Counter(c for c in data[tree][case["id"]]["categories"] if c.split(":")[1] not in ("credential_exposure", "literal_credential"))
        base = Counter(data["main"][case["id"]]["categories"])
        if mine != base:
            changed.append((case["id"], sorted((mine - base).elements()), sorted((base - mine).elements())))
        new = len(data[tree][case["id"]]["findings"])
        score_a, score_b = data[tree][case["id"]].get("score"), data["main"][case["id"]].get("score")
        if score_a is not None and score_b is not None:
            deltas[(new, round(score_a - score_b, 1))] += 1
    w(f"- {tree}: {len(changed)} cases whose other findings differ from main" + (": " + "; ".join(f"{i} +{a} -{b}" for i, a, b in changed[:12]) if changed else "") + ".")
    w(f"  Score change against main by number of credential findings in the case: " + ", ".join(f"{n} finding(s) -> {d:+} in {count} cases" for (n, d), count in sorted(deltas.items())) + ".")

# ---- PR 255 misses and false positives ----------------------------------------------------
def listing(title: str, pick) -> None:
    w(f"\n## {title}\n")
    w("| case | origin | shape | position | name | planted value | PR 255 | PR 259 |\n| --- | --- | --- | --- | --- | --- | --- | --- |")
    count = 0
    for case in manifest:
        if not pick(case):
            continue
        count += 1
        a = data["pr255"][case["id"]]["findings"]
        b = data["pr259"][case["id"]]["findings"]
        da = "; ".join(f["detail"].split("in its launch: ")[-1].rstrip(".") for f in a) or "-"
        db = "; ".join(f["detail"].split(" at ", 1)[-1].rstrip(".") for f in b) or "-"
        w(f"| {case['id']} | {case['origin']} | {case['shape']} | {case['position']} | `{shown(case['name'], 30)}` | `{shown(case['value'], 56)}` | {shown(da, 80)} | {shown(db, 80)} |")
    w(f"\n{count} cases.")


listing("PR 255 misses: labelled credential, no credential_exposure", lambda c: c["label"] == "credential" and not flagged("pr255", c["id"]))
listing("PR 255 false positives: labelled benign, credential_exposure raised", lambda c: c["label"] == "benign" and flagged("pr255", c["id"]))
listing("PR 259 misses: labelled credential, no literal_credential", lambda c: c["label"] == "credential" and not flagged("pr259", c["id"]))
listing("PR 259 false positives: labelled benign, literal_credential raised", lambda c: c["label"] == "benign" and flagged("pr259", c["id"]))

(out / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

with (out / "cases.tsv").open("w", encoding="utf-8") as stream:
    stream.write("id\torigin\tlabel\tauthor_label\tshape\tposition\tfile\tname\tvalue\tmain\tpr255\tpr259\tpr255_detail\tpr259_detail\tleak_main\tleak_pr255\tleak_pr259\tnote\n")
    for case in manifest:
        row = [case["id"], case["origin"], case["label"], case["author_label"], case["shape"], case["position"], case["file"], shown(case["name"], 40), shown(case["value"], 80)]
        row += [str(int(flagged(tree, case["id"]))) for tree in TREES]
        row.append("; ".join(f["detail"].split("in its launch: ")[-1] for f in data["pr255"][case["id"]]["findings"]))
        row.append("; ".join(f["detail"].split(" at ", 1)[-1] for f in data["pr259"][case["id"]]["findings"]))
        row += [",".join(sorted({h["kind"] for h in data[tree][case["id"]]["leaks"]})) for tree in TREES]
        row.append(case["note"])
        stream.write("\t".join(cell.replace("\t", " ").replace("\n", "\\n") for cell in row) + "\n")
print(f"wrote {out / 'RESULTS.md'} ({len(lines)} lines) and {out / 'cases.tsv'}")
