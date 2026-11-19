"""Forty-five more cases: credential shapes and benign values that corpus.py lacks.

    python3 -I extra_cases.py <out dir>

Written by the second reader of the review, who did not see how corpus.py was built.
One project per case, with a manifest in the format corpus.py writes, so run_tree.py and
compare.py read it as they read the main corpus. Every credential-shaped value is put
together here from parts when the script runs; no token is committed.
"""
from __future__ import annotations
import base64, hashlib, json, shutil, string, sys
from pathlib import Path

ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
B64 = string.ascii_letters + string.digits + "+/"
UP32 = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"


def rnd(n: int, alphabet: str = ALNUM, seed: str = "") -> str:
    out: list[str] = []
    counter = 0
    limit = 256 - (256 % len(alphabet))
    while len(out) < n:
        for byte in hashlib.sha256(f"cred-verify:{seed}:{counter}".encode()).digest():
            if byte < limit:
                out.append(alphabet[byte % len(alphabet)])
        counter += 1
    return "".join(out[:n])


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


PIN = ["-y", "some-mcp@1.0.0"]
IMG = "mcp/x@sha256:" + "a" * 64
URL = "https://mcp.example.test/mcp"
CASES: list[dict] = []


def add(label: str, shape: str, position: str, server: dict | None, secret: str, value: str | None = None, note: str = "", servers: dict | None = None, name: str = "") -> None:
    CASES.append({
        "id": f"x{len(CASES) + 1:03d}", "origin": "verify", "label": label, "shape": shape, "position": position,
        "file": ".mcp.json", "name": name, "value": secret if value is None else value, "secret": secret, "note": note,
        "author_label": label, "servers": servers or {"svc": server},
    })


def env(**pairs: str) -> dict:
    return {"command": "npx", "args": list(PIN), "env": pairs}


def envd(pairs: dict) -> dict:
    return {"command": "npx", "args": list(PIN), "env": pairs}


def args(*extra: str, command: str = "npx", lead: list[str] | None = None) -> dict:
    return {"command": command, "args": [*(PIN if lead is None else lead), *extra]}


def http(**headers: str) -> dict:
    return {"type": "http", "url": URL, "headers": headers}


# ---- credential shapes the corpus lacks -------------------------------------------------
SIG = rnd(43, B64.replace("+", "").replace("/", ""), "sas") 
SAS = f"https://acmeprod.blob.core.windows.net/models/weights.bin?sv=2022-11-02&ss=b&srt=co&sp=rl&se=2027-01-01T00:00:00Z&spr=https&sig={SIG}%3D"
add("credential", "sas-url-sig", "url_query_env", env(AZURE_BLOB_URL=SAS), SIG, SAS, "Azure SAS URL: the secret is the sig= query parameter", name="AZURE_BLOB_URL")
add("credential", "sas-url-sig", "url_query_arg", args("--blob-url", SAS), SIG, SAS, "Azure SAS URL as an option value", name="--blob-url")
AMZ_SIG = rnd(64, HEX, "amz")
AKIA = "AK" + "IA" + rnd(16, string.ascii_uppercase + string.digits, "akia")
PRESIGNED = (f"https://acme-models.s3.amazonaws.com/weights.bin?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={AKIA}%2F20261118%2Fus-east-1%2Fs3%2Faws4_request"
             f"&X-Amz-Date=20261118T000000Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature={AMZ_SIG}")
add("credential", "presigned-url", "url_query_env", env(MODEL_URL=PRESIGNED), AMZ_SIG, PRESIGNED, "AWS presigned URL", name="MODEL_URL")
GOOG_SIG = rnd(128, HEX, "goog")
GSIGNED = (f"https://storage.googleapis.com/acme-data/corpus.tar?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Date=20261118T000000Z&X-Goog-Expires=604800"
           f"&X-Goog-SignedHeaders=host&X-Goog-Signature={GOOG_SIG}")
add("credential", "presigned-url", "url_query_arg", args("--dataset", GSIGNED), GOOG_SIG, GSIGNED, "Google signed URL as an option value", name="--dataset")

R40 = rnd(40, seed="default-literal")
add("credential", "default-literal", "env", env(API_TOKEN="${API_TOKEN:-" + R40 + "}"), R40, "${API_TOKEN:-" + R40 + "}", "a literal credential as the default of a shell-style reference", name="API_TOKEN")
add("credential", "default-literal", "arg_flag_sep", args("--token", "${API_TOKEN:-" + R40 + "}"), R40, "${API_TOKEN:-" + R40 + "}", "", name="--token")
add("credential", "default-literal", "header", http(Authorization="Bearer ${API_TOKEN:-" + R40 + "}"), R40, "Bearer ${API_TOKEN:-" + R40 + "}", "", name="Authorization")
GH = "gh" + "p_" + rnd(36, seed="default-gh")
add("credential", "default-literal", "env", env(GITHUB_TOKEN="${GITHUB_TOKEN:-" + GH + "}"), GH, "${GITHUB_TOKEN:-" + GH + "}", "the default is a token in a known format", name="GITHUB_TOKEN")

PW1 = "vR8#" + "qL2!nX6@" + "tB4&"
PW2 = "Marigold" + "-Otter-" + "Lantern-58"
add("credential", "abbreviated-name", "env", env(DB_PW=PW1), PW1, note="a password under a name the name rule does not know", name="DB_PW")
add("credential", "abbreviated-name", "env", env(ADMIN_PSWD=PW2), PW2, name="ADMIN_PSWD")
add("credential", "abbreviated-name", "arg_flag_sep", args("--pw", PW2), PW2, name="--pw")
WORDS = ["lantern", "orbit", "velvet", "cactus", "harbor", "pencil", "tundra", "magnet", "sorrel", "quiver", "bramble", "nectar"]
MNEMONIC = " ".join(WORDS)
add("credential", "mnemonic", "env", env(WALLET_MNEMONIC=MNEMONIC), MNEMONIC, note="a wallet seed phrase (synthetic words)", name="WALLET_MNEMONIC")

DO = "dop" + "_v1_" + rnd(64, HEX, "do")
LIN = "lin" + "_api_" + rnd(40, seed="lin")
ATL = "ATATT" + "3xFfGF0" + rnd(60, ALNUM + "-_", "atl") + "=" + rnd(8, string.hexdigits.upper()[:16], "atl2")
AGE = "AGE-SECRET" + "-KEY-1" + rnd(58, UP32, "age")
DISCORD = rnd(24, ALNUM, "dc1") + "." + rnd(6, ALNUM + "-_", "dc2") + "." + rnd(38, ALNUM + "-_", "dc3")
for name, token, note in (("DIGITALOCEAN", DO, "DigitalOcean token prefix"), ("LINEAR", LIN, "Linear key prefix"), ("ATLASSIAN", ATL, "Atlassian API token prefix"),
                          ("SOPS_AGE", AGE, "age secret key"), ("DISCORD_BOT", DISCORD, "Discord bot token shape")):
    add("credential", "vendor-prefix-unlisted-plain-name", "env", envd({name: token}), token, note=note + ", under a name without a credential word", name=name)

IPW = "Zx9" + "Kv4Qm7Tn" + "2Lp8"
add("credential", "package-index-userinfo", "url_userinfo_arg", args("--index-url", f"https://deploy:{IPW}@pypi.example.test/simple", "some-mcp==1.0.0", command="uvx", lead=[]), IPW,
    f"https://deploy:{IPW}@pypi.example.test/simple", "a password in a package index option", name="--index-url")
add("credential", "package-index-userinfo", "url_userinfo_arg", args(f"--index-url=https://deploy:{IPW}@pypi.example.test/simple", "some-mcp==1.0.0", command="uvx", lead=[]), IPW,
    f"https://deploy:{IPW}@pypi.example.test/simple", "", name="--index-url=")
add("credential", "package-index-userinfo", "url_userinfo_env", env(UV_INDEX_URL=f"https://deploy:{IPW}@pypi.example.test/simple"), IPW, f"https://deploy:{IPW}@pypi.example.test/simple", "", name="UV_INDEX_URL")
NPM = "np" + "m_" + rnd(36, seed="npmrc")
add("credential", "npmrc-key-env-name", "env", envd({"npm_config_//npm.example.test/:_authToken": NPM}), NPM, note="npm's per-registry token setting as an env name with slashes", name="npm_config_//npm.example.test/:_authToken")
DOCKER_AUTH = json.dumps({"auths": {"registry.example.test": {"auth": b64("deploy:" + IPW)}}})
add("credential", "docker-auth-json", "env", env(REGISTRY_CONFIG=DOCKER_AUTH), b64("deploy:" + IPW), DOCKER_AUTH, "a registry auth document under a plain name", name="REGISTRY_CONFIG")
add("credential", "curl-user", "arg_flag_sep", args("-u", f"svc:{IPW}"), IPW, f"svc:{IPW}", "user:password after a short option", name="-u")
add("credential", "smtp-url", "url_userinfo_env", env(MAIL_URL=f"smtps://mailer:{IPW}@smtp.example.test:465"), IPW, f"smtps://mailer:{IPW}@smtp.example.test:465", "", name="MAIL_URL")
add("credential", "ipv6-userinfo", "url_userinfo_env", env(UPSTREAM=f"https://svc:{IPW}@[2001:db8::1]:8443/mcp"), IPW, f"https://svc:{IPW}@[2001:db8::1]:8443/mcp", "", name="UPSTREAM")
T40 = rnd(40, seed="crlf")
add("credential", "crlf-header", "header", http(**{"X-Trace": "abc\r\nAuthorization: Bearer " + T40}), T40, "abc\r\nAuthorization: Bearer " + T40, "a second header smuggled into a header value", name="X-Trace")

# ---- structures the corpus lacks (one value per file there) -----------------------------
S1, S2 = rnd(40, seed="two-a"), rnd(40, seed="two-b")
add("credential", "two-servers-two-credentials", "env+header", None, S1, S2, "two servers with one credential each and a clean third",
    servers={"alpha": env(API_TOKEN=S1), "beta": http(Authorization="Bearer " + S2), "clean": args()})
add("credential", "same-value-two-positions", "env+arg", {"command": "npx", "args": [*PIN, "--token", S1], "env": {"API_TOKEN": S1}}, S1, note="one value in env and in an argument")
add("credential", "disabled-server", "env", {**env(API_TOKEN=S1), "disabled": True}, S1, note="a credential on a disabled server")
add("credential", "endpoint-userinfo-plus-header", "url_userinfo_endpoint+header", {"type": "http", "url": f"https://svc:{IPW}@mcp.example.test/mcp", "headers": {"X-Api-Key": S1}}, S1, IPW,
    "two different literals: endpoint password (transport_security) and a header key")

# ---- benign values the corpus lacks -----------------------------------------------------
SSH = ["mcp@build.example.test", "mcp-server", "--stdio"]
add("benign", "ssh-option", "arg_kv", {"command": "ssh", "args": ["-o", "StrictHostKeyChecking=accept-new", *SSH]}, "accept-new", "StrictHostKeyChecking=accept-new", "the usual ssh host key option", name="StrictHostKeyChecking")
add("benign", "ssh-option", "arg_kv", {"command": "ssh", "args": ["-o", "PreferredAuthentications=publickey", *SSH]}, "publickey", "PreferredAuthentications=publickey", "", name="PreferredAuthentications")
add("benign", "ssh-option", "arg_kv", {"command": "ssh", "args": ["-o", "HostKeyAlgorithms=ssh-ed25519", *SSH]}, "ssh-ed25519", "HostKeyAlgorithms=ssh-ed25519", "", name="HostKeyAlgorithms")
add("benign", "uv-keyring-provider", "arg_flag_sep", {"command": "uvx", "args": ["--keyring-provider", "subprocess", "some-mcp==1.0.0"]}, "subprocess", note="uv's own option and one of its two values", name="--keyring-provider")
add("benign", "uv-keyring-provider", "env", {"command": "uvx", "args": ["some-mcp==1.0.0"], "env": {"UV_KEYRING_PROVIDER": "subprocess"}}, "subprocess", name="UV_KEYRING_PROVIDER")
add("benign", "python-keyring-backend", "env", env(PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring"), "keyring.backends.null.Keyring", note="the keyring library's own variable", name="PYTHON_KEYRING_BACKEND")
add("benign", "docker-add-host", "arg_flag_sep", {"command": "docker", "args": ["run", "-i", "--rm", "--add-host", "auth-server:192.168.10.20", IMG]}, "auth-server:192.168.10.20", note="a host mapping", name="--add-host")
add("benign", "docker-volume", "arg_flag_sep", {"command": "docker", "args": ["run", "-i", "--rm", "-v", "/home/dev/.aws/credentials:/root/.aws/credentials:ro", IMG]}, "/home/dev/.aws/credentials:/root/.aws/credentials:ro", note="a mount of a credentials file", name="-v")
add("benign", "docker-mount", "arg_flag_sep", {"command": "docker", "args": ["run", "-i", "--rm", "--mount", "type=bind,source=/run/secrets/api_token,target=/run/secrets/api_token,readonly", IMG]},
    "type=bind,source=/run/secrets/api_token,target=/run/secrets/api_token,readonly", name="--mount")
add("benign", "timestamp-or-duration", "env", env(TOKEN_EXPIRES_AT="2027-01-01T00:00:00Z"), "2027-01-01T00:00:00Z", name="TOKEN_EXPIRES_AT")
add("benign", "timestamp-or-duration", "env", env(SESSION_TIMEOUT_MS="86400000"), "86400000", name="SESSION_TIMEOUT_MS")
add("benign", "protocol-header", "header", http(**{"Access-Control-Request-Headers": "content-type, mcp-protocol-version"}), "content-type, mcp-protocol-version", note="a CORS header whose name contains 'header'", name="Access-Control-Request-Headers")
JWT_ANON = ".".join((base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("="),
                     base64.urlsafe_b64encode(json.dumps({"iss": "supabase", "ref": "abcdefghijklmnopqrst", "role": "anon", "iat": 1700000000, "exp": 2000000000}).encode()).decode().rstrip("="),
                     rnd(43, ALNUM + "-_", "anon")))
add("benign", "public-anon-jwt", "env", env(SUPABASE_ANON_KEY=JWT_ANON), JWT_ANON, note="a key that is public by design (role anon); label arguable", name="SUPABASE_ANON_KEY")
add("benign", "git-scp-url", "arg_flag_sep", args("--private-repo", "git@github.com:acme/internal-tools.git"), "git@github.com:acme/internal-tools.git", note="an scp-style repository address under an option that contains 'private'", name="--private-repo")
add("benign", "readme-placeholder", "env", env(SLACK_BOT_TOKEN="xoxb-your-bot-token", SLACK_TEAM_ID="T01234567"), "xoxb-your-bot-token", note="the placeholder of a published server's README", name="SLACK_BOT_TOKEN")


def build(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    manifest = []
    for case in CASES:
        root = out / case["id"]
        root.mkdir()
        (root / ".mcp.json").write_text(json.dumps({"mcpServers": case["servers"]}, indent=1), encoding="utf-8")
        manifest.append({k: v for k, v in case.items() if k != "servers"})
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(len(manifest), "cases:", sum(c["label"] == "credential" for c in manifest), "credential,", sum(c["label"] == "benign" for c in manifest), "benign")


if __name__ == "__main__":
    build(Path(sys.argv[1]))
