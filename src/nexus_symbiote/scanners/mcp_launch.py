"""Classify MCP launch commands statically, without executing anything.

Commands are matched by normalised basename. Common wrappers (``env``, ``sh -c``,
``cmd /c``, ``powershell -Command``, ``wsl`` and secret-injection runners such as
``op run --``) are unwrapped with bounded parsing. Each recognised package runner
reads only the options it documents, with a table of the options that take a
value, so a value, possibly a secret, is never taken for the package. A runner
whose arguments do not fit its grammar, or whose package is not a registry name,
is reported through ``Launch.unknown``; it is never guessed.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.core.hashing import extract_version_pin
from nexus_symbiote.scanners.base import sanitized_origin

MAX_WRAPPERS = 4
MAX_SCRIPT_CHARS = 4096
MAX_SCRIPT_TOKENS = 256
MAX_SPEC_CHARS = 2048

_EXECUTABLE_SUFFIXES = (".exe", ".cmd", ".bat", ".ps1", ".com")
_EXPANSION = re.compile(r"\$\{|\$[A-Za-z_(]|%[A-Za-z_][A-Za-z0-9_]*%|`")
_SHELL_OPERATOR = re.compile(r"[;&|<>()`\n\r]|\$\(")
_CMD_OPERATOR = re.compile(r"[&|<>^()\n\r]")
_POWERSHELL_OPERATOR = re.compile(r"[;&|<>(){}\[\]$`\n\r]|(?:^|\s)@")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=", re.ASCII)
_HOSTNAME = re.compile(r"[\w.-]+|[0-9a-f:.]+")
_COMMIT = re.compile(r"[0-9a-fA-F]{40}")

_NPM_NAME = r"(?:@[A-Za-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*"
_NPM_SPEC = re.compile(rf"({_NPM_NAME})(?:@(.+))?", re.ASCII | re.DOTALL)
_GITHUB_SHORTHAND = re.compile(r"[A-Za-z0-9][\w.-]*/[\w.-]+(?:#.*)?", re.ASCII | re.DOTALL)
_GIT_HOSTED = re.compile(r"(?:github|gitlab|bitbucket|gist):", re.IGNORECASE)
_LOCAL_PATH = re.compile(r"(?:\.{1,2}|~)(?:[\\/]|$)|[\\/]|[A-Za-z]:[\\/]|file:|link:", re.I)
_ARCHIVE = re.compile(r"\.(?:tgz|tar|tar\.gz|zip|whl)$", re.IGNORECASE)
_OCI = re.compile(
    r"(?P<repository>(?:[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]+)?/)?"
    r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?"
    r"(?:@sha256:(?P<digest>[0-9a-fA-F]{64}))?"
)
# A release tag names three version components; "1", "20" or "3.12" roll forward.
_RELEASE_TAG = re.compile(r"v?\d+\.\d+\.\d+(?:[-+._][0-9A-Za-z.+_-]*)?")
_JSR = re.compile(r"(@[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*)(?:@([^/]+))?(?:/.*)?", re.S)

INTERPRETER_INLINE_OPTIONS = {
    "node": ({"-e", "--eval", "-p", "--print"}, {"-r", "--require", "--import", "--loader"}),
    "python": ({"-c"}, set()),
}


@dataclass(frozen=True)
class Package:
    """A package a launcher fetches. ``spec`` is raw input and is never exported."""

    ecosystem: str
    spec: str
    name: str | None = None
    version: str | None = None
    pinned: bool = False
    pin: str | None = None
    origin: str | None = None

    @property
    def registry(self) -> bool:
        return self.ecosystem in {"npm", "pypi", "oci", "jsr", "golang"} and self.name is not None

    @property
    def identity(self) -> str:
        if self.registry:
            return f"{self.ecosystem}:{self.name}"
        if self.ecosystem in {"git", "url"} and self.origin:
            return f"{self.ecosystem}:{self.origin}"
        return self.ecosystem


@dataclass
class Launch:
    """What a declared command runs, without any argument value."""

    command: str | None = None
    launcher: str | None = None
    family: str | None = None
    runner: bool = False
    wrappers: list[str] = field(default_factory=list)
    executable: str | None = None
    packages: list[Package] = field(default_factory=list)
    unknown: str | None = None
    sources: list[tuple[str, str]] = field(default_factory=list)
    context: dict[str, int] = field(default_factory=dict)
    environment: list[tuple[str, str]] = field(default_factory=list)

    def mark(self, flag: str, count: int = 1) -> None:
        self.context[flag] = self.context.get(flag, 0) + count

    def fail(self, reason: str) -> None:
        if self.unknown is None:
            self.unknown = reason


def known_executable(name: str | None) -> bool:
    """A runner, wrapper or interpreter name from a fixed vocabulary, safe to export."""
    return name is not None and (
        name in _RUNNERS
        or name in _SHELLS
        or name in _INJECTORS
        or name in _INTERPRETERS
        or bool(re.fullmatch(r"(?:python|pypy)[0-9.]*|py|node(?:js)?", name))
    )


def normalize_command(value: str) -> str:
    """Basename for POSIX and Windows paths, without a Windows suffix, casefolded."""
    base = re.split(r"[\\/]", value.strip().strip("\"'"))[-1].casefold()
    for suffix in _EXECUTABLE_SUFFIXES:
        if base.endswith(suffix) and len(base) > len(suffix):
            return base[: -len(suffix)]
    return base


def expands(value: str) -> bool:
    """Whether a value depends on environment, input or command substitution."""
    return bool(_EXPANSION.search(value))


def origin(url: str) -> str | None:
    """Scheme, host and port of a URL; None when it has none or its host is ambiguous."""
    if expands(url):
        return None
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if "\\" in parsed.netloc or not hostname or not _HOSTNAME.fullmatch(hostname):
            return None
    except ValueError:
        return None
    exported = sanitized_origin(url)
    return None if exported == "[redacted]" else exported


def _split_script(script: str, operators: re.Pattern[str] = _SHELL_OPERATOR) -> list[str] | None:
    """Words of a simple command; None for anything a shell would do more with."""
    if len(script) > MAX_SCRIPT_CHARS or operators.search(script):
        return None
    try:
        words = shlex.split(script, posix=True)
    except ValueError:
        return None
    return words if 0 < len(words) <= MAX_SCRIPT_TOKENS else None


@dataclass(frozen=True)
class _Options:
    flags: frozenset[str] = frozenset()
    values: frozenset[str] = frozenset()
    value_patterns: tuple[re.Pattern[str], ...] = ()
    flag_patterns: tuple[re.Pattern[str], ...] = ()
    combined: bool = False
    boolean_values: bool = False


def _table(
    flags: str = "",
    values: str = "",
    *,
    value_patterns: tuple[str, ...] = (),
    flag_patterns: tuple[str, ...] = (),
    combined: bool = False,
    boolean_values: bool = False,
) -> _Options:
    return _Options(
        frozenset(flags.split()),
        frozenset(values.split()),
        tuple(re.compile(pattern) for pattern in value_patterns),
        tuple(re.compile(pattern) for pattern in flag_patterns),
        combined,
        boolean_values,
    )


def _scan(tokens: list[str], table: _Options) -> tuple[list[tuple[str, str | None]], int] | None:
    """Options before the first positional word; None when one is not in the table."""
    seen: list[tuple[str, str | None]] = []
    index = 0
    while index < len(tokens):
        word = tokens[index]
        if word == "--":
            return seen, index + 1
        if not word.startswith("-") or word == "-":
            return seen, index
        name, equals, attached = word.partition("=")
        takes_value = name in table.values or any(
            pattern.fullmatch(name) for pattern in table.value_patterns
        )
        is_flag = name in table.flags or any(
            pattern.fullmatch(name) for pattern in table.flag_patterns
        )
        if takes_value:
            if not equals:
                if index + 1 >= len(tokens):
                    return None
                index += 1
                attached = tokens[index]
            seen.append((name, attached))
        elif is_flag and (
            not equals
            or any(pattern.fullmatch(name) for pattern in table.flag_patterns)
            or (table.boolean_values and attached.lower() in {"true", "false", "1", "0"})
        ):
            seen.append((name, attached if equals else None))
        elif table.combined and not word.startswith("--"):
            consumed = _combined(word, tokens, index, table, seen)
            if consumed is None:
                return None
            index = consumed
        else:
            return None
        index += 1
    return seen, len(tokens)


def _combined(
    word: str,
    tokens: list[str],
    index: int,
    table: _Options,
    seen: list[tuple[str, str | None]],
) -> int | None:
    letters = word[1:]
    for position, letter in enumerate(letters):
        option = "-" + letter
        if option in table.flags:
            seen.append((option, None))
            continue
        if option not in table.values:
            return None
        rest = letters[position + 1 :]
        if rest:
            seen.append((option, rest.removeprefix("=")))
            return index
        if index + 1 >= len(tokens):
            return None
        seen.append((option, tokens[index + 1]))
        return index + 1
    return index


def _git(spec: str) -> Package:
    """A git source is pinned only by a full 40-hexadecimal commit."""
    body = spec[4:] if spec.lower().startswith("git+") else spec
    reference = ""
    try:
        if "#" in body:
            body, _, reference = body.partition("#")
            reference = reference.removeprefix("commit=")
        elif "@" in urlsplit(body).path:
            reference = urlsplit(body).path.rsplit("@", 1)[1]
    except ValueError:
        return Package("unknown", spec)
    source: str | None
    if _GIT_HOSTED.match(body):
        host = body.split(":", 1)[0].lower()
        source = "https://gist.github.com" if host == "gist" else f"https://{host}.com"
    elif body.startswith("git@"):
        host = body[4:].split(":", 1)[0]
        source = f"ssh://{host}" if _HOSTNAME.fullmatch(host) else None
    else:
        source = origin(body)
    pinned = bool(_COMMIT.fullmatch(reference))
    return Package(
        "git",
        spec,
        version=reference.lower() if pinned else None,
        pinned=pinned,
        pin="commit" if pinned else None,
        origin=source,
    )


def _plain(spec: str) -> bool:
    return (
        0 < len(spec) <= MAX_SPEC_CHARS
        and not spec.isspace()
        and not any(char in spec for char in "\r\n\x00")
        and not expands(spec)
    )


def npm_spec(spec: str) -> Package:
    """An npm package spec: registry name and version, alias, git, URL or path."""
    if not _plain(spec):
        return Package("unknown", spec)
    lowered = spec.lower()
    if lowered.startswith(("git+", "git://", "git@", "ssh://")) or _GIT_HOSTED.match(spec):
        return _git(spec)
    if "://" in spec:
        return Package("url", spec, origin=origin(spec))
    if _LOCAL_PATH.match(spec) or _ARCHIVE.search(spec):
        return Package("path", spec)
    match = _NPM_SPEC.fullmatch(spec)
    if match is None:
        if _GITHUB_SHORTHAND.fullmatch(spec):
            return _git("github:" + spec)
        return Package("unknown", spec)
    name, reference = match.groups()
    if reference is None:
        return Package("npm", spec, name=name)
    if reference.startswith("npm:"):
        target = npm_spec(reference[4:])
        aliased = target.ecosystem == "npm" and "@npm:" not in reference[4:]
        return target if aliased else Package("unknown", spec)
    if reference.lower().startswith(("git+", "git://", "git@")) or _GIT_HOSTED.match(reference):
        return _git(reference)
    if "://" in reference:
        return Package("url", spec, origin=origin(reference))
    if _LOCAL_PATH.match(reference) or _ARCHIVE.search(reference):
        return Package("path", spec)
    if reference.startswith("workspace:"):
        return Package("path", spec)
    if "/" in reference:
        return _git("github:" + reference)
    version = extract_version_pin(f"{name}@{reference}", ecosystem="npm")
    return Package(
        "npm",
        spec,
        name=name,
        version=version,
        pinned=version is not None,
        pin="version" if version else None,
    )


def python_spec(spec: str, *, shorthand: bool = False) -> Package:
    """A PEP 508 requirement, uvx ``name@version`` shorthand, git URL, URL or path."""
    if not _plain(spec):
        return Package("unknown", spec)
    lowered = spec.lower()
    if lowered.startswith("git+"):
        return _git(spec)
    if "://" in spec and " @ " not in spec and "@ " not in spec:
        return Package("url", spec, origin=origin(spec))
    if _LOCAL_PATH.match(spec) or (_ARCHIVE.search(spec) and "://" not in spec):
        return Package("path", spec)
    reference = spec
    if shorthand and "@" in spec and " " not in spec:
        name, _, wanted = spec.rpartition("@")
        if wanted == "latest":
            reference = name
        else:
            try:
                Version(wanted)
            except InvalidVersion:
                return Package("unknown", spec)
            reference = f"{name}=={wanted}"
    try:
        requirement = Requirement(reference)
    except InvalidRequirement:
        return Package("unknown", spec)
    if requirement.url:
        url = requirement.url
        if url.lower().startswith("git+"):
            return _git(url)
        return Package(
            "path" if url.lower().startswith("file:") else "url", spec, origin=origin(url)
        )
    version = extract_version_pin(reference, ecosystem="python")
    return Package(
        "pypi",
        spec,
        name=str(canonicalize_name(requirement.name)),
        version=version,
        pinned=version is not None,
        pin="version" if version else None,
    )


def oci_spec(spec: str) -> Package:
    """An image is pinned only by a digest; a tag, even ``1.2.3``, can be moved."""
    if not _plain(spec) or spec.startswith("-"):
        return Package("unknown", spec)
    match = _OCI.fullmatch(spec)
    if match is None:
        return Package("unknown", spec)
    repository = match["repository"].lower()
    if match["digest"]:
        digest = "sha256:" + match["digest"].lower()
        return Package("oci", spec, name=repository, version=digest, pinned=True, pin="digest")
    tag = match["tag"]
    if tag and _RELEASE_TAG.fullmatch(tag):
        return Package("oci", spec, name=repository, version=tag, pin="tag")
    return Package("oci", spec, name=repository)


def jsr_spec(spec: str) -> Package:
    match = _JSR.fullmatch(spec) if _plain(spec) else None
    if match is None:
        return Package("unknown", spec)
    name, reference = match.groups()
    version = extract_version_pin(f"x@{reference}", ecosystem="npm") if reference else None
    return Package(
        "jsr",
        spec,
        name=name,
        version=version,
        pinned=version is not None,
        pin="version" if version else None,
    )


_NPM_SOURCE = frozenset({"--registry", "--userconfig", "--globalconfig", "--prefix", "-C"})
_SCOPED_REGISTRY = r"--@[a-z0-9][a-z0-9._-]*:registry"
_NPM_EXEC = _table(
    "-y --yes --no -n --no-yes -q --quiet -s --silent --ignore-existing --prefer-online"
    " --prefer-offline --offline --no-install --legacy-peer-deps --foreground-scripts"
    " --include-workspace-root --workspaces -ws --no-update-notifier --no-audit --no-fund"
    " --verbose -d -dd -ddd",
    "-p --package -c --call --registry --cache --userconfig --globalconfig --node-options"
    " --loglevel -w --workspace --prefix -C --tag --before --script-shell --shell",
    value_patterns=(_SCOPED_REGISTRY,),
)
_PNPM_DLX = _table(
    "-s --silent --reporter-hide-prefix",
    "--package --allow-build --reporter --registry --store-dir --cache-dir",
    value_patterns=(_SCOPED_REGISTRY,),
)
_YARN_DLX = _table("-q --quiet", "-p --package")
_BUNX = _table("--bun --silent --verbose --no-install", "-p --package")
_UV_GLOBAL = (
    "-q --quiet -v --verbose --offline --no-cache -n --native-tls --no-config --no-progress"
    " --no-env-file --refresh -U --upgrade --reinstall --no-build --no-sources --preview"
    " --compile-bytecode --no-python-downloads --no-managed-python --managed-python --isolated",
    "--cache-dir --directory --project --config-file --color --python-preference"
    " --allow-insecure-host --index --default-index --index-url -i --extra-index-url"
    " --find-links -f --index-strategy --keyring-provider --resolution --prerelease"
    " --exclude-newer --refresh-package --reinstall-package --upgrade-package -P"
    " --link-mode --config-setting -C --python -p --env-file",
)
_UV_TOOL_RUN = _table(
    _UV_GLOBAL[0],
    _UV_GLOBAL[1] + " --from --with --with-editable --with-requirements --constraints"
    " --overrides --build-constraints",
)
_UV_RUN = _table(
    _UV_GLOBAL[0] + " --no-project --no-sync --frozen --locked --all-extras --no-dev"
    " --only-dev --all-groups --no-default-groups --active --script -s --module -m"
    " --gui-script --no-editable --exact --all-packages",
    _UV_GLOBAL[1] + " --with --with-editable --with-requirements --extra --group --no-group"
    " --only-group --package",
)
_UV_SOURCE = frozenset(
    {"--index", "--default-index", "--index-url", "-i", "--extra-index-url", "--find-links", "-f"}
)
_PIPX_RUN = _table(
    "--no-cache --pypackages --path --system-site-packages -e --editable -v --verbose -q"
    " --quiet --fetch-missing-python --global",
    "--spec --python --pip-args -i --index-url --backend",
)
_PIP_SOURCE = frozenset(
    {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host"}
)
_DOCKER_FLAGS = (
    "-d --detach --disable-content-trust --init -i --interactive --no-healthcheck"
    " --oom-kill-disable --privileged -P --publish-all -q --quiet --read-only --rm"
    " --sig-proxy -t --tty --use-api-socket"
)
_DOCKER_VALUES = (
    "-a --attach --add-host --annotation --blkio-weight --blkio-weight-device --cap-add"
    " --cap-drop --cgroup-parent --cgroupns --cidfile --cpu-period --cpu-quota"
    " --cpu-rt-period --cpu-rt-runtime -c --cpu-shares --cpus --cpuset-cpus --cpuset-mems"
    " --device --device-cgroup-rule --device-read-bps --device-read-iops --device-write-bps"
    " --device-write-iops --dns --dns-option --dns-search --domainname --entrypoint -e --env"
    " --env-file --expose --gpus --group-add --health-cmd --health-interval --health-retries"
    " --health-start-interval --health-start-period --health-timeout -h --hostname --ip --ip6"
    " --ipc --isolation --kernel-memory -l --label --label-file --link --link-local-ip"
    " --log-driver --log-opt --mac-address -m --memory --memory-reservation --memory-swap"
    " --memory-swappiness --mount --name --network --net --network-alias --net-alias"
    " --oom-score-adj --pid --pids-limit --platform -p --publish --pull --restart --runtime"
    " --security-opt --shm-size --stop-signal --stop-timeout --storage-opt --sysctl --tmpfs"
    " --ulimit -u --user --userns --uts -v --volume --volume-driver --volumes-from -w --workdir"
)
_CONTAINER_RUN = {
    "docker": _table(_DOCKER_FLAGS, _DOCKER_VALUES, combined=True, boolean_values=True),
    "podman": _table(
        _DOCKER_FLAGS + " --replace --rmi --env-host --passwd --read-only-tmpfs --no-hosts"
        " --rootfs --unsetenv-all --tls-verify --http-proxy",
        _DOCKER_VALUES + " --pod --secret --uidmap --gidmap --subuidname --subgidname --arch"
        " --os --variant --authfile --cert-dir --creds --decryption-key --image-volume"
        " --passwd-entry --group-entry --personality --preserve-fds --requires --sdnotify"
        " --seccomp-policy --timeout --tz --umask --unsetenv --chrootdirs --detach-keys"
        " --env-merge --hostuser --pidfile --systemd --retry --retry-delay",
        combined=True,
        boolean_values=True,
    ),
    "nerdctl": _table(
        _DOCKER_FLAGS + " --insecure-registry",
        _DOCKER_VALUES + " --namespace --snapshotter --cosign-key --verify",
        combined=True,
        boolean_values=True,
    ),
}
_CONTAINER_GLOBAL = {
    "docker": _table(
        "-D --debug --tls --tlsverify",
        "-c --context -H --host --config -l --log-level --tlscacert --tlscert --tlskey",
    ),
    "podman": _table(
        "-r --remote --syslog",
        "--url --connection -c --identity --root --runroot --storage-driver --storage-opt"
        " --cgroup-manager --events-backend --log-level --tmpdir --runtime --module",
    ),
    "nerdctl": _table(
        "--debug --debug-full --insecure-registry --experimental",
        "-n --namespace -a -H --address --snapshotter --storage-driver --cni-path"
        " --data-root --hosts-dir --host-gateway-ip --cgroup-manager",
    ),
}
_DENO_RUN = _table(
    "-A --allow-all -q --quiet --no-check --no-lock --frozen --cached-only --no-remote"
    " --no-npm --no-config --no-prompt --unstable -R -W -N -E -S -P",
    "-c --config --import-map --cert --location --seed --ext --preload --require",
    flag_patterns=(
        r"--(?:allow|deny)-[a-z-]+",
        r"--unstable-[a-z-]+",
        r"--(?:reload|lock|node-modules-dir|env-file|inspect|inspect-brk|inspect-wait"
        r"|allow-scripts|check|watch|watch-hmr|v8-flags|frozen|cached-only)",
        r"-r",
    ),
)
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish"})
_INTERPRETERS = frozenset(
    {"cmd", "powershell", "pwsh", "wsl", "env", "exec", "nohup", "java", "ruby", "perl", "php"}
)
_INJECTORS = frozenset({"op", "doppler", "infisical", "dotenvx", "aws-vault", "with-secrets"})


def _command_words(command: str) -> list[str] | None:
    """A command that is a path stays one word; a command line is split like a shell."""
    stripped = command.strip()
    if stripped[:1] in {'"', "'"}:
        close = stripped.find(stripped[0], 1)
        if close < 0:
            return None
        tail = stripped[close + 1 :]
        words = _split_script(tail) if tail.strip() else []
        return None if words is None else [stripped[1:close], *words]
    last = re.split(r"[\\/]", stripped)[-1]
    if not any(char.isspace() for char in stripped) or (
        re.match(r"[A-Za-z]:[\\/]", stripped) and not any(char.isspace() for char in last)
    ):
        return [stripped]
    return _split_script(stripped)


def analyze(command: str, args: list[str]) -> Launch:
    """Classify a declared command and its arguments, recording no argument value."""
    launch = Launch()
    if not command:
        return launch
    words = _command_words(command)
    if words is None:
        launch.command = "[redacted-command]"
        launch.launcher = "shell"
        launch.mark("inline_shell_code")
        launch.fail("command line is not a simple command")
        return launch
    if len(words) > 1:
        launch.wrappers.append("command-line")
    tokens = [*words, *args]
    launch.command = normalize_command(tokens[0])
    for _ in range(MAX_WRAPPERS + 1):
        inner = _unwrap(tokens, launch)
        if launch.unknown is not None:
            return launch
        if inner is None:
            _classify(tokens, launch)
            return launch
        tokens = inner
    launch.fail("wrapper nesting limit")
    return launch


def _unwrap(tokens: list[str], launch: Launch) -> list[str] | None:
    name = normalize_command(tokens[0])
    rest = tokens[1:]
    if name == "env":
        return _unwrap_env(rest, launch)
    if name in _SHELLS:
        return _unwrap_shell(name, rest, launch)
    if name == "cmd":
        return _unwrap_cmd(rest, launch)
    if name in {"powershell", "pwsh"}:
        return _unwrap_powershell(rest, launch)
    if name == "wsl":
        return _unwrap_wsl(rest, launch)
    if name in {"exec", "nohup"} and rest:
        launch.wrappers.append(name)
        return rest
    if name in _INJECTORS:
        if "--" not in rest or rest.index("--") + 1 >= len(rest):
            launch.launcher = name
            launch.fail(f"{name} wrapper without '--' before the command")
            return None
        launch.wrappers.append(name)
        return rest[rest.index("--") + 1 :]
    return None


def _unwrap_env(rest: list[str], launch: Launch) -> list[str] | None:
    index = 0
    while index < len(rest):
        word = rest[index]
        if word in {"-i", "-", "--ignore-environment", "-0", "--null", "-v", "--debug", "--"}:
            index += 1
        elif word in {"-u", "-C", "--unset", "--chdir"}:
            index += 2
        elif word.startswith(("--unset=", "--chdir=")):
            index += 1
        elif word in {"-S", "--split-string"} or word.startswith(("-S", "--split-string=")):
            if word in {"-S", "--split-string"}:
                if index + 1 >= len(rest):
                    break
                value, skip = rest[index + 1], 2
            elif word.startswith("--split-string="):
                value, skip = word.partition("=")[2], 1
            else:
                value, skip = word[2:], 1
            words = _split_script(value)
            if words is None:
                launch.fail("env -S value is not a simple command")
                return None
            rest = [*words, *rest[index + skip :]]
            index = 0
        elif word.startswith("-"):
            launch.fail("unrecognised env option")
            return None
        elif _ASSIGNMENT.match(word):
            name, _, value = word.partition("=")
            launch.environment.append((name, value))
            index += 1
        else:
            launch.wrappers.append("env")
            return rest[index:]
    launch.fail("env without a command")
    return None


def _script_words(words: list[str], launch: Launch) -> list[str] | None:
    while words and _ASSIGNMENT.match(words[0]):
        name, _, value = words[0].partition("=")
        launch.environment.append((name, value))
        words = words[1:]
    if words and words[0] == "exec":
        words = words[1:]
    return words or None


def _unwrap_shell(name: str, rest: list[str], launch: Launch) -> list[str] | None:
    index = 0
    while index < len(rest):
        word = rest[index]
        if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", word):
            break
        if word in {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}:
            index += 2
        elif word.startswith(("-", "+")):
            index += 1
        else:
            # A script file: the shell runs local code, which the inventory does not read.
            launch.launcher = "local"
            launch.executable = name
            return None
    else:
        launch.launcher = "local"
        launch.executable = name
        return None
    launch.launcher = "shell"
    launch.mark("shell_wrapper")
    if index + 1 >= len(rest):
        launch.fail("shell -c without a script")
        return None
    words = _split_script(rest[index + 1])
    words = _script_words(words, launch) if words is not None else None
    if words is None:
        launch.mark("inline_shell_code")
        launch.fail("inline shell script")
        return None
    launch.wrappers.append(f"{name} -c")
    return words


def _unwrap_cmd(rest: list[str], launch: Launch) -> list[str] | None:
    index = 0
    while index < len(rest) and rest[index].lower() not in {"/c", "/k"}:
        if not re.fullmatch(r"/[a-z](?::\w+)?", rest[index].lower()):
            launch.launcher = "local"
            launch.executable = "cmd"
            return None
        index += 1
    launch.launcher = "shell"
    launch.mark("shell_wrapper")
    remainder = rest[index + 1 :]
    if len(remainder) == 1 and any(char.isspace() for char in remainder[0]):
        words = _split_script(remainder[0], _CMD_OPERATOR)
    elif remainder and not any(_CMD_OPERATOR.search(word) for word in remainder):
        words = remainder
    else:
        words = None
    if not words:
        launch.mark("inline_shell_code")
        launch.fail("cmd /c command line is not a simple command")
        return None
    launch.wrappers.append("cmd /c")
    return words


def _unwrap_powershell(rest: list[str], launch: Launch) -> list[str] | None:
    index = 0
    with_value = {
        "-executionpolicy",
        "-ep",
        "-ex",
        "-windowstyle",
        "-w",
        "-inputformat",
        "-outputformat",
        "-configurationname",
        "-workingdirectory",
        "-wd",
        "-version",
    }
    while index < len(rest):
        word = rest[index].lower()
        if word in {"-c", "-command"} or (word.startswith("-com") and "-command".startswith(word)):
            break
        if word in {"-file", "-f"}:
            launch.launcher = "local"
            launch.executable = "powershell"
            return None
        if word in with_value:
            index += 2
        elif word.startswith("-") and not word.startswith(("-e", "-enc")):
            index += 1
        else:
            index = len(rest)
    launch.launcher = "shell"
    launch.mark("shell_wrapper")
    script = " ".join(rest[index + 1 :])
    words = _split_script(script, _POWERSHELL_OPERATOR) if script else None
    if words is None:
        launch.mark("inline_shell_code")
        launch.fail("PowerShell command is not a simple command")
        return None
    launch.wrappers.append("powershell -Command")
    return words


def _unwrap_wsl(rest: list[str], launch: Launch) -> list[str] | None:
    index = 0
    direct = False
    while index < len(rest):
        word = rest[index]
        if word in {"-d", "--distribution", "-u", "--user", "--cd", "--shell-type"}:
            index += 2
        elif word in {"-e", "--exec"}:
            direct = True
            index += 1
            break
        elif word in {"--system", "--"}:
            index += 1
            if word == "--":
                break
        elif word.startswith("-"):
            launch.fail("unrecognised wsl option")
            return None
        else:
            break
    words = rest[index:]
    if not words or (not direct and any(_SHELL_OPERATOR.search(word) for word in words)):
        launch.mark("inline_shell_code")
        launch.fail("wsl command line is not a simple command")
        return None
    launch.wrappers.append("wsl")
    return words


def _classify(tokens: list[str], launch: Launch) -> None:
    name = normalize_command(tokens[0])
    rest = tokens[1:]
    launch.executable = name
    if expands(name) or not name:
        launch.launcher = "unknown"
        launch.fail("command depends on the environment")
        return
    handler = _RUNNERS.get(name)
    if handler is not None:
        launch.runner = True
        handler(name, rest, launch)
        return
    family = "python" if re.fullmatch(r"python[0-9.]*|py|pypy[0-9.]*", name) else name
    inline, preload = INTERPRETER_INLINE_OPTIONS.get(family, (set(), set()))
    for word in rest:
        option = word.partition("=")[0]
        if option in inline:
            launch.mark("inline_code")
        elif option in preload:
            launch.mark("preload_module")
        elif not word.startswith("-"):
            break
    launch.launcher = "local"


def _package_runner(
    rest: list[str], launch: Launch, table: _Options, package_options: set[str]
) -> None:
    """npx-style grammar: packages from -p/--package, else the first word."""
    scanned = _scan(rest, table)
    if scanned is None:
        launch.fail(f"unrecognised {launch.launcher} option")
        return
    options, position = scanned
    specs: list[str] = []
    for option, value in options:
        if option in package_options and value is not None:
            specs.append(value)
        elif option in {"-c", "--call"}:
            launch.fail(f"{launch.launcher} --call runs a shell command")
            return
        elif (option in _NPM_SOURCE or option.endswith(":registry")) and value is not None:
            launch.sources.append((option, value))
    if not specs:
        if position >= len(rest):
            launch.fail("no package named")
            return
        specs = [rest[position]]
    elif position < len(rest):
        launch.executable = normalize_command(rest[position])
    launch.packages.extend(npm_spec(spec) for spec in specs)


def _npx(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "npx", "npm"
    _package_runner(rest, launch, _NPM_EXEC, {"-p", "--package"})


def _subcommand(
    rest: list[str], table: _Options, launch: Launch
) -> tuple[str, list[str], list[tuple[str, str | None]]] | None:
    scanned = _scan(rest, table)
    if scanned is None or scanned[1] >= len(rest):
        launch.fail(f"unrecognised {launch.launcher} invocation")
        return None
    options, position = scanned
    return rest[position], rest[position + 1 :], options


_NPM_LOCAL = frozenset(
    {"run", "run-script", "rum", "urn", "start", "test", "t", "tst", "restart", "stop"}
)


def _npm(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "npm", "npm"
    found = _subcommand(rest, _NPM_EXEC, launch)
    if found is None:
        return
    subcommand, remainder, options = found
    launch.sources.extend(
        (option, value)
        for option, value in options
        if (option in _NPM_SOURCE or option.endswith(":registry")) and value is not None
    )
    if subcommand in {"exec", "x"}:
        launch.launcher = "npm exec"
        _package_runner(remainder, launch, _NPM_EXEC, {"-p", "--package"})
    elif subcommand in _NPM_LOCAL:
        launch.launcher = f"npm {subcommand}"
    else:
        launch.fail("npm subcommand fetches or installs packages")


def _pnpm(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "pnpm", "npm"
    if name == "pnpx":
        launch.launcher = "pnpm dlx"
        _package_runner(rest, launch, _PNPM_DLX, {"--package"})
        return
    found = _subcommand(rest, _table(), launch)
    if found is None:
        return
    subcommand, remainder, _ = found
    if subcommand == "dlx":
        launch.launcher = "pnpm dlx"
        _package_runner(remainder, launch, _PNPM_DLX, {"--package"})
    elif subcommand in {"create", "add", "install", "i", "update", "up"}:
        launch.fail("pnpm subcommand fetches or installs packages")
    else:
        launch.launcher = f"pnpm {subcommand}" if subcommand in {"exec", "run", "start"} else "pnpm"


def _yarn(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "yarn", "yarn"
    found = _subcommand(rest, _table(), launch)
    if found is None:
        return
    subcommand, remainder, _ = found
    if subcommand == "dlx":
        launch.launcher = "yarn dlx"
        _package_runner(remainder, launch, _YARN_DLX, {"-p", "--package"})
    elif subcommand in {"create", "add", "install", "global", "up", "upgrade"}:
        launch.fail("yarn subcommand fetches or installs packages")


def _bun(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "bun", "bun"
    if name == "bunx":
        launch.launcher = "bunx"
        _package_runner(rest, launch, _BUNX, {"-p", "--package"})
        return
    found = _subcommand(rest, _table("--bun --silent"), launch)
    if found is None:
        return
    subcommand, remainder, _ = found
    if subcommand == "x":
        launch.launcher = "bun x"
        _package_runner(remainder, launch, _BUNX, {"-p", "--package"})
    elif subcommand in {"create", "add", "install", "i", "update", "upgrade", "link", "pm"}:
        launch.fail("bun subcommand fetches or installs packages")


def _python_runner(
    rest: list[str],
    launch: Launch,
    table: _Options,
    *,
    primary: str | None,
    extras: set[str],
    paths: set[str],
    shorthand: bool,
) -> list[tuple[str, str | None]] | None:
    scanned = _scan(rest, table)
    if scanned is None:
        launch.fail(f"unrecognised {launch.launcher} option")
        return None
    options, position = scanned
    declared: str | None = None
    with_specs: list[str] = []
    for option, value in options:
        if value is None:
            continue
        if option == primary:
            declared = value
        elif option in extras:
            with_specs.append(value)
        elif option in paths:
            launch.packages.append(Package("path", value))
        elif option in _UV_SOURCE or option == "--config-file":
            launch.sources.append((option, value))
    if primary is not None:
        if declared is None and position >= len(rest):
            launch.fail("no package named")
            return None
        if declared is not None:
            launch.packages.insert(0, python_spec(declared))
            if position < len(rest):
                launch.executable = normalize_command(rest[position])
        else:
            launch.packages.insert(0, python_spec(rest[position], shorthand=shorthand))
    elif position < len(rest):
        launch.executable = normalize_command(rest[position])
    launch.packages.extend(python_spec(spec) for spec in with_specs)
    return options


def _uvx(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "uvx", "uv-tool"
    _python_runner(
        rest,
        launch,
        _UV_TOOL_RUN,
        primary="--from",
        extras={"--with"},
        paths={"--with-editable", "--with-requirements", "--constraints", "--overrides"},
        shorthand=True,
    )


def _uv(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher = "uv"
    found = _subcommand(rest, _table(*_UV_GLOBAL), launch)
    if found is None:
        return
    subcommand, remainder, _ = found
    if subcommand == "tool" and remainder[:1] == ["run"]:
        launch.launcher, launch.family = "uv tool run", "uv-tool"
        _python_runner(
            remainder[1:],
            launch,
            _UV_TOOL_RUN,
            primary="--from",
            extras={"--with"},
            paths={"--with-editable", "--with-requirements", "--constraints", "--overrides"},
            shorthand=True,
        )
    elif subcommand == "run":
        launch.launcher, launch.family = "uv run", "uv-project"
        _python_runner(
            remainder,
            launch,
            _UV_RUN,
            primary=None,
            extras={"--with"},
            paths={"--with-editable", "--with-requirements"},
            shorthand=False,
        )
    else:
        launch.fail("uv subcommand is not a supported runner")


def _pipx(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "pipx run", "pip"
    if rest[:1] != ["run"]:
        launch.fail("pipx subcommand is not a supported runner")
        return
    options = _python_runner(
        rest[1:],
        launch,
        _PIPX_RUN,
        primary="--spec",
        extras=set(),
        paths=set(),
        shorthand=False,
    )
    if options is None:
        return
    for option, value in options:
        if option == "--pip-args" and value is not None:
            words = _split_script(value)
            if words is None:
                launch.fail("pipx --pip-args value is not a simple option list")
                return
            for index, word in enumerate(words):
                option_name, equals, attached = word.partition("=")
                if option_name in _PIP_SOURCE:
                    found = (
                        attached if equals else (words[index + 1] if index + 1 < len(words) else "")
                    )
                    launch.sources.append((option_name, found))
        elif option in {"--path", "-e", "--editable"} and launch.packages:
            launch.packages[0] = Package("path", launch.packages[0].spec)


_DANGEROUS_CAPABILITIES = frozenset(
    {"all", "sys_admin", "net_admin", "sys_ptrace", "sys_module", "dac_read_search", "sys_rawio"}
)
_SOCKETS = ("docker.sock", "podman.sock", "containerd.sock", "docker_engine")
_BROAD = re.compile(
    r"(?:~|\$\{?home\}?|%userprofile%|/home|/users|/root|/etc|/var|/proc|/sys|/dev|/boot|/usr"
    r"|[a-z]:[\\/]users)(?:[\\/][^\\/]*)?[\\/]?$",
    re.IGNORECASE,
)


def _host_source(spec: str, *, mount: bool) -> str | None:
    if mount:
        fields = dict(part.partition("=")[::2] for part in spec.split(","))
        if fields.get("type", "volume") != "bind":
            return None
        return fields.get("source") or fields.get("src") or None
    source = spec.split(":", 1)[0]
    if re.match(r"[A-Za-z]:[\\/]", spec):
        source = spec[:2] + spec[2:].split(":", 1)[0]
    return (
        source
        if source.startswith(("/", "~", "$", "%", "\\")) or re.match(r"[A-Za-z]:", source)
        else None
    )


def _container_context(options: list[tuple[str, str | None]], launch: Launch) -> None:
    for option, value in options:
        text = (value or "").strip().lower()
        if option == "--privileged" and text in {"", "true", "1"}:
            launch.mark("privileged")
        elif option in {"--network", "--net", "--pid", "--ipc", "--uts", "--userns", "--cgroupns"}:
            if text == "host":
                launch.mark("host_namespaces")
        elif option == "--cap-add":
            launch.mark("added_capabilities")
            if text.removeprefix("cap_") in _DANGEROUS_CAPABILITIES:
                launch.mark("dangerous_capabilities")
        elif option == "--device":
            launch.mark("devices")
        elif option == "--security-opt" and re.search(
            r"unconfined|disable|no-new-privileges[:=]false", text
        ):
            launch.mark("security_options_disabled")
        elif option in {"-v", "--volume", "--mount"} and value:
            source = _host_source(value, mount=option == "--mount")
            if source is None:
                continue
            launch.mark("host_mounts")
            normalized = source.rstrip("/\\") or "/"
            if normalized in {"/", "\\"} or re.fullmatch(r"[A-Za-z]:[\\/]?", source):
                launch.mark("host_root_mount")
            elif source.lower().endswith(_SOCKETS):
                launch.mark("runtime_socket_mount")
            elif _BROAD.fullmatch(source):
                launch.mark("broad_host_mount")
        elif option == "--entrypoint":
            launch.mark("entrypoint_override")


def _container(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = name, "oci"
    scanned = _scan(rest, _CONTAINER_GLOBAL[name])
    if scanned is None or scanned[1] >= len(rest):
        launch.fail(f"unrecognised {name} invocation")
        return
    _, position = scanned
    if rest[position] == "run":
        run = rest[position + 1 :]
    elif rest[position] == "container" and rest[position + 1 : position + 2] == ["run"]:
        run = rest[position + 2 :]
    else:
        launch.fail(f"{name} subcommand does not start an image")
        return
    launch.launcher = f"{name} run"
    parsed = _scan(run, _CONTAINER_RUN[name])
    if parsed is None or parsed[1] >= len(run):
        launch.fail(f"unrecognised {name} run option")
        return
    options, image = parsed
    _container_context(options, launch)
    launch.packages.append(oci_spec(run[image]))


def _deno(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "deno run", "deno"
    if rest[:1] in (["run"], ["serve"]):
        rest = rest[1:]
    elif rest[:1] == ["task"]:
        launch.launcher = "deno task"
        return
    elif not rest or rest[0].startswith("-") or rest[0] in {"x", "install", "add", "compile"}:
        launch.fail("deno subcommand is not a supported runner")
        return
    scanned = _scan(rest, _DENO_RUN)
    if scanned is None or scanned[1] >= len(rest):
        launch.fail("unrecognised deno run option")
        return
    script = rest[scanned[1]]
    if script.startswith("npm:"):
        body = script[4:]
        scoped = body.startswith("@")
        parts = body.split("/")
        package = "/".join(parts[:2]) if scoped else parts[0]
        launch.packages.append(npm_spec(package))
    elif script.startswith("jsr:"):
        launch.packages.append(jsr_spec(script[4:]))
    elif "://" in script and not script.lower().startswith("file:"):
        launch.packages.append(Package("url", script, origin=origin(script)))
    elif expands(script):
        launch.fail("deno script depends on the environment")


def _flags(names: str) -> str:
    return " ".join(f"{prefix}{name}" for name in names.split() for prefix in ("-", "--"))


_GO_RUN = _table(
    _flags("a race msan asan cover v x n work trimpath linkshared modcacherw"),
    _flags(
        "C p covermode coverpkg asmflags buildmode buildvcs compiler gccgoflags gcflags"
        " installsuffix ldflags mod modfile overlay pgo pkgdir tags toolexec exec"
    ),
    boolean_values=True,
)
_GO_VERSION = re.compile(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?")


def go_spec(spec: str) -> Package:
    """``module/path@version``: an exact semantic or pseudo-version is a pin."""
    if not _plain(spec) or spec.count("@") != 1:
        return Package("unknown", spec)
    path, _, version = spec.partition("@")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~/-]*", path):
        return Package("unknown", spec)
    exact = bool(_GO_VERSION.fullmatch(version))
    return Package(
        "golang",
        spec,
        name=path,
        version=version if exact else None,
        pinned=exact,
        pin="version" if exact else None,
    )


def _go(name: str, rest: list[str], launch: Launch) -> None:
    launch.launcher, launch.family = "go", "go"
    if rest[:1] != ["run"]:
        launch.fail("go subcommand is not a supported runner")
        return
    launch.launcher = "go run"
    scanned = _scan(rest[1:], _GO_RUN)
    if scanned is None or scanned[1] >= len(rest) - 1:
        launch.fail("unrecognised go run option")
        return
    target = rest[1 + scanned[1]]
    if "@" in target:
        launch.packages.append(go_spec(target))


_RUNNERS: dict[str, Callable[[str, list[str], Launch], None]] = {
    "npx": _npx,
    "npm": _npm,
    "pnpm": _pnpm,
    "pnpx": _pnpm,
    "yarn": _yarn,
    "bunx": _bun,
    "bun": _bun,
    "uvx": _uvx,
    "uv": _uv,
    "pipx": _pipx,
    "docker": _container,
    "podman": _container,
    "nerdctl": _container,
    "deno": _deno,
    "go": _go,
}
