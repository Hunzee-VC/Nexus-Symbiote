"""Parse MCP server launch commands into package identity and pinning facts (``spec/collectors.md`` mcp-config).

``npx -y some-server`` resolves *whatever is newest* at every start: the classic rug-pull channel
(``SYM-MCP-002``; postmark-mcp, Sep 2025). This module answers, without executing anything: which ecosystem
and package a launcher fetches, whether the reference is immutable, and why not when it floats.

Pinning rules (``spec/agentbom-profile.md`` §3.3 ``package.floating``):

* npm / PyPI / NuGet / Go: an exact version is pinned (registries forbid re-publishing a version); ranges,
  dist-tags (``latest``, ``next``) and missing versions float.
* OCI: only a ``@sha256:`` digest pins; every tag (including ``1.2.3``) is mutable.
* git references pin only to a full 40-hex commit; URLs and tarballs float.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Final

from packageurl import PackageURL

from symbiote.model.enums import Launcher

__all__ = ["LaunchFacts", "parse_launch"]

_EXACT_SEMVER: Final = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_PEP440_EXACT: Final = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$")
_HEX40: Final = re.compile(r"^[0-9a-f]{40}$")
_OCI_DIGEST: Final = re.compile(r"@(sha256:[0-9a-f]{64})$")


@dataclass(frozen=True, slots=True)
class LaunchFacts:
    """What a server command line would fetch and run."""

    launcher: Launcher
    launcher_detail: str
    ecosystem: str | None = None
    package_name: str | None = None
    version_spec: str | None = None
    purl: str | None = None
    pinned: bool = False
    float_reason: str | None = None
    digest: str | None = None
    risky_flags: tuple[str, ...] = ()
    local_path: str | None = None

    @property
    def floating(self) -> bool:
        """True when a registry package is referenced without an immutable version or digest."""
        return self.package_name is not None and not self.pinned


def _basename(command: str) -> str:
    name = PureWindowsPath(command).name if "\\" in command else PurePosixPath(command).name
    lowered = name.lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if lowered.endswith(suffix):
            return lowered[: -len(suffix)]
    return lowered


# --------------------------------------------------------------------------------------------- npm


def _split_npm_spec(spec: str) -> tuple[str, str | None]:
    if spec.startswith("npm:"):
        spec = spec[4:]
    if spec.startswith("@"):
        scope_end = spec.find("/")
        at = spec.find("@", scope_end if scope_end != -1 else 1)
        return (spec, None) if at == -1 else (spec[:at], spec[at + 1 :] or None)
    name, sep, version = spec.partition("@")
    return name, (version or None) if sep else None


def _npm_facts(spec: str, detail: str) -> LaunchFacts:
    if spec.startswith(("./", "../", "/", "file:")) or re.match(r"^[A-Za-z]:[\\/]", spec):
        return LaunchFacts(Launcher.NPX, detail, local_path=spec)
    if spec.startswith(("github:", "git+", "git:", "gitlab:", "bitbucket:")):
        ref = spec.rsplit("#", 1)[1] if "#" in spec else None
        pinned = bool(ref and _HEX40.match(ref.lower()))
        return LaunchFacts(
            Launcher.NPX,
            detail,
            ecosystem="npm",
            package_name=spec.split("#", 1)[0],
            version_spec=ref,
            pinned=pinned,
            float_reason=None if pinned else "git-ref",
        )
    if spec.startswith(("http://", "https://")):
        return LaunchFacts(
            Launcher.NPX, detail, ecosystem="npm", package_name=spec, pinned=False, float_reason="url"
        )
    name, version = _split_npm_spec(spec)
    namespace, _, short = name.rpartition("/")
    if version is None:
        reason: str | None = "no-version"
    elif _EXACT_SEMVER.match(version):
        reason = None
    elif re.match(r"^[A-Za-z][A-Za-z0-9._-]*$", version):
        reason = f"dist-tag:{version}"
    else:
        reason = "range"
    purl = PackageURL(
        type="npm",
        namespace=namespace or None,
        name=short,
        version=version.lstrip("v") if version and not reason else None,
    ).to_string()
    return LaunchFacts(
        Launcher.NPX,
        detail,
        ecosystem="npm",
        package_name=name,
        version_spec=version,
        purl=purl,
        pinned=reason is None,
        float_reason=reason,
    )


_NPX_VALUE_FLAGS: Final = frozenset(
    {
        "-p",
        "--package",
        "-c",
        "--call",
        "--registry",
        "--prefix",
        "--cache",
        "--userconfig",
        "--node-options",
        "-w",
        "--workspace",
    }
)


def _parse_npx(args: Sequence[str], detail: str) -> LaunchFacts:
    packages: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            i += 1
            break
        if arg.startswith("--package=") or arg.startswith("-p="):
            packages.append(arg.split("=", 1)[1])
        elif arg in ("-p", "--package") and i + 1 < len(args):
            packages.append(args[i + 1])
            i += 1
        elif arg in _NPX_VALUE_FLAGS and i + 1 < len(args):
            i += 1
        elif not arg.startswith("-"):
            break
        i += 1
    if packages:
        return _npm_facts(packages[0], detail)
    if i < len(args):
        return _npm_facts(args[i], detail)
    return LaunchFacts(Launcher.NPX, detail)


# --------------------------------------------------------------------------------------------- PyPI

_UVX_VALUE_FLAGS: Final = frozenset(
    {
        "--with",
        "--with-editable",
        "--with-requirements",
        "--python",
        "-p",
        "--index",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "-f",
        "--default-index",
        "--cache-dir",
        "--directory",
        "--project",
        "--config-file",
        "--constraints",
        "-c",
        "--overrides",
        "--build-constraints",
        "--env-file",
    }
)


def _pypi_facts(spec: str, detail: str, launcher: Launcher) -> LaunchFacts:
    if spec.startswith(("git+", "https://", "http://", "file:", "./", "/")):
        ref = spec.rsplit("@", 1)[1] if spec.startswith("git+") and "@" in spec.split("://", 1)[-1] else None
        pinned = bool(ref and _HEX40.match(ref.lower()))
        return LaunchFacts(
            launcher,
            detail,
            ecosystem="pypi",
            package_name=spec.split("@", 1)[0] if spec.startswith("git+") else spec,
            version_spec=ref,
            pinned=pinned,
            float_reason=None if pinned else ("git-ref" if spec.startswith("git+") else "url"),
        )
    match = re.match(
        r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?(?P<rest>.*)$", spec.strip()
    )
    if not match:
        return LaunchFacts(launcher, detail, ecosystem="pypi", package_name=spec, float_reason="unparsed")
    name = match.group("name")
    rest = match.group("rest").strip()
    version: str | None = None
    reason: str | None
    if rest.startswith("=="):
        version = rest[2:].strip()
        reason = None if _PEP440_EXACT.match(version) else "range"
    elif rest.startswith("@"):
        version = rest[1:].strip()
        reason = None if _PEP440_EXACT.match(version) else f"dist-tag:{version}"
    elif rest:
        version = rest
        reason = "range"
    else:
        reason = "no-version"
    purl = PackageURL(
        type="pypi", name=name.lower().replace("_", "-"), version=version if reason is None else None
    ).to_string()
    return LaunchFacts(
        launcher,
        detail,
        ecosystem="pypi",
        package_name=name,
        version_spec=version,
        purl=purl,
        pinned=reason is None,
        float_reason=reason,
    )


def _parse_uvx(args: Sequence[str], detail: str) -> LaunchFacts:
    i = 0
    from_spec: str | None = None
    while i < len(args):
        arg = args[i]
        if arg.startswith("--from="):
            from_spec = arg.split("=", 1)[1]
        elif arg == "--from" and i + 1 < len(args):
            from_spec = args[i + 1]
            i += 1
        elif arg in _UVX_VALUE_FLAGS and i + 1 < len(args):
            i += 1
        elif arg.startswith("-"):
            pass
        else:
            break
        i += 1
    spec = from_spec or (args[i] if i < len(args) else None)
    if spec is None:
        return LaunchFacts(Launcher.UVX, detail)
    return _pypi_facts(spec, detail, Launcher.UVX)


def _parse_pipx(args: Sequence[str]) -> LaunchFacts:
    rest = list(args[1:]) if args and args[0] == "run" else list(args)
    spec: str | None = None
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg.startswith("--spec="):
            spec = arg.split("=", 1)[1]
        elif arg == "--spec" and i + 1 < len(rest):
            spec = rest[i + 1]
            i += 1
        elif arg in {"--python", "--index-url", "-i", "--pip-args"} and i + 1 < len(rest):
            i += 1
        elif not arg.startswith("-"):
            spec = spec or arg
            break
        i += 1
    return _pypi_facts(spec, "pipx run", Launcher.UVX) if spec else LaunchFacts(Launcher.UVX, "pipx run")


# --------------------------------------------------------------------------------------------- OCI

_DOCKER_VALUE_FLAGS: Final = frozenset(
    {
        "-a", "--attach", "--add-host", "--annotation", "--blkio-weight", "--blkio-weight-device", "--cap-add",
        "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-period", "--cpu-quota",
        "--cpu-rt-period", "--cpu-rt-runtime", "-c", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems",
        "--device", "--device-cgroup-rule", "--device-read-bps", "--device-read-iops", "--device-write-bps",
        "--device-write-iops", "--dns", "--dns-option", "--dns-search", "--domainname", "--entrypoint", "-e",
        "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd", "--health-interval",
        "--health-retries", "--health-start-period", "--health-start-interval", "--health-timeout", "-h",
        "--hostname", "--ip", "--ip6", "--ipc", "--isolation", "--kernel-memory", "-l", "--label", "--label-file",
        "--link", "--link-local-ip", "--log-driver", "--log-opt", "--mac-address", "-m", "--memory",
        "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount", "--name", "--network", "--net",
        "--network-alias", "--oom-score-adj", "--pid", "--pids-limit", "--platform", "-p", "--publish", "--pull",
        "--restart", "--runtime", "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout",
        "--storage-opt", "--sysctl", "--tmpfs", "--ulimit", "-u", "--user", "--userns", "--uts", "-v", "--volume",
        "--volume-driver", "--volumes-from", "-w", "--workdir",
    }
)  # fmt: skip


def _docker_risks(flag: str, value: str | None) -> list[str]:
    risks: list[str] = []
    v = (value or "").lower()
    if flag == "--privileged":
        risks.append("privileged")
    if flag in {"--network", "--net"} and v == "host":
        risks.append("host-network")
    if flag in {"--pid", "--ipc", "--uts", "--userns", "--cgroupns"} and v == "host":
        risks.append(f"host-{flag.lstrip('-')}")
    if flag == "--cap-add" and v:
        risks.append(f"cap-add:{v.upper()}")
    if flag in {"-v", "--volume", "--mount"} and v:
        if "docker.sock" in v:
            risks.append("docker-socket-mount")
        source = (
            v.split(":", 1)[0]
            if flag != "--mount"
            else next((kv.split("=", 1)[1] for kv in v.split(",") if kv.startswith(("source=", "src="))), "")
        )
        if source in {"/", "c:\\", "c:/"}:
            risks.append("host-root-mount")
        elif (
            source.startswith(("~", "$home", "/home", "/users", "/root"))
            and source.rstrip("/").count("/") <= 2
        ):
            risks.append("home-directory-mount")
    if flag == "--security-opt" and ("unconfined" in v or "no-new-privileges=false" in v):
        risks.append(f"security-opt:{v}")
    if flag == "--device" and v:
        risks.append("device-passthrough")
    if flag in {"-u", "--user"} and v in {"0", "root", "0:0"}:
        risks.append("runs-as-root")
    return risks


def _oci_facts(image: str, detail: str, risks: list[str]) -> LaunchFacts:
    digest_match = _OCI_DIGEST.search(image)
    digest = digest_match.group(1) if digest_match else None
    ref = image[: digest_match.start()] if digest_match else image
    last = ref.rsplit("/", 1)[-1]
    tag = None
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = "docker.io", ("library/" + ref) if len(parts) == 1 else ref
    name = repo.rsplit("/", 1)[-1].lower()
    qualifiers = {"repository_url": f"{registry}/{repo}".lower()}
    if tag:
        qualifiers["tag"] = tag
    purl = PackageURL(type="oci", name=name, version=digest, qualifiers=qualifiers).to_string()
    reason = None if digest else f"mutable-tag:{tag or 'latest'}"
    return LaunchFacts(
        Launcher.DOCKER,
        detail,
        ecosystem="oci",
        package_name=f"{registry}/{repo}",
        version_spec=digest or tag,
        purl=purl,
        pinned=digest is not None,
        float_reason=reason,
        digest=digest,
        risky_flags=tuple(dict.fromkeys(risks)),
    )


def _parse_docker(args: Sequence[str], detail: str) -> LaunchFacts:
    rest = list(args)
    if rest and rest[0] in {"run", "container"}:
        rest = rest[2:] if rest[0] == "container" and len(rest) > 1 and rest[1] == "run" else rest[1:]
    else:
        return LaunchFacts(Launcher.DOCKER, detail)
    risks: list[str] = []
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--":
            i += 1
            break
        if arg.startswith("--") and "=" in arg:
            flag, _, inline = arg.partition("=")
            risks.extend(_docker_risks(flag, inline))
        elif arg in _DOCKER_VALUE_FLAGS:
            following = rest[i + 1] if i + 1 < len(rest) else None
            risks.extend(_docker_risks(arg, following))
            i += 1
        elif arg.startswith("-"):
            risks.extend(_docker_risks(arg, None))
        else:
            break
        i += 1
    if i >= len(rest):
        return LaunchFacts(Launcher.DOCKER, detail, risky_flags=tuple(dict.fromkeys(risks)))
    return _oci_facts(rest[i], detail, risks)


# --------------------------------------------------------------------------------------------- others


def _parse_dnx(args: Sequence[str]) -> LaunchFacts:
    positional = [a for a in args if not a.startswith("-")]
    version: str | None = None
    for i, arg in enumerate(args):
        if arg == "--version" and i + 1 < len(args):
            version = args[i + 1]
    if not positional:
        return LaunchFacts(Launcher.DNX, "dnx")
    name, _, at_version = positional[0].partition("@")
    resolved: str | None = version or at_version or None
    version = resolved
    reason = None if version and _EXACT_SEMVER.match(version) else ("no-version" if not version else "range")
    purl = PackageURL(type="nuget", name=name, version=version if reason is None else None).to_string()
    return LaunchFacts(Launcher.DNX, "dnx", "nuget", name, version, purl, reason is None, reason)


def _parse_deno(args: Sequence[str]) -> LaunchFacts:
    if not args or args[0] not in {"run", "x"}:
        return LaunchFacts(Launcher.OTHER, "deno")
    spec = next((a for a in args[1:] if not a.startswith("-")), None)
    if spec is None:
        return LaunchFacts(Launcher.OTHER, "deno run")
    if spec.startswith("npm:"):
        facts = _npm_facts(spec, "deno run")
        return LaunchFacts(
            Launcher.OTHER,
            "deno run",
            facts.ecosystem,
            facts.package_name,
            facts.version_spec,
            facts.purl,
            facts.pinned,
            facts.float_reason,
        )
    if spec.startswith("jsr:"):
        name, version = _split_npm_spec(spec[4:])
        reason = (
            None if version and _EXACT_SEMVER.match(version) else ("no-version" if not version else "range")
        )
        return LaunchFacts(Launcher.OTHER, "deno run", "jsr", name, version, None, reason is None, reason)
    if spec.startswith(("http://", "https://")):
        return LaunchFacts(Launcher.OTHER, "deno run", "url", spec, None, None, False, "url")
    return LaunchFacts(Launcher.BINARY, "deno run", local_path=spec)


def _parse_go(args: Sequence[str]) -> LaunchFacts:
    if not args or args[0] != "run":
        return LaunchFacts(Launcher.OTHER, "go")
    spec = next((a for a in args[1:] if not a.startswith("-")), None)
    if not spec or "@" not in spec:
        return LaunchFacts(Launcher.BINARY, "go run", local_path=spec)
    module, _, version = spec.partition("@")
    reason = (
        None if _EXACT_SEMVER.match(version) else (f"dist-tag:{version}" if version == "latest" else "range")
    )
    namespace, _, name = module.rpartition("/")
    purl = PackageURL(
        type="golang", namespace=namespace or None, name=name, version=version if reason is None else None
    ).to_string()
    return LaunchFacts(Launcher.OTHER, "go run", "golang", module, version, purl, reason is None, reason)


_SCRIPT_RUNNERS: Final = frozenset(
    {
        "node",
        "nodejs",
        "python",
        "python3",
        "py",
        "ruby",
        "php",
        "perl",
        "bash",
        "sh",
        "zsh",
        "pwsh",
        "powershell",
        "tsx",
        "ts-node",
        "java",
    }
)


def _h_npx(base: str, argv: list[str]) -> LaunchFacts:
    return _parse_npx(argv, base)


def _h_npm(base: str, argv: list[str]) -> LaunchFacts:
    if argv[:1] in (["exec"], ["x"]):
        return _parse_npx(argv[1:], "npm exec")
    return LaunchFacts(Launcher.OTHER, base)


def _h_dlx(base: str, argv: list[str]) -> LaunchFacts:
    if argv[:1] == ["dlx"]:
        return _parse_npx(argv[1:], f"{base} dlx")
    return LaunchFacts(Launcher.OTHER, base)


def _h_bun(base: str, argv: list[str]) -> LaunchFacts:
    if base == "bunx":
        return _parse_npx(argv, "bunx")
    if argv[:1] == ["x"]:
        return _parse_npx(argv[1:], "bunx")
    return LaunchFacts(Launcher.OTHER, base)


def _h_uv(base: str, argv: list[str]) -> LaunchFacts:
    if base == "uvx":
        return _parse_uvx(argv, "uvx")
    if argv[:2] == ["tool", "run"]:
        return _parse_uvx(argv[2:], "uv tool run")
    return LaunchFacts(Launcher.OTHER, base)


def _h_pipx(base: str, argv: list[str]) -> LaunchFacts:
    del base
    return _parse_pipx(argv)


def _h_docker(base: str, argv: list[str]) -> LaunchFacts:
    return _parse_docker(argv, f"{base} run")


def _h_dnx(base: str, argv: list[str]) -> LaunchFacts:
    if base == "dnx":
        return _parse_dnx(argv)
    if argv[:1] == ["dnx"]:
        return _parse_dnx(argv[1:])
    return LaunchFacts(Launcher.OTHER, base)


def _h_deno(base: str, argv: list[str]) -> LaunchFacts:
    del base
    return _parse_deno(argv)


def _h_go(base: str, argv: list[str]) -> LaunchFacts:
    del base
    return _parse_go(argv)


_LAUNCHERS: Final[dict[str, Callable[[str, list[str]], LaunchFacts]]] = {
    "npx": _h_npx,
    "pnpx": _h_npx,
    "npm": _h_npm,
    "pnpm": _h_dlx,
    "yarn": _h_dlx,
    "bunx": _h_bun,
    "bun": _h_bun,
    "uvx": _h_uv,
    "uv": _h_uv,
    "pipx": _h_pipx,
    "docker": _h_docker,
    "podman": _h_docker,
    "nerdctl": _h_docker,
    "dnx": _h_dnx,
    "dotnet": _h_dnx,
    "deno": _h_deno,
    "go": _h_go,
}


def parse_launch(command: str | None, args: Sequence[object]) -> LaunchFacts:
    """Identify what ``command args...`` would fetch and execute. Never executes anything."""
    if not command:
        return LaunchFacts(Launcher.OTHER, "none")
    argv = [str(a) for a in args]
    base = _basename(command)
    handler = _LAUNCHERS.get(base)
    if handler is not None:
        return handler(base, argv)
    if base in _SCRIPT_RUNNERS:
        script = next((a for a in argv if not a.startswith("-")), None)
        return LaunchFacts(Launcher.BINARY, base, local_path=script)
    return LaunchFacts(Launcher.BINARY, "binary", local_path=command)
