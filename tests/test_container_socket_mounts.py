"""A bind mount that gives a container the engine socket is a runtime socket mount.

The socket can be reached through the directory that holds it or any directory above
it, however the mount option and its source are spelled.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.mcp_launch import MAX_EXPANSION_DEPTH, analyze
from tests.support import scaling_ratio

IMAGE = "example/agent@sha256:" + "a" * 64


def _context(*options: str, engine: str = "docker") -> dict[str, int]:
    launch = analyze(engine, ["run", "-i", "--rm", *options, IMAGE])
    assert launch.unknown is None, launch.unknown
    return launch.context


def _spellings(source: str) -> list[list[str]]:
    return [
        ["-v", f"{source}:/host"],
        ["--volume", f"{source}:/host:ro"],
        [f"--volume={source}:/host"],
        ["--mount", f"type=bind,source={source},target=/host"],
        ["--mount", f"type=bind,src={source},dst=/host,readonly"],
        ["--mount", f'"type=bind","src={source}","dst=/host"'],
    ]


ENGINE_DIRECTORIES = [
    "/run",
    "/var/run",
    "/run/user/1000",
    "/run/podman",
    "/run/containerd",
    "/",
    "/run/",
    "/run/.",
    "/run//",
    "//run",
    "/./run/",
    "/run/podman/..",
    "/srv/../run",
    "/var/./run/.",
    "/RUN",
    "/var/Run",
]


@pytest.mark.parametrize("source", ENGINE_DIRECTORIES)
@pytest.mark.parametrize("spelling", range(6))
def test_engine_socket_directory_mounts_are_socket_mounts(source, spelling):
    context = _context(*_spellings(source)[spelling])
    assert context.get("host_mounts") == 1
    assert context.get("runtime_socket_mount") == 1


@pytest.mark.parametrize(
    "source",
    [
        # System and rootless runtime directories, and the directories above them.
        "/var",
        "/run/user",
        "/run/user/1000/",
        "/run/user/1000/podman",
        "/run/user/1000/docker",
        "/run/user/1000/docker/containerd",
        "/run/docker",
        "/var/run/docker",
        "/run/docker/containerd",
        "/var/run/containerd/",
        "/var/run/podman",
        "/run/crio",
        "/run/crio/crio.sock",
        "/run/k3s",
        "/run/k3s/containerd",
        "/private/var/run",
        "/private/var",
        # Desktop engines under a home directory.
        "~/.docker",
        "~/.docker/run",
        "~/.docker/run/",
        "~/.docker/./run",
        "~/.docker/desktop",
        "~/.colima",
        "~/.colima/default",
        "~/.colima/default/docker.sock",
        "~/.lima/docker/sock",
        "~/.rd",
        "~/.orbstack/run",
        "~/.local/share/containers/podman/machine/qemu",
        "$HOME/.docker/run",
        "${HOME}/.colima",
        "${env:HOME}/.docker/run",
        "${userHome}/.docker/desktop",
        "/Users/alice/.docker/run",
        "/home/alice/.docker",
        "/root/.docker/run",
        "/var/home/alice/.colima",
        # The rootless runtime directory named by its variable.
        "${XDG_RUNTIME_DIR}",
        "$XDG_RUNTIME_DIR/",
        "${XDG_RUNTIME_DIR}/podman",
        "${env:XDG_RUNTIME_DIR}",
        "${xdg_runtime_dir}/docker",
        # Climbing to an unknown depth and then naming the directory.
        "../../../../../../../../run",
        "./../../../../../../../var/run",
        "../../../../../../../../run/user/1000",
        "../../../../../../../../home/alice/.docker/run",
        "~/../../run",
        "$HOME/../../../var/run/",
        # A client expands a default, or an alternate value, in place of an unset variable.
        "${UNSET:-/run}",
        "${UNSET-/var/run}",
        "${UNSET:=/run/user/1000}",
        "${SET:+/run/podman}",
        "${A:-${B:-/run}}",
        "${A:-/var}/run",
        "/var/${A:-run}",
        "${A:-${XDG_RUNTIME_DIR}}",
        "${A:-~}/.docker/run",
        # The daemon follows /proc links to a process's root, its working directory or a
        # directory it holds open.
        "/proc/self/root/run",
        "/proc/1/root/var/run/",
        "/proc/thread-self/root/run/user/1000",
        "/proc/1/task/1/root/run",
        "/proc/self/cwd/run",
        "/proc/self/fd/3/run",
        "/dev/fd/3/run",
        "/dev/stdin/var/run",
        "../../../../../../../../proc/1/root/run",
        # Other socket names, and a backslash read as a separator, as Windows reads it.
        "/var/run/docker.sock.raw",
        "/srv/engine/crio.sock",
        "/run\\",
        "/var\\run",
        # Windows named pipes.
        "\\\\.\\pipe",
        "\\\\.\\pipe\\",
        "//./pipe",
        "//./PIPE/",
    ],
)
@pytest.mark.parametrize("spelling", [0, 3, 4])
def test_more_socket_locations_and_spellings_are_socket_mounts(source, spelling):
    context = _context(*_spellings(source)[spelling])
    assert context.get("runtime_socket_mount") == 1


@pytest.mark.parametrize("engine", ["docker", "podman", "nerdctl"])
@pytest.mark.parametrize("source", ["/run", "/run/user/1000", "/var/run/"])
def test_every_engine_reads_the_socket_directory(engine, source):
    assert _context("-v", f"{source}:/run", engine=engine).get("runtime_socket_mount") == 1


@pytest.mark.parametrize(
    "command,args",
    [
        ("sh", ["-c", f"docker run -i --rm -v /run:/run {IMAGE}"]),
        ("env", ["docker", "run", "-i", "--mount", "type=bind,src=/var/run,dst=/r", IMAGE]),
        ("docker", ["container", "run", "-i", "-v", "/run/user/1000:/x", IMAGE]),
    ],
)
def test_wrapped_launches_read_the_socket_directory(command, args):
    launch = analyze(command, args)
    assert launch.launcher == "docker run" and launch.unknown is None
    assert launch.context.get("runtime_socket_mount") == 1


@pytest.mark.parametrize(
    "source", ["/", "//", "/etc/..", "/proc/1/root", "/proc/self/root/", "/proc/1/cwd/."]
)
def test_the_host_root_is_also_a_socket_mount(source):
    context = _context("-v", f"{source}:/host")
    assert context.get("host_root_mount") == 1
    assert context.get("runtime_socket_mount") == 1
    assert "broad_host_mount" not in context


def test_a_broad_directory_behind_a_proc_link_is_broad():
    context = _context("-v", "/proc/1/root/etc:/host")
    assert context.get("broad_host_mount") == 1
    assert not {"host_root_mount", "runtime_socket_mount"} & set(context)


@pytest.mark.parametrize(
    "spec,socket",
    [
        # docker and podman read source and src as one key; the last one wins.
        ("type=bind,source=/srv/data,src=/run,target=/x", True),
        ("type=bind,src=/srv/data,source=/run,target=/x", True),
        ("type=bind,src=/run,source=/srv/data,target=/x", False),
        ("type=bind,source=/run,source=/srv/data,target=/x", False),
        ("type=volume,type=bind,src=/run,target=/x", True),
        ("Type=VOLUME,TYPE=Bind,SRC=/var/run,target=/x", True),
    ],
)
def test_the_last_mount_source_and_type_are_read(spec, socket):
    context = _context("--mount", spec)
    assert context.get("host_mounts") == 1
    assert bool(context.get("runtime_socket_mount")) is socket


def test_a_bind_mount_overridden_by_a_volume_type_mounts_no_host_path():
    context = _context("--mount", "type=bind,type=volume,src=/run,target=/x")
    assert "host_mounts" not in context and "runtime_socket_mount" not in context


@pytest.mark.parametrize(
    "spec",
    [
        # The local volume driver bind-mounts its device option.
        "type=volume,dst=/x,volume-opt=type=none,volume-opt=o=bind,volume-opt=device=/run",
        'type=volume,dst=/x,"volume-opt=o=bind,ro",volume-opt=device=/var/run/',
        "dst=/x,volume-opt=device=/run/user/1000,volume-opt=o=bind",
        "type=volume,dst=/x,Volume-Opt=Device=/run/podman",
        # podman expands a glob source into one bind mount per match.
        "type=glob,src=/run/*,dst=/x",
        "type=glob,src=/r*,dst=/x",
        "type=glob,src=/run/docker.s*,dst=/x",
        "type=glob,src=/run/user/*/podman,dst=/x",
        "type=glob,src=/run/[cp]o*,dst=/x",
        # A Windows engine mounts a named pipe.
        "type=npipe,source=\\\\.\\pipe\\docker_engine,target=\\\\.\\pipe\\docker_engine",
    ],
)
def test_volume_device_and_glob_sources_are_host_mounts(spec):
    context = _context("--mount", spec, engine="podman" if "glob" in spec else "docker")
    assert context.get("host_mounts") == 1
    assert context.get("runtime_socket_mount") == 1


@pytest.mark.parametrize(
    "spec,flag",
    [
        (
            "type=volume,dst=/x,volume-opt=type=none,volume-opt=o=bind,volume-opt=device=/srv/a",
            None,
        ),
        ("type=volume,dst=/x,volume-opt=type=ext4,volume-opt=device=/dev/sdb1", "broad_host_mount"),
        ("type=glob,src=/usr/lib64/libexample*,dst=/x", None),
        ("type=glob,src=/srv/*,dst=/x", None),
    ],
)
def test_device_and_glob_sources_away_from_the_socket_are_ordinary(spec, flag):
    context = _context("--mount", spec, engine="podman")
    assert context.get("host_mounts") == 1
    assert "runtime_socket_mount" not in context
    assert (flag is None and "broad_host_mount" not in context) or context.get(flag) == 1


@pytest.mark.parametrize(
    "spec",
    [
        "type=volume,dst=/x,volume-opt=type=nfs,volume-opt=device=:/export/run",
        "type=volume,src=cache,dst=/x",
        "type=tmpfs,dst=/run",
        "type=volume,dst=/x,volume-opt=device",
    ],
)
def test_volumes_without_a_host_path_are_not_host_mounts(spec):
    context = _context("--mount", spec)
    assert "host_mounts" not in context and "runtime_socket_mount" not in context


@pytest.mark.parametrize(
    "source,broad",
    [
        ("/srv/app", False),
        ("/srv/app/run", False),
        ("/run/user/1000/bus", False),
        ("/run/user/1000/pulse/native", False),
        ("/run/host-services/ssh-auth.sock", False),
        ("/run/secrets", True),
        ("/run/systemd", True),
        ("/var/run/secrets/app", False),
        ("/runtime", False),
        ("/run-data/x", False),
        ("/var/runner/x", False),
        ("/var/lib", True),
        ("/var/lib/app", False),
        ("/opt/run", False),
        ("./data", False),
        ("./run", False),
        (".", False),
        ("${workspaceFolder}", False),
        ("${workspaceFolder}/run", False),
        ("${workspaceFolder}/var/run", False),
        ("$PWD/run", False),
        ("${UNSET:-/srv/data}", False),
        ("${UNSET}/run", False),
        ("${XDG_RUNTIME_DIR}/bus", False),
        ("~/.docker/config.json", False),
        ("/home/alice/.docker/config.json", False),
        ("~/.config/gcloud", False),
        ("~/project", True),
        ("~", True),
        ("$HOME", True),
        ("/home/alice", True),
        ("/Users/alice", True),
        ("/home", True),
        ("/root", True),
        ("..", True),
        ("../parent", True),
        ("../../..", True),
        ("~/..", True),
        ("/proc/1", True),
        ("/proc/self/status", False),
        ("/proc/1/fd", False),
        ("./proc/1/root/run", False),
        ("C:\\Users\\alice\\.docker\\run", False),
        ("C:\\", False),
    ],
)
def test_ordinary_mounts_are_not_socket_mounts(source, broad):
    for options in _spellings(source)[:1] + _spellings(source)[4:5]:
        context = _context(*options)
        assert context.get("host_mounts") == 1, options
        assert "runtime_socket_mount" not in context, options
        assert bool(context.get("broad_host_mount")) is broad, options


@pytest.mark.parametrize("volume", ["data:/data", "/run", "${A:-/run}", "cache:${A:-/run}"])
def test_named_and_anonymous_volumes_are_not_host_mounts(volume):
    context = _context("-v", volume)
    assert "host_mounts" not in context and "runtime_socket_mount" not in context


def test_expansions_nested_past_the_reader_limit_fail_closed():
    source = "${A:-" * (MAX_EXPANSION_DEPTH + 2) + "/run" + "}" * (MAX_EXPANSION_DEPTH + 2)
    launch = analyze("docker", ["run", "-i", "-v", f"{source}:/run", IMAGE])
    assert launch.unknown is not None and "mount source" in launch.unknown


def test_each_mount_counts_once_whatever_its_readings():
    context = _context("-v", "${A:-/run}:/a", "-v", "/:/b", "-v", "/srv/app:/c")
    assert context["host_mounts"] == 3
    assert context["runtime_socket_mount"] == 2
    assert context["host_root_mount"] == 1


@pytest.mark.parametrize(
    "options,flag,engine",
    [
        (["--volumes-from", "sibling"], "inherited_mounts", "docker"),
        (["--volumes-from=sibling:ro"], "inherited_mounts", "podman"),
        (["--network", "container:sibling"], "container_namespaces", "docker"),
        (["--net=container:sibling"], "container_namespaces", "docker"),
        (["--network", "CONTAINER:sibling"], "container_namespaces", "docker"),
        (["--pid=container:sibling"], "container_namespaces", "docker"),
        (["--ipc", "container:sibling"], "container_namespaces", "nerdctl"),
        (["--uts", "container:sibling"], "container_namespaces", "podman"),
        (["--userns=container:sibling"], "container_namespaces", "podman"),
        (["--cgroupns", "container:sibling"], "container_namespaces", "podman"),
        (["--pod", "shared"], "container_namespaces", "podman"),
        (["--network", "ns:/proc/1/ns/net"], "host_namespaces", "podman"),
        (["--pid=ns:/proc/1/ns/pid"], "host_namespaces", "podman"),
    ],
)
def test_sharing_another_container_widens_the_context(options, flag, engine):
    assert _context(*options, engine=engine).get(flag) == 1


@pytest.mark.parametrize(
    "options,engine",
    [
        (["--network", "bridge"], "docker"),
        (["--network", "example-net"], "docker"),
        (["--network", "none"], "docker"),
        (["--ipc", "private"], "docker"),
        (["--ipc", "shareable"], "docker"),
        (["--userns", "keep-id"], "podman"),
        (["--pod", "new:fresh"], "podman"),
        (["--cgroupns", "private"], "podman"),
    ],
)
def test_private_namespaces_do_not_widen_the_context(options, engine):
    context = _context(*options, engine=engine)
    assert not {"container_namespaces", "host_namespaces", "inherited_mounts"} & set(context)


def _server(root: Path, options: list[str]) -> MCPServerComponent:
    (root / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"agent": {"command": "docker", "args": ["run", *options, IMAGE]}}}
        )
    )
    result = MCPScanner().scan(root, config_only=True)
    assert not result.scan_failures and not result.surfaces_excluded
    (server,) = [c for c in result.components if isinstance(c, MCPServerComponent)]
    return server


@pytest.mark.parametrize(
    "options",
    [
        ["-i", "--rm", "-v", "/run:/run"],
        ["-i", "--rm", "--mount", "type=bind,src=/run/user/1000/,dst=/run/user/1000"],
        ["-i", "--rm", "-v", "${UNSET:-/var/run}:/var/run"],
    ],
)
def test_the_scanner_rates_a_socket_directory_mount_high(tmp_path, options):
    server = _server(tmp_path, options)
    assert server.properties["launch_context"].get("runtime_socket_mount") == 1
    findings = [r for r in server.risks if r.category == "launch_context"]
    assert [r.severity.value for r in findings] == ["high"]
    assert "a container runtime socket mount" in findings[0].detail
    exported = server.model_dump_json()
    assert "/run/user/1000" not in exported and "UNSET" not in exported


def test_the_scanner_rates_a_shared_container_medium(tmp_path):
    server = _server(tmp_path, ["--volumes-from", "sibling", "--network", "container:sibling"])
    findings = [r for r in server.risks if r.category == "launch_context"]
    assert [r.severity.value for r in findings] == ["medium"]
    assert "another container's mounts" in findings[0].detail
    assert "another container's namespace" in findings[0].detail
    assert "sibling" not in server.model_dump_json()


@pytest.mark.parametrize("source,failed", [("/run", 1), ("/srv/app", 0)])
def test_a_socket_directory_mount_fails_the_high_risk_gate(tmp_path, source, failed):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Be helpful.\n")
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "agent": {
                        "command": "docker",
                        "args": ["run", "-i", "--rm", "-v", f"{source}:/data", IMAGE],
                    }
                }
            }
        )
    )
    output = tmp_path / "bom.json"
    runner = CliRunner()
    scan = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert scan.exit_code == 0, scan.output
    risk = runner.invoke(
        main,
        [
            "risk",
            str(output),
            "--project",
            str(project),
            "--no-project-policy",
            "--fail-on-severity",
            "high",
            "--json-output",
        ],
    )
    assert risk.exit_code == failed, risk.output


@pytest.mark.parametrize(
    "unit,tail,flag",
    [
        ("x/", ":/x", None),
        ("proc/self/root/", "run:/x", "runtime_socket_mount"),
        ("proc/1/task/", "run:/x", None),
        ("../", "run:/x", "runtime_socket_mount"),
        ("${", ":/x", None),
        ("${A}", "/run:/x", None),
        ("${A:-x}", ":/x", None),
        ("${A:-/}", "run:/x", "runtime_socket_mount"),
    ],
)
def test_long_mount_sources_are_read_in_linear_time(unit, tail, flag):
    def run(scale: int) -> None:
        context = _context("-v", "/" + unit * (2_000 * scale) + tail)
        assert context.get("host_mounts") == 1
        assert flag is None or context.get(flag) == 1

    assert scaling_ratio(run) < 10
