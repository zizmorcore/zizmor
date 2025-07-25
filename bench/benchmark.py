# /// script
# requires-python = ">=3.12"
# ///

import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, NoReturn, TypedDict

_DEPS = ["hyperfine", "curl", "unzip"]

_HERE = Path(__file__).parent
_PROJECT_ROOT = _HERE.parent
_ZIZMOR = _PROJECT_ROOT / "target" / "release" / "zizmor"

assert (_PROJECT_ROOT / "Cargo.toml").is_file(), "Missing project root?"

_BENCHMARKS = _HERE / "benchmarks.json"
_RESULTS = _HERE / "results"

assert _BENCHMARKS.is_file(), f"Benchmarks file not found: {_BENCHMARKS}"
_RESULTS.mkdir(exist_ok=True)

_CACHE_DIR = Path(tempfile.gettempdir()) / "zizmor-benchmark-cache"
_CACHE_DIR.mkdir(exist_ok=True)


class Log:
    def __init__(self, scope: str | None) -> None:
        self.scopes = [scope] if scope else []

    def info(self, message: str) -> None:
        scopes = " ".join(f"[{s}]" for s in self.scopes)
        print(f"[+] {scopes} {message}", file=sys.stderr)

    def warn(self, message: str) -> None:
        scopes = " ".join(f"[{s}]" for s in self.scopes)
        print(f"[!] {scopes} {message}", file=sys.stderr)

    def error(self, message: str) -> NoReturn:
        self.warn(message)
        sys.exit(1)

    @contextmanager
    def scope(self, new_scope: str) -> Iterator[None]:
        """Create a new logging scope."""
        self.scopes.append(new_scope)
        try:
            yield None
        finally:
            self.scopes.pop()


LOG = Log("benchmarks")


def _curl(url: str, expected_sha256: str) -> Path:
    """Download a URL and cache it using content addressing with SHA256."""
    cached_file = _CACHE_DIR / expected_sha256
    if cached_file.exists():
        LOG.info("Using cached file")
        return cached_file

    result = subprocess.run(
        ["curl", "-fsSL", url],
        capture_output=True,
        check=True,
    )

    content = result.stdout
    content_hash = hashlib.sha256(content).hexdigest()

    if content_hash != expected_sha256:
        LOG.error(f"Hash mismatch: {expected_sha256} != {content_hash}")

    cached_file.write_bytes(content)

    return cached_file


def _unzip(archive_path: Path, extract_name: str) -> Path:
    """Extract an archive to a directory in the cache."""
    extract_dir = _CACHE_DIR / extract_name

    if extract_dir.exists():
        LOG.info("Using cached extraction")
        return extract_dir

    extract_dir.mkdir(exist_ok=True)

    subprocess.run(
        ["unzip", "-q", str(archive_path), "-d", str(extract_dir)],
        check=True,
    )

    LOG.info(f"Extracted {archive_path.name} to {extract_dir}")
    return extract_dir


class Benchmark(TypedDict):
    name: str
    source_type: str
    source: str
    source_sha256: str
    stencil: str


Plan = list[str]


class Bench:
    def __init__(self, benchmark: Benchmark) -> None:
        self.benchmark = benchmark

    def plan(self) -> Plan:
        match self.benchmark["source_type"]:
            case "archive-url":
                url = self.benchmark["source"]
                sha256 = self.benchmark["source_sha256"]
                archive = _curl(url, sha256)
                inputs = [str(_unzip(archive, self.benchmark["name"]))]
            case _:
                LOG.error(f"Unknown source type: {self.benchmark['source_type']}")

        stencil = self.benchmark["stencil"]
        command = stencil.replace("$ZIZMOR", str(_ZIZMOR)).replace(
            "$INPUTS", " ".join(inputs)
        )
        return shlex.split(command)

    def run(self, plan: Plan, *, dry_run: bool) -> None:
        command = shlex.join(plan)

        result_file = _RESULTS / f"{self.benchmark['name']}.json"
        if result_file.exists() and not dry_run:
            LOG.warn("clobbering existing result file")

        hyperfine_command = [
            "hyperfine",
            "--warmup",
            "3",
            # NOTE: not needed because we use --no-exit-codes in the stencil
            # "--ignore-failure",
            "--export-json",
            str(result_file),
            command,
        ]

        if dry_run:
            LOG.warn(f"would have run: {shlex.join(hyperfine_command)}")
            return

        try:
            subprocess.run(
                hyperfine_command,
                check=True,
            )
        except subprocess.CalledProcessError:
            LOG.error("run failed, see above for details")

        # Stupid hack: fixup each result file's results[0].command
        # to be a more useful benchmark identifier, since bencher
        # apparently keys on these.
        result_json = json.loads(result_file.read_bytes())
        result_json["results"][0]["command"] = f"zizmor::{self.benchmark['name']}"
        result_file.write_text(json.dumps(result_json))

        LOG.info(f"run written to {result_file}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dry-run", action="store_true", help="Show plans without running them"
    )

    args = parser.parse_args()

    missing = []
    for dep in _DEPS:
        if not shutil.which(dep):
            missing.append(dep)

    if missing:
        LOG.error(
            f"Missing dependencies: {', '.join(missing)}. "
            "Please install them before running benchmarks."
        )

    LOG.info("ensuring we have a benchable zizmor build")
    subprocess.run(
        ["cargo", "build", "--release", "-p", "zizmor"],
        check=True,
        cwd=_PROJECT_ROOT,
    )

    if not _ZIZMOR.is_file():
        LOG.error("zizmor build presumably failed, see above for details")

    LOG.info(f"using cache dir: {_CACHE_DIR}")

    benchmarks: list[Benchmark] = json.loads(_BENCHMARKS.read_text(encoding="utf-8"))
    LOG.info(f"found {len(benchmarks)} benchmarks in {_BENCHMARKS.name}")

    benches = [Bench(benchmark) for benchmark in benchmarks]
    plans = []
    with LOG.scope("plan"):
        for bench in benches:
            with LOG.scope(bench.benchmark["name"]):
                LOG.info("beginning plan")
                plans.append(bench.plan())

    with LOG.scope("run"):
        for bench, plan in zip(benches, plans):
            with LOG.scope(bench.benchmark["name"]):
                bench.run(plan, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
