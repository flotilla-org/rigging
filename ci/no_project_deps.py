"""Rigging crates sit at the bottom of the graph: they depend on no project crate.

Fails when any Cargo.toml in this repository has a git or path dependency that
leaves the repository, or a git dependency on a flotilla-org repository.
"""
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def tables(doc):
    for section in SECTIONS:
        yield section, doc.get(section, {})
        for target, body in doc.get("target", {}).items():
            yield f"target.{target}.{section}", body.get(section, {})
    workspace = doc.get("workspace", {})
    yield "workspace.dependencies", workspace.get("dependencies", {})


def main():
    failures = []
    for manifest in ROOT.rglob("Cargo.toml"):
        if "target" in manifest.relative_to(ROOT).parts:
            continue
        doc = tomllib.loads(manifest.read_text())
        for where, deps in tables(doc):
            for name, spec in deps.items():
                if not isinstance(spec, dict):
                    continue
                git = spec.get("git", "")
                if "flotilla-org/" in git and "flotilla-org/rigging" not in git:
                    failures.append(f"{manifest}: [{where}] {name} is a git dependency on {git}")
                path = spec.get("path")
                if path is not None:
                    resolved = (manifest.parent / path).resolve()
                    if not resolved.is_relative_to(ROOT):
                        failures.append(f"{manifest}: [{where}] {name} has a path outside rigging: {path}")
    for failure in failures:
        print(failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
