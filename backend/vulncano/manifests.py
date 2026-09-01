"""Dependency manifest parsing, independent of any scanner.

Every parser returns (ecosystem, name, version) triples so an adapter that only needs a
dependency list supports every ecosystem here for free. Lines that cannot be understood
come back as warnings instead of disappearing.
"""

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import PurePosixPath

PYPI = "PyPI"
MAVEN = "Maven"
NPM = "npm"
GO = "Go"
CRATES = "crates.io"
RUBYGEMS = "RubyGems"
PACKAGIST = "Packagist"
NUGET = "NuGet"

PURL_TYPES = {
    PYPI: "pypi",
    MAVEN: "maven",
    NPM: "npm",
    GO: "golang",
    CRATES: "cargo",
    RUBYGEMS: "gem",
    PACKAGIST: "composer",
    NUGET: "nuget",
}

REQUIREMENT_PIN = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")
REQUIREMENT_LOOSE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?:[<>~!=]=?\s*([^\s;#,]+))?\s*$")
GO_MOD_REQUIRE = re.compile(r"^\s*(?:require\s+)?([^\s]+/[^\s]+|[^\s]+\.[^\s/]+)\s+v([^\s/]+)")
GO_SUM_LINE = re.compile(r"^(\S+)\s+v(\S+?)(?:/go\.mod)?\s+h1:")
GEMFILE_LOCK_SPEC = re.compile(r"^\s{4}([A-Za-z0-9._-]+) \(([^()]+)\)$")
YARN_ENTRY_NAME = re.compile(r'^"?((?:@[^/\s"@]+/)?[^@\s"]+)@')
YARN_VERSION = re.compile(r'^\s+"?version"?:?\s+"?([^"\s]+)"?')
MAVEN_NS = re.compile(r"^\{.*\}")


@dataclass
class Dependency:
    ecosystem: str
    name: str
    version: str

    @property
    def coordinate(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name

    @property
    def purl(self) -> str:
        kind = PURL_TYPES.get(self.ecosystem, "generic")
        if self.ecosystem == MAVEN and ":" in self.name:
            group, artifact = self.name.split(":", 1)
            return f"pkg:{kind}/{group}/{artifact}@{self.version}"
        return f"pkg:{kind}/{self.name}@{self.version}"


@dataclass
class ManifestResult:
    dependencies: list[Dependency] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def extend(self, other: "ManifestResult") -> None:
        self.dependencies.extend(other.dependencies)
        self.warnings.extend(other.warnings)

    def deduplicated(self) -> list[Dependency]:
        seen = {}
        for dependency in self.dependencies:
            seen.setdefault((dependency.ecosystem, dependency.name, dependency.version), dependency)
        return list(seen.values())


class UnsupportedManifest(ValueError):
    pass


def _strip_ns(tag: str) -> str:
    return MAVEN_NS.sub("", tag)


def parse_requirements(text: str) -> ManifestResult:
    result = ManifestResult()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or line.startswith("http"):
            continue
        pinned = REQUIREMENT_PIN.match(line)
        if pinned:
            result.dependencies.append(Dependency(PYPI, pinned.group(1), pinned.group(2)))
            continue
        loose = REQUIREMENT_LOOSE.match(line)
        if loose and loose.group(2):
            result.dependencies.append(Dependency(PYPI, loose.group(1), loose.group(2)))
            result.warnings.append(
                f"requirements line {number}: {line} is not pinned with ==, using {loose.group(2)}"
            )
        elif loose:
            result.warnings.append(f"requirements line {number}: {line} has no version, skipped")
        else:
            result.warnings.append(f"requirements line {number}: cannot parse {line}")
    return result


def parse_pyproject(text: str) -> ManifestResult:
    result = ManifestResult()
    data = tomllib.loads(text)
    project_deps = data.get("project", {}).get("dependencies", [])
    for entry in project_deps:
        result.extend(parse_requirements(entry))
    for group in data.get("project", {}).get("optional-dependencies", {}).values():
        for entry in group:
            result.extend(parse_requirements(entry))
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        version = spec if isinstance(spec, str) else (spec or {}).get("version", "")
        cleaned = str(version).lstrip("^~>=< ")
        if cleaned:
            result.dependencies.append(Dependency(PYPI, name, cleaned))
        else:
            result.warnings.append(f"pyproject: {name} has no resolvable version, skipped")
    return result


def parse_poetry_lock(text: str) -> ManifestResult:
    result = ManifestResult()
    for package in tomllib.loads(text).get("package", []):
        result.dependencies.append(Dependency(PYPI, package["name"], package.get("version", "")))
    return result


def parse_pom(text: str) -> ManifestResult:
    result = ManifestResult()
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise UnsupportedManifest(f"pom.xml is not valid XML: {exc}") from exc

    properties = {}
    for element in root.iter():
        if _strip_ns(element.tag) == "properties":
            for child in element:
                properties[_strip_ns(child.tag)] = (child.text or "").strip()
    properties.setdefault("project.version", (root.findtext("{*}version") or "").strip())

    def resolve(value: str) -> str:
        match = re.fullmatch(r"\$\{([^}]+)\}", value or "")
        return properties.get(match.group(1), "") if match else value

    for element in root.iter():
        if _strip_ns(element.tag) != "dependency":
            continue
        fields = {_strip_ns(child.tag): (child.text or "").strip() for child in element}
        group, artifact = fields.get("groupId", ""), fields.get("artifactId", "")
        version = resolve(fields.get("version", ""))
        if not group or not artifact:
            continue
        if not version:
            result.warnings.append(
                f"pom.xml: {group}:{artifact} has no resolved version (inherited from a parent pom), skipped"
            )
            continue
        result.dependencies.append(Dependency(MAVEN, f"{group}:{artifact}", version))
    return result


def parse_package_json(text: str) -> ManifestResult:
    result = ManifestResult()
    data = json.loads(text)
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = str(spec).lstrip("^~>=< v")
            if not version or not version[0].isdigit():
                result.warnings.append(f"package.json: {name} resolves to a range or url ({spec}), skipped")
                continue
            result.dependencies.append(Dependency(NPM, name, version))
    return result


def parse_package_lock(text: str) -> ManifestResult:
    result = ManifestResult()
    data = json.loads(text)
    packages = data.get("packages")
    if packages:
        for path, entry in packages.items():
            if not path or entry.get("link"):
                continue
            name = entry.get("name") or path.split("node_modules/")[-1]
            if entry.get("version"):
                result.dependencies.append(Dependency(NPM, name, entry["version"]))
        return result
    for name, entry in (data.get("dependencies") or {}).items():
        if entry.get("version"):
            result.dependencies.append(Dependency(NPM, name, entry["version"]))
    return result


def parse_yarn_lock(text: str) -> ManifestResult:
    result = ManifestResult()
    current = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" ") and raw.rstrip().endswith(":"):
            header = raw.rstrip(":").split(",")[0].strip()
            match = YARN_ENTRY_NAME.match(header)
            current = match.group(1) if match else None
            continue
        version = YARN_VERSION.match(raw)
        if version and current:
            result.dependencies.append(Dependency(NPM, current, version.group(1)))
            current = None
    return result


def parse_go_mod(text: str) -> ManifestResult:
    result = ManifestResult()
    inside_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            inside_block = True
            continue
        if inside_block and line == ")":
            inside_block = False
            continue
        if not (inside_block or line.startswith("require ")):
            continue
        match = GO_MOD_REQUIRE.match(line)
        if match:
            result.dependencies.append(Dependency(GO, match.group(1), match.group(2)))
        elif line and line != "require (":
            result.warnings.append(f"go.mod: cannot parse require line {line}")
    return result


def parse_go_sum(text: str) -> ManifestResult:
    result = ManifestResult()
    for raw in text.splitlines():
        match = GO_SUM_LINE.match(raw.strip())
        if match:
            result.dependencies.append(Dependency(GO, match.group(1), match.group(2)))
    return result


def parse_cargo_lock(text: str) -> ManifestResult:
    result = ManifestResult()
    for package in tomllib.loads(text).get("package", []):
        result.dependencies.append(Dependency(CRATES, package["name"], package.get("version", "")))
    return result


def parse_gemfile_lock(text: str) -> ManifestResult:
    result = ManifestResult()
    in_specs = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs and stripped and not raw.startswith(" "):
            in_specs = False
        if not in_specs:
            continue
        match = GEMFILE_LOCK_SPEC.match(raw)
        if match:
            result.dependencies.append(Dependency(RUBYGEMS, match.group(1), match.group(2)))
    return result


def parse_composer_lock(text: str) -> ManifestResult:
    result = ManifestResult()
    data = json.loads(text)
    for section in ("packages", "packages-dev"):
        for package in data.get(section) or []:
            result.dependencies.append(
                Dependency(PACKAGIST, package["name"], str(package.get("version", "")).lstrip("v"))
            )
    return result


def parse_csproj(text: str) -> ManifestResult:
    result = ManifestResult()
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise UnsupportedManifest(f"csproj is not valid XML: {exc}") from exc
    for element in root.iter():
        if _strip_ns(element.tag) != "PackageReference":
            continue
        name = element.get("Include") or element.get("Update")
        version = element.get("Version") or element.findtext("{*}Version") or ""
        if not name:
            continue
        if not version:
            result.warnings.append(f"csproj: {name} has no Version attribute (central package management), skipped")
            continue
        result.dependencies.append(Dependency(NUGET, name, version.strip()))
    return result


PARSERS = {
    "requirements.txt": parse_requirements,
    "pyproject.toml": parse_pyproject,
    "poetry.lock": parse_poetry_lock,
    "pom.xml": parse_pom,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "go.mod": parse_go_mod,
    "go.sum": parse_go_sum,
    "cargo.lock": parse_cargo_lock,
    "gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
}

SUPPORTED = sorted(set(PARSERS) | {"*.csproj"})


def parser_for(filename: str):
    name = PurePosixPath(filename).name.lower()
    if name in PARSERS:
        return PARSERS[name]
    if name.endswith(".csproj"):
        return parse_csproj
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements
    return None


def parse_manifest(filename: str, text: str) -> ManifestResult:
    parser = parser_for(filename)
    if parser is None:
        raise UnsupportedManifest(
            f"{filename} is not a manifest Vulncano understands. Supported: {', '.join(SUPPORTED)}"
        )
    try:
        result = parser(text)
    except UnsupportedManifest:
        raise
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, KeyError, ValueError) as exc:
        raise UnsupportedManifest(f"{filename} could not be parsed: {exc}") from exc
    if not result.dependencies:
        result.warnings.append(f"{filename}: no dependencies found")
    return result
