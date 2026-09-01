import pytest
from conftest import fixture_text

from vulncano.manifests import UnsupportedManifest, parse_manifest


def coordinates(result):
    return {f"{item.ecosystem}:{item.name}@{item.version}" for item in result.dependencies}


def parse(name):
    return parse_manifest(name, fixture_text("manifests", name))


def test_requirements_pins_and_warnings():
    result = parse("requirements.txt")
    assert "PyPI:Flask@2.0.1" in coordinates(result)
    assert "PyPI:PyYAML@5.3.1" in coordinates(result)
    assert any("urllib3" in warning for warning in result.warnings)
    assert any("cryptography" in warning for warning in result.warnings)


def test_pyproject_reads_both_layouts():
    result = parse("pyproject.toml")
    assert "PyPI:Flask@2.0.1" in coordinates(result)
    assert "PyPI:pytest@7.4.0" in coordinates(result)


def test_poetry_lock():
    assert coordinates(parse("poetry.lock")) == {"PyPI:flask@2.0.1", "PyPI:jinja2@2.11.2"}


def test_pom_resolves_properties_and_reports_inherited_versions():
    result = parse("pom.xml")
    assert "Maven:org.apache.logging.log4j:log4j-core@2.14.1" in coordinates(result)
    assert "Maven:com.fasterxml.jackson.core:jackson-databind@2.9.10.4" in coordinates(result)
    assert any("spring-core" in warning for warning in result.warnings)


def test_package_json_strips_ranges_and_reports_git_dependencies():
    result = parse("package.json")
    assert "npm:lodash@4.17.15" in coordinates(result)
    assert "npm:minimist@0.0.8" in coordinates(result)
    assert "npm:express@4.17.1" in coordinates(result)
    assert any("legacy-helper" in warning for warning in result.warnings)


def test_package_lock_v3():
    result = parse("package-lock.json")
    assert "npm:lodash@4.17.15" in coordinates(result)
    assert "npm:express@4.17.1" in coordinates(result)


def test_yarn_lock_handles_scoped_packages():
    result = parse("yarn.lock")
    assert "npm:lodash@4.17.15" in coordinates(result)
    assert "npm:@babel/core@7.12.3" in coordinates(result)


def test_go_mod_block_and_single_require():
    result = parse("go.mod")
    assert "Go:github.com/gin-gonic/gin@1.7.2" in coordinates(result)
    assert "Go:github.com/stretchr/testify@1.7.0" in coordinates(result)


def test_go_sum_ignores_the_go_mod_hashes():
    result = parse("go.sum")
    assert coordinates(result) == {"Go:github.com/gin-gonic/gin@1.7.2", "Go:golang.org/x/text@0.3.5"}


def test_cargo_lock():
    assert "crates.io:time@0.1.44" in coordinates(parse("Cargo.lock"))


def test_gemfile_lock_reads_only_the_specs_block():
    result = parse("Gemfile.lock")
    assert "RubyGems:actionpack@5.2.4.3" in coordinates(result)
    assert "RubyGems:nokogiri@1.10.9" in coordinates(result)
    assert not any(item.name == "DEPENDENCIES" for item in result.dependencies)


def test_composer_lock_strips_the_v_prefix():
    result = parse("composer.lock")
    assert "Packagist:symfony/http-kernel@4.4.12" in coordinates(result)
    assert "Packagist:phpunit/phpunit@8.5.8" in coordinates(result)


def test_csproj_reports_central_package_management():
    result = parse("Sample.csproj")
    assert "NuGet:Newtonsoft.Json@12.0.2" in coordinates(result)
    assert any("Serilog" in warning for warning in result.warnings)


def test_purl_generation():
    result = parse("pom.xml")
    log4j = next(item for item in result.dependencies if item.name.endswith("log4j-core"))
    assert log4j.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def test_unknown_file_names_the_supported_ones():
    with pytest.raises(UnsupportedManifest, match="requirements.txt"):
        parse_manifest("random.txt", "whatever")


def test_broken_json_is_reported_not_swallowed():
    with pytest.raises(UnsupportedManifest, match="could not be parsed"):
        parse_manifest("package.json", "{not json")
