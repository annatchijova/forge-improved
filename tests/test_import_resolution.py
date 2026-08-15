"""Tests for per-language import resolution in the triage connectivity graph.

Connectivity decides CONNECTED_ALIVE versus DEAD_WEIGHT, which in turn decides
what every detector is allowed to look at. A resolution error therefore does
not produce a wrong number in a report -- it silently removes a file from the
audit, or keeps a genuinely orphaned one in it. The cases below are the ones
the previous stem-tally could not tell apart.
"""
from __future__ import annotations

from forge.detector.imports import (
    go_references,
    javascript_references,
    resolved_references,
    rust_references,
)
from forge.detector.stack import discover_files, triage


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def sources(root):
    return discover_files(root)


def classify(root):
    return {item.path: item for item in triage(root).modules}


# --------------------------------------------------------------------------
# JavaScript / TypeScript
# --------------------------------------------------------------------------

def test_relative_import_resolves_across_extensions_and_index_files(tmp_path):
    write(tmp_path, "src/index.ts", "import { a } from './util';\nimport { b } from './widget';\n")
    write(tmp_path, "src/util.ts", "export const a = 1;\n")
    write(tmp_path, "src/widget/index.tsx", "export const b = 2;\n")
    references = javascript_references(tmp_path, sources(tmp_path))
    assert references["src/util.ts"] == {"src/index.ts"}
    assert references["src/widget/index.tsx"] == {"src/index.ts"}


def test_a_bare_package_specifier_never_credits_a_local_file(tmp_path):
    # The stem tally credited `store.ts` for `import store from "store"`, an
    # npm dependency that has nothing to do with the local module.
    write(tmp_path, "app.ts", "import store from 'store';\nimport lodash from 'lodash/get';\n")
    write(tmp_path, "store.ts", "export default {};\n")
    references = javascript_references(tmp_path, sources(tmp_path))
    assert references["store.ts"] == set()


def test_same_stem_in_two_directories_is_not_conflated(tmp_path):
    write(tmp_path, "a/index.ts", "import { c } from './config';\n")
    write(tmp_path, "a/config.ts", "export const c = 1;\n")
    write(tmp_path, "b/config.ts", "export const c = 2;\n")
    references = javascript_references(tmp_path, sources(tmp_path))
    assert references["a/config.ts"] == {"a/index.ts"}
    assert references["b/config.ts"] == set(), "an orphan must not inherit its namesake's callers"


def test_typescript_importing_a_js_specifier_resolves_to_the_ts_source(tmp_path):
    write(tmp_path, "src/index.ts", "import { a } from './util.js';\n")
    write(tmp_path, "src/util.ts", "export const a = 1;\n")
    assert javascript_references(tmp_path, sources(tmp_path))["src/util.ts"] == {"src/index.ts"}


def test_require_and_dynamic_import_are_both_resolved(tmp_path):
    write(tmp_path, "index.js", "const a = require('./a');\nconst b = import('./b');\n")
    write(tmp_path, "a.js", "module.exports = 1;\n")
    write(tmp_path, "b.js", "export default 2;\n")
    references = javascript_references(tmp_path, sources(tmp_path))
    assert references["a.js"] == {"index.js"}
    assert references["b.js"] == {"index.js"}


# --------------------------------------------------------------------------
# Go
# --------------------------------------------------------------------------

def test_go_import_resolves_through_the_module_path_to_a_package_directory(tmp_path):
    write(tmp_path, "go.mod", "module github.com/demo/app\n\ngo 1.22\n")
    write(tmp_path, "main.go", 'package main\n\nimport (\n\t"fmt"\n\t"github.com/demo/app/internal/store"\n)\n')
    write(tmp_path, "internal/store/store.go", "package store\n")
    write(tmp_path, "internal/store/query.go", "package store\n")
    references = go_references(tmp_path, sources(tmp_path))
    # A Go import names a package, so every file in that directory is reached.
    assert references["internal/store/store.go"] == {"main.go"}
    assert references["internal/store/query.go"] == {"main.go"}


def test_go_standard_library_import_credits_nothing(tmp_path):
    write(tmp_path, "go.mod", "module github.com/demo/app\n")
    write(tmp_path, "main.go", 'package main\n\nimport "os"\n')
    write(tmp_path, "os/helper.go", "package os\n")
    references = go_references(tmp_path, sources(tmp_path))
    assert references["os/helper.go"] == set()


def test_go_single_line_import_form_is_resolved(tmp_path):
    write(tmp_path, "go.mod", "module demo\n")
    write(tmp_path, "main.go", 'package main\n\nimport alias "demo/pkg"\n')
    write(tmp_path, "pkg/pkg.go", "package pkg\n")
    assert go_references(tmp_path, sources(tmp_path))["pkg/pkg.go"] == {"main.go"}


def test_go_without_a_module_file_only_resolves_unambiguous_suffixes(tmp_path):
    # No go.mod means the import path cannot be anchored. A unique trailing
    # match is accepted; an ambiguous one is left undetermined rather than
    # guessed, because crediting the wrong package is the worse error.
    write(tmp_path, "main.go", 'package main\n\nimport (\n\t"example.com/x/store"\n\t"example.com/x/util"\n)\n')
    write(tmp_path, "store/store.go", "package store\n")
    write(tmp_path, "a/util/util.go", "package util\n")
    write(tmp_path, "b/util/util.go", "package util\n")
    references = go_references(tmp_path, sources(tmp_path))
    assert references["store/store.go"] == {"main.go"}
    assert references["a/util/util.go"] == set()
    assert references["b/util/util.go"] == set()


# --------------------------------------------------------------------------
# Rust
# --------------------------------------------------------------------------

def test_rust_mod_declaration_is_the_connectivity_graph(tmp_path):
    write(tmp_path, "src/main.rs", "mod handlers;\nmod config;\n")
    write(tmp_path, "src/handlers/mod.rs", "pub fn run() {}\n")
    write(tmp_path, "src/config.rs", "pub const N: u8 = 1;\n")
    references = rust_references(tmp_path, sources(tmp_path))
    assert references["src/handlers/mod.rs"] == {"src/main.rs"}
    assert references["src/config.rs"] == {"src/main.rs"}


def test_rust_child_modules_of_a_non_root_file_live_in_its_own_directory(tmp_path):
    write(tmp_path, "src/lib.rs", "mod api;\n")
    write(tmp_path, "src/api.rs", "mod routes;\n")
    write(tmp_path, "src/api/routes.rs", "pub fn get() {}\n")
    references = rust_references(tmp_path, sources(tmp_path))
    assert references["src/api.rs"] == {"src/lib.rs"}
    assert references["src/api/routes.rs"] == {"src/api.rs"}


def test_rust_use_crate_path_also_counts_as_a_reference(tmp_path):
    write(tmp_path, "src/lib.rs", "mod store;\nmod api;\n")
    write(tmp_path, "src/store.rs", "pub struct Db;\n")
    write(tmp_path, "src/api.rs", "use crate::store::Db;\n")
    assert rust_references(tmp_path, sources(tmp_path))["src/store.rs"] == {
        "src/lib.rs", "src/api.rs",
    }


def test_rust_module_reachable_by_no_mod_declaration_stays_unreferenced(tmp_path):
    write(tmp_path, "src/main.rs", "mod used;\n")
    write(tmp_path, "src/used.rs", "pub fn a() {}\n")
    write(tmp_path, "src/orphan.rs", "pub fn b() {}\n")
    references = rust_references(tmp_path, sources(tmp_path))
    assert references["src/used.rs"] == {"src/main.rs"}
    assert references["src/orphan.rs"] == set()


# --------------------------------------------------------------------------
# Cross-language and triage integration
# --------------------------------------------------------------------------

def test_resolvers_never_cross_language_boundaries(tmp_path):
    write(tmp_path, "main.py", "import frontend\nimport store\n")
    write(tmp_path, "frontend.ts", "export const a = 1;\n")
    write(tmp_path, "store.go", "package store\n")
    references = resolved_references(tmp_path, sources(tmp_path))
    assert references["frontend.ts"] == set()
    assert references["store.go"] == set()


def test_entry_points_keep_executables_out_of_dead_weight(tmp_path):
    write(tmp_path, "go.mod", "module demo\n")
    write(tmp_path, "main.go", "package main\n\nfunc main() {}\n")
    write(tmp_path, "src/main.rs", "fn main() {}\n")
    write(tmp_path, "index.ts", "export const start = () => 1;\n")
    modules = classify(tmp_path)
    # An entry point has no importer by construction; without recognising them
    # the one file that is certainly alive would be reported as dead weight.
    for path in ("main.go", "src/main.rs", "index.ts"):
        assert modules[path].module_class.value == "CONNECTED_ALIVE", path


def test_declared_manifest_entry_points_are_honoured(tmp_path):
    write(tmp_path, "package.json", '{"name": "demo", "main": "./lib/server.js"}\n')
    write(tmp_path, "lib/server.js", "module.exports = () => 1;\n")
    assert classify(tmp_path)["lib/server.js"].module_class.value == "CONNECTED_ALIVE"


def test_triage_declares_approximate_connectivity_for_unresolved_languages(tmp_path):
    write(tmp_path, "Legacy.java", "class Legacy {}\n")
    write(tmp_path, "main.py", "x = 1\n")
    limitations = " ".join(triage(tmp_path).limitations)
    assert "Java" in limitations
    assert "approximated" in limitations


def test_triage_makes_no_approximation_claim_for_resolved_languages(tmp_path):
    write(tmp_path, "go.mod", "module demo\n")
    write(tmp_path, "main.go", "package main\n\nfunc main() {}\n")
    assert not any("approximated" in item for item in triage(tmp_path).limitations)
