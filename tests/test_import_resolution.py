"""Tests for per-language import resolution in the triage connectivity graph.

Connectivity decides CONNECTED_ALIVE versus DEAD_WEIGHT, which in turn decides
what every detector is allowed to look at. A resolution error therefore does
not produce a wrong number in a report -- it silently removes a file from the
audit, or keeps a genuinely orphaned one in it. The cases below are the ones
the previous stem-tally could not tell apart.
"""
from __future__ import annotations

from forge.detector.imports import (
    csharp_references,
    go_references,
    java_references,
    javascript_references,
    php_references,
    resolved_references,
    ruby_references,
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
    write(tmp_path, "legacy.cpp", "int main() { return 0; }\n")
    write(tmp_path, "main.py", "x = 1\n")
    limitations = " ".join(triage(tmp_path).limitations)
    assert "C++" in limitations
    assert "approximated" in limitations


def test_triage_makes_no_approximation_claim_for_resolved_languages(tmp_path):
    write(tmp_path, "go.mod", "module demo\n")
    write(tmp_path, "main.go", "package main\n\nfunc main() {}\n")
    write(tmp_path, "Main.java", "package app;\npublic class Main {}\n")
    write(tmp_path, "app.rb", "puts 1\n")
    write(tmp_path, "index.php", "<?php\n")
    assert not any("approximated" in item for item in triage(tmp_path).limitations)


# --------------------------------------------------------------------------
# Java
# --------------------------------------------------------------------------

def test_java_import_resolves_through_the_declared_package(tmp_path):
    write(tmp_path, "src/com/example/app/Main.java",
          "package com.example.app;\nimport com.example.store.Repo;\npublic class Main {}\n")
    write(tmp_path, "src/com/example/store/Repo.java",
          "package com.example.store;\npublic class Repo {}\n")
    references = java_references(tmp_path, sources(tmp_path))
    assert references["src/com/example/store/Repo.java"] == {"src/com/example/app/Main.java"}


def test_java_wildcard_import_credits_the_whole_package(tmp_path):
    write(tmp_path, "app/Main.java", "package app;\nimport store.*;\npublic class Main {}\n")
    write(tmp_path, "store/Repo.java", "package store;\npublic class Repo {}\n")
    write(tmp_path, "store/Row.java", "package store;\npublic class Row {}\n")
    references = java_references(tmp_path, sources(tmp_path))
    assert references["store/Repo.java"] == {"app/Main.java"}
    assert references["store/Row.java"] == {"app/Main.java"}


def test_java_same_package_siblings_are_counted_without_an_import(tmp_path):
    # Java requires no import for a sibling type, so an import-only resolver
    # would report every same-package collaborator as dead weight.
    write(tmp_path, "app/Service.java", "package app;\nclass Service { Repo repo; }\n")
    write(tmp_path, "app/Repo.java", "package app;\nclass Repo {}\n")
    assert java_references(tmp_path, sources(tmp_path))["app/Repo.java"] == {"app/Service.java"}


def test_java_simple_name_does_not_reach_across_packages(tmp_path):
    # Two classes called Repo in different packages are different classes.
    write(tmp_path, "app/Service.java", "package app;\nclass Service { Repo repo; }\n")
    write(tmp_path, "app/Repo.java", "package app;\nclass Repo {}\n")
    write(tmp_path, "other/Repo.java", "package other;\nclass Repo {}\n")
    references = java_references(tmp_path, sources(tmp_path))
    assert references["app/Repo.java"] == {"app/Service.java"}
    assert references["other/Repo.java"] == set()


def test_java_import_of_an_external_library_credits_nothing(tmp_path):
    write(tmp_path, "app/Main.java",
          "package app;\nimport java.util.List;\nimport com.google.common.io.Files;\nclass Main {}\n")
    write(tmp_path, "util/List.java", "package util;\nclass List {}\n")
    assert java_references(tmp_path, sources(tmp_path))["util/List.java"] == set()


# --------------------------------------------------------------------------
# C#
# --------------------------------------------------------------------------

def test_csharp_using_credits_every_file_in_the_namespace(tmp_path):
    write(tmp_path, "App/Program.cs", "using Example.Data;\nnamespace Example.App;\nclass Program {}\n")
    write(tmp_path, "Data/Repo.cs", "namespace Example.Data;\nclass Repo {}\n")
    write(tmp_path, "Data/Row.cs", "namespace Example.Data { class Row {} }\n")
    references = csharp_references(tmp_path, sources(tmp_path))
    assert references["Data/Repo.cs"] == {"App/Program.cs"}
    assert references["Data/Row.cs"] == {"App/Program.cs"}


def test_csharp_same_namespace_types_are_counted_without_a_using(tmp_path):
    write(tmp_path, "Service.cs", "namespace App;\nclass Service { Repo repo; }\n")
    write(tmp_path, "Repo.cs", "namespace App;\nclass Repo {}\n")
    assert csharp_references(tmp_path, sources(tmp_path))["Repo.cs"] == {"Service.cs"}


def test_csharp_using_of_a_framework_namespace_credits_nothing(tmp_path):
    write(tmp_path, "Program.cs", "using System.IO;\nnamespace App;\nclass Program {}\n")
    write(tmp_path, "Helpers/IO.cs", "namespace Helpers;\nclass IO {}\n")
    assert csharp_references(tmp_path, sources(tmp_path))["Helpers/IO.cs"] == set()


# --------------------------------------------------------------------------
# Ruby
# --------------------------------------------------------------------------

def test_ruby_require_relative_resolves_against_the_requiring_file(tmp_path):
    write(tmp_path, "lib/app.rb", "require_relative 'store'\n")
    write(tmp_path, "lib/store.rb", "class Store; end\n")
    assert ruby_references(tmp_path, sources(tmp_path))["lib/store.rb"] == {"lib/app.rb"}


def test_ruby_bare_require_resolves_through_load_path_conventions(tmp_path):
    write(tmp_path, "bin/run.rb", "require 'store/order'\n")
    write(tmp_path, "lib/store/order.rb", "class Order; end\n")
    assert ruby_references(tmp_path, sources(tmp_path))["lib/store/order.rb"] == {"bin/run.rb"}


def test_ruby_constant_reference_reaches_an_autoloaded_file(tmp_path):
    # A Rails application often contains no `require` at all: a file is reached
    # purely by something naming the constant it defines.
    write(tmp_path, "app/controllers/orders_controller.rb",
          "class OrdersController\n  def index\n    OrderRepository.new.all\n  end\nend\n")
    write(tmp_path, "app/models/order_repository.rb", "class OrderRepository; end\n")
    references = ruby_references(tmp_path, sources(tmp_path))
    assert references["app/models/order_repository.rb"] == {
        "app/controllers/orders_controller.rb",
    }


def test_ruby_ambiguous_constant_credits_nobody(tmp_path):
    # Two files claiming `Config` would each inherit the other's callers, which
    # is exactly the defect the stem tally had.
    write(tmp_path, "a/config.rb", "class Config; end\n")
    write(tmp_path, "b/config.rb", "class Config; end\n")
    write(tmp_path, "app.rb", "Config.load\n")
    references = ruby_references(tmp_path, sources(tmp_path))
    assert references["a/config.rb"] == set()
    assert references["b/config.rb"] == set()


# --------------------------------------------------------------------------
# PHP
# --------------------------------------------------------------------------

def test_php_use_resolves_through_the_declared_namespace(tmp_path):
    write(tmp_path, "src/App/Controller.php",
          "<?php\nnamespace App;\nuse App\\Data\\Repo;\nclass Controller {}\n")
    write(tmp_path, "src/App/Data/Repo.php", "<?php\nnamespace App\\Data;\nclass Repo {}\n")
    references = php_references(tmp_path, sources(tmp_path))
    assert references["src/App/Data/Repo.php"] == {"src/App/Controller.php"}


def test_php_literal_require_resolves_relative_to_the_including_file(tmp_path):
    write(tmp_path, "public/index.php", "<?php\nrequire_once __DIR__ . '/../src/boot.php';\n")
    write(tmp_path, "src/boot.php", "<?php\n")
    assert php_references(tmp_path, sources(tmp_path))["src/boot.php"] == {"public/index.php"}


def test_php_use_of_a_vendor_namespace_credits_nothing(tmp_path):
    write(tmp_path, "src/Controller.php",
          "<?php\nnamespace App;\nuse Symfony\\Component\\HttpFoundation\\Request;\nclass Controller {}\n")
    write(tmp_path, "src/Request.php", "<?php\nnamespace App;\nclass Request {}\n")
    assert php_references(tmp_path, sources(tmp_path))["src/Request.php"] == set()


# --------------------------------------------------------------------------
# Classification effect
# --------------------------------------------------------------------------

def test_resolution_separates_a_live_java_class_from_an_orphaned_namesake(tmp_path):
    write(tmp_path, "app/Main.java", "package app;\nimport app.store.Repo;\nclass Main {}\n")
    write(tmp_path, "app/store/Repo.java", "package app.store;\nclass Repo {}\n")
    write(tmp_path, "legacy/Repo.java", "package legacy;\nclass Repo {}\n")
    modules = classify(tmp_path)
    assert modules["app/store/Repo.java"].module_class.value == "CONNECTED_ALIVE"
    assert modules["legacy/Repo.java"].module_class.value != "CONNECTED_ALIVE"


# --------------------------------------------------------------------------
# Framework entry points
# --------------------------------------------------------------------------

def test_a_framework_controller_is_not_dead_weight_in_any_language(tmp_path):
    # Nothing imports a controller -- the framework dispatches into it. Left
    # unrecognised it scores zero references and drops out of detector scope,
    # which discards the exact file where untrusted input enters.
    write(tmp_path, "src/com/acme/web/OrderController.java",
          "package com.acme.web;\npublic class OrderController {}\n")
    write(tmp_path, "app/controllers/orders_controller.rb", "class OrdersController; end\n")
    write(tmp_path, "src/Http/OrderController.php", "<?php\nnamespace Acme\\Http;\nclass OrderController {}\n")
    write(tmp_path, "Api/OrderController.cs", "namespace Acme.Api;\nclass OrderController {}\n")
    modules = classify(tmp_path)
    for path in modules:
        assert modules[path].module_class.value == "CONNECTED_ALIVE", path


def test_an_orphan_beside_a_controller_is_still_dead_weight(tmp_path):
    # The entry-point convention must not become a blanket amnesty.
    write(tmp_path, "app/controllers/orders_controller.rb", "class OrdersController; end\n")
    write(tmp_path, "app/services/legacy_importer.rb", "class LegacyImporter; end\n")
    modules = classify(tmp_path)
    assert modules["app/controllers/orders_controller.rb"].module_class.value == "CONNECTED_ALIVE"
    assert modules["app/services/legacy_importer.rb"].module_class.value != "CONNECTED_ALIVE"


def test_a_path_convention_does_not_vouch_for_another_language(tmp_path):
    # `app/controllers/` is a Rails convention and says nothing about a Go file
    # that happens to sit in a directory of that name.
    from forge.languages import is_framework_entry_point

    assert is_framework_entry_point("app/controllers/orders_controller.rb")
    assert not is_framework_entry_point("app/controllers/handler.go")
    assert is_framework_entry_point("src/web/OrderController.java")
    assert not is_framework_entry_point("src/web/OrderController.rb")
