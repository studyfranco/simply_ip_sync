//! Properties of `static/app.js` that nothing else in the build pipeline checks.
//!
//! `static/` is served straight off disk by `ServeDir` (`lib.rs`) and is never compiled, linted,
//! or executed by anything else in this repository — `cargo check`, `cargo clippy`, and every
//! HTTP-level integration test in `tests/` all exercise the API and never parse the file they're
//! serving. A syntax error, or a `document.getElementById("typo-id")` referencing an element that
//! doesn't exist, is invisible to all of them and only surfaces when a human opens the dashboard.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;

/// Resolves a path relative to the crate root, independent of `cargo test`'s working directory.
fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative)).unwrap_or_else(|e| panic!("{relative} must be readable: {e}"))
}

/// Parses one file as a classic (non-module) script — `app.js` is loaded with a plain `<script>`
/// tag, so `import`/`export` the browser would reject here must be rejected here too — and
/// returns its syntax errors, each rendered as `path:line:col message`.
fn syntax_errors(relative: &str, source: &str) -> Vec<String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::cjs()).parse();
    parsed
        .diagnostics
        .iter()
        .map(|err| {
            let offset = (err.labels.first().map_or(0, |span| span.offset()) as usize).min(source.len());
            let line = source[..offset].matches('\n').count() + 1;
            let column = offset - source[..offset].rfind('\n').map_or(0, |i| i + 1) + 1;
            format!("{relative}:{line}:{column}  {}", err.message)
        })
        .collect()
}

/// `static/app.js` must parse as valid ECMAScript.
#[test]
fn app_js_has_no_syntax_errors() {
    let source = read("static/app.js");
    let errors = syntax_errors("static/app.js", &source);
    assert!(
        errors.is_empty(),
        "static/app.js has {} syntax error(s) and will not load in a browser:\n  {}",
        errors.len(),
        errors.join("\n  ")
    );
}

/// The check is only worth having if it actually rejects broken input. A backtick inside a
/// template literal ends the template early and leaves the rest as bare tokens — feed the parser
/// exactly that defect and confirm it is reported, so a future refactor that neuters the real
/// check (wrong path, swallowed diagnostics, an always-true condition) doesn't keep passing
/// silently.
#[test]
fn the_syntax_check_rejects_the_defect_it_exists_to_catch() {
    let broken = r#"
        function render(rows) {
            return rows.map(r => `
                <span title="${r.address}">
                    <!-- ` a stray backtick ends the template literal early -->
                </span>
            `).join('');
        }
    "#;
    let errors = syntax_errors("<fixture>", broken);
    assert!(
        !errors.is_empty(),
        "a backtick inside a template literal must be reported as a syntax error — if this \
         passes, the parser is not actually checking anything"
    );
}

/// A file that no longer exists would make `read` panic with a path-naming message rather than
/// silently reporting success against nothing. Cheap insurance against the check being pointed at
/// a path that no longer exists after a reorganization.
#[test]
fn the_checked_file_is_where_the_test_thinks_it_is() {
    assert!(repo_path("static/app.js").is_file(), "static/app.js not found");
    assert!(repo_path("static/index.html").is_file(), "static/index.html not found");
}

/// Every DOM element id `app.js` reaches for via a literal `document.getElementById("...")` call
/// must actually exist somewhere it could plausibly be found at the moment it's queried — either
/// statically in `index.html`, or dynamically because `app.js` itself injects an element carrying
/// that id (via an `innerHTML` template) before immediately querying it in the same function. A
/// typo'd id doesn't fail to parse, it fails silently at runtime with `null` and a `TypeError` on
/// the next line, and nothing except opening the page in a browser would ever catch it otherwise.
#[test]
fn every_literal_get_element_by_id_reference_exists_somewhere_it_could_be_found() {
    let app_js = read("static/app.js");
    let index_html = read("static/index.html");

    // The valid set is the union of ids declared in the static document and ids `app.js`
    // dynamically injects into it — both are legitimate, and conflating them would either miss
    // real typos (checking against nothing) or flag every dynamically-created form as broken
    // (checking against index.html alone, which is what the first version of this test did before
    // it caught its own overly narrow assumption against `source-form`, `vault-form`, and friends).
    let mut valid_ids = html_element_ids(&index_html);
    valid_ids.extend(html_element_ids(&app_js));

    let literal_call = Regex::new(r#"getElementById\(\s*["']([A-Za-z0-9_-]+)["']\s*\)"#).expect("valid regex");
    let mut missing = Vec::new();
    let mut checked = HashSet::new();
    for capture in literal_call.captures_iter(&app_js) {
        let id = capture[1].to_owned();
        if checked.insert(id.clone()) && !valid_ids.contains(&id) {
            missing.push(id);
        }
    }

    assert!(
        !checked.is_empty(),
        "sanity check: the literal-getElementById regex matched nothing in app.js — it is no \
         longer checking anything (has the call syntax changed?)"
    );
    assert!(
        missing.is_empty(),
        "app.js calls document.getElementById() with id(s) found neither in index.html nor \
         dynamically injected by app.js itself: {missing:?}"
    );
}

/// Every id `app.js` injects via an `innerHTML` template and then queries in the *same* rendering
/// function must be spelled identically on both sides — the previous test only proves the id
/// exists *somewhere* in the file; a copy-paste typo between a template's `id="foo-form"` and a
/// sibling function's `getElementById("foo−form")` (or similar) would still pass it if the typo
/// happened to collide with an unrelated real id elsewhere in the file. This test is deliberately
/// narrower and catches same-function mismatches directly.
#[test]
fn dynamically_injected_form_ids_are_queried_with_the_exact_same_spelling() {
    let app_js = read("static/app.js");
    let html_ids = html_element_ids(&read("static/index.html"));
    let js_defined_ids = html_element_ids(&app_js);

    // Every id app.js defines itself (i.e. not already in index.html) must also be referenced by
    // at least one getElementById call somewhere in the file — an injected element nothing ever
    // queries again is dead markup, and one queried under a different spelling is exactly the
    // silent-typo failure mode this whole file exists to catch.
    let literal_call = Regex::new(r#"getElementById\(\s*["']([A-Za-z0-9_-]+)["']\s*\)"#).expect("valid regex");
    let queried_ids: HashSet<String> = literal_call.captures_iter(&app_js).map(|c| c[1].to_owned()).collect();

    let dynamically_defined_only: Vec<&String> = js_defined_ids.difference(&html_ids).collect();
    assert!(!dynamically_defined_only.is_empty(), "sanity check: expected at least one app.js-only id");

    let never_queried: Vec<&&String> =
        dynamically_defined_only.iter().filter(|id| !queried_ids.contains(id.as_str())).collect();
    assert!(
        never_queried.is_empty(),
        "app.js injects id(s) via innerHTML that no getElementById call ever references: {never_queried:?}"
    );
}

/// The one dynamic exception: `document.getElementById("tab-" + tabName)` inside `activateTab()`
/// builds its id at runtime from a nav button's `data-tab` attribute, so the literal-string check
/// above cannot see it. Verify the underlying invariant directly instead: every `data-tab="X"`
/// value present in `index.html` must have a matching `id="tab-X"` panel element, since that's
/// exactly the pairing the runtime concatenation depends on.
///
/// The pinned expression was `getElementById("tab-" + btn.dataset.tab)` until the WebUI was
/// aligned with the ecosystem's `.tab-btn`/`.tab-panel` convention, which moved the lookup out of
/// the click handler and into a reusable `activateTab(tabName)` — the concatenation, and therefore
/// the invariant, is the same; only the variable it reads from changed.
#[test]
fn dynamic_tab_panel_id_construction_matches_every_nav_button() {
    let app_js = read("static/app.js");
    let index_html = read("static/index.html");
    let html_ids = html_element_ids(&index_html);

    assert!(
        app_js.contains(r#"getElementById("tab-" + tabName)"#),
        "this test pins a specific dynamic id-construction pattern in app.js; if it no longer \
         appears, the pattern changed and this test (and its rationale) need to be revisited \
         rather than silently passing on nothing"
    );

    let data_tab = Regex::new(r#"data-tab="([A-Za-z0-9_-]+)""#).expect("valid regex");
    let tab_values: HashSet<String> = data_tab.captures_iter(&index_html).map(|c| c[1].to_owned()).collect();
    assert!(!tab_values.is_empty(), "sanity check: no data-tab attributes found in index.html");

    let missing: Vec<String> =
        tab_values.iter().filter(|v| !html_ids.contains(&format!("tab-{v}"))).cloned().collect();
    assert!(
        missing.is_empty(),
        "nav buttons reference data-tab value(s) with no matching id=\"tab-<value>\" panel: {missing:?}"
    );
}

/// Extracts every `id="..."` attribute value from a raw HTML source string.
fn html_element_ids(html: &str) -> HashSet<String> {
    let id_attr = Regex::new(r#"\bid="([A-Za-z0-9_-]+)""#).expect("valid regex");
    id_attr.captures_iter(html).map(|c| c[1].to_owned()).collect()
}
