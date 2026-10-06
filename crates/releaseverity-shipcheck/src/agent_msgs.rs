//! Localization of the agent's step messages.
//!
//! The agent runs inside the clean environment and has no access to the catalogs, so it
//! reports plain English. The host recognises each known message by pattern and maps it to a
//! catalog key (+ arguments) so the UI/CLI/reports can render it in the user's language.
//! Unknown messages are left as the agent wrote them. The tests below feed every message the
//! agent can produce, so drift between agent and catalog is caught at build time.

use regex::Regex;
use releaseverity_core::model::Msg;
use std::sync::OnceLock;

struct Rule {
    re: Regex,
    key: &'static str,
}

const RULES: &[(&str, &str)] = &[
    (r"^installers cannot run inside an AppContainer.*$", "a.sandbox.no-installer"),
    (r"^could not create the AppContainer sandbox: (?P<err>.*)$", "a.sandbox.create-fail"),
    (r"^(?P<tool>msiexec|installer) returned exit code (?P<code>-?\d+): (?P<hint>.*)$", "a.install.exit"),
    (r"^installed \(a reboot is required to finish\)$", "a.install.reboot"),
    (r"^extracted (?P<n>\d+) files$", "a.extract.ok"),
    (r"^could not extract the package: (?P<err>.*)$", "a.extract.fail"),
    (r"^installed (?P<name>.+?) (?P<version>\S*) → (?P<exe>.+)$", "a.files.ok"),
    (r"^application found at (?P<exe>.+) but no Add/Remove Programs entry was registered$", "a.files.noentry"),
    (r"^the installer reported success but no installed application could be found$", "a.files.none"),
    (r"^no executable found in the portable package$", "a.files.noexe"),
    (r"^found (?P<exe>.+)$", "a.files.found"),
    (r"^portable directory removed cleanly$", "a.cleanup.ok"),
    (r"^could not remove the directory: (?P<err>.*)$", "a.cleanup.fail"),
    (r"^APPLICATION HUNG — .*$", "a.launch.hung"),
    (r"^running and responsive after (?P<secs>\d+)s \((?P<windows>\d+) window\(s\)\)$", "a.launch.alive"),
    (r"^process stayed alive but no visible window was created$", "a.launch.nowindow"),
    (r"^exited with code 0 before the alive window elapsed.*$", "a.launch.early0"),
    (r"^exit code (?P<code>-?\d+) as expected$", "a.smoke.ok"),
    (r"^output does not contain (?P<text>.+)$", "a.smoke.output"),
    (r"^exit code (?P<code>-?\d+), expected (?P<expected>-?\d+)$", "a.smoke.exit"),
    (r"^no uninstaller is registered.*$", "a.uninstall.none"),
    (r"^the uninstaller exited successfully but the application files are still present$", "a.uninstall.left-files"),
    (r"^the uninstaller exited successfully but its Add/Remove Programs entry is still registered$", "a.uninstall.left-reg"),
    (r"^uninstalled, but (?P<n>\d+) leftover item\(s\) remain in the install directory$", "a.uninstall.leftovers"),
    (r"^uninstalled cleanly.*$", "a.uninstall.ok"),
    (r"^could not start the process: (?P<err>.*)$", "a.start.fail"),
    (r"^TEST TIMEOUT — still running after (?P<secs>\d+)s; the process tree was terminated$", "a.timeout"),
    (r"^APPLICATION CRASHED — exit code 0x(?P<code>[0-9A-Fa-f]+)$", "a.crash"),
    (r"^exit code (?P<code>-?\d+)$", "a.exit"),
    (r"^still running when stopped$", "a.running"),
    (r"^no installed application to run$", "a.skip.noapp"),
    (r"^nothing was installed$", "a.skip.nothing"),
    (r"^disabled by configuration$", "a.skip.disabled"),
    (r"^launch test not requested$", "a.skip.nolaunch"),
    (r"^could not prepare the sandbox: (?P<err>.*)$", "a.skip.prepfail"),
];

/// Installer exit-code hints (English as produced by the agent → catalog key).
const HINTS: &[(&str, &str)] = &[
    ("Windows Installer service is not accessible", "a.hint.msi.1601"),
    ("installation cancelled by the user", "a.hint.msi.1602"),
    ("fatal error during installation (see the MSI log)", "a.hint.msi.1603"),
    ("another installation is already in progress", "a.hint.msi.1618"),
    ("the installation package could not be opened", "a.hint.msi.1620"),
    ("installation is forbidden by system policy", "a.hint.msi.1625"),
    ("another version of this product is already installed", "a.hint.msi.1638"),
    ("invalid command line argument", "a.hint.msi.1639"),
    ("Windows Installer returned an error (see the MSI log)", "a.hint.msi.default"),
    ("installer reported a generic failure or invalid command line (check the silent-install switches)", "a.hint.exe.1"),
    ("installation cancelled or setup failed to initialise", "a.hint.exe.2"),
    ("access denied (installer needs elevation)", "a.hint.exe.5"),
    ("the installer returned a non-zero exit code", "a.hint.exe.default"),
];

fn rules() -> &'static Vec<Rule> {
    static R: OnceLock<Vec<Rule>> = OnceLock::new();
    R.get_or_init(|| RULES.iter().map(|(p, k)| Rule { re: Regex::new(p).expect("valid pattern"), key: k }).collect())
}

/// Recognise an agent message; `None` when it is not one of the known messages.
pub fn localize(message: &str) -> Option<Msg> {
    for rule in rules() {
        let Some(caps) = rule.re.captures(message) else { continue };
        let mut args: Vec<(String, String)> =
            rule.re.capture_names().flatten().filter_map(|n| caps.name(n).map(|m| (n.to_string(), m.as_str().to_string()))).collect();
        for (k, v) in &mut args {
            if k == "hint" {
                if let Some((_, key)) = HINTS.iter().find(|(en, _)| en == v) {
                    *v = format!("@{key}");
                }
            }
        }
        let refs: Vec<(&str, &str)> = args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        return Some(Msg::new(rule.key, &refs));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use releaseverity_core::i18n::I18n;

    /// Every message the agent can emit, written exactly as the agent formats it.
    const SAMPLES: &[(&str, &str)] = &[
        ("installers cannot run inside an AppContainer: they must write Program Files and HKLM", "a.sandbox.no-installer"),
        ("could not create the AppContainer sandbox: boom", "a.sandbox.create-fail"),
        ("msiexec returned exit code 1603: fatal error during installation (see the MSI log)", "a.install.exit"),
        ("installer returned exit code 1: installer reported a generic failure or invalid command line (check the silent-install switches)", "a.install.exit"),
        ("installed (a reboot is required to finish)", "a.install.reboot"),
        ("extracted 12 files", "a.extract.ok"),
        ("could not extract the package: bad zip", "a.extract.fail"),
        ("installed ReleaseVerity 0.1.0 → C:\\Apps\\ReleaseVerity\\cli\\releaseverity.exe", "a.files.ok"),
        ("application found at C:\\a.exe but no Add/Remove Programs entry was registered", "a.files.noentry"),
        ("the installer reported success but no installed application could be found", "a.files.none"),
        ("no executable found in the portable package", "a.files.noexe"),
        ("found C:\\x\\app.exe", "a.files.found"),
        ("portable directory removed cleanly", "a.cleanup.ok"),
        ("could not remove the directory: access denied", "a.cleanup.fail"),
        ("APPLICATION HUNG — its window stopped responding", "a.launch.hung"),
        ("running and responsive after 5s (1 window(s))", "a.launch.alive"),
        ("process stayed alive but no visible window was created", "a.launch.nowindow"),
        ("exited with code 0 before the alive window elapsed (expected a GUI to keep running)", "a.launch.early0"),
        ("exit code 0 as expected", "a.smoke.ok"),
        ("output does not contain \"zzz\"", "a.smoke.output"),
        ("exit code 3, expected 0", "a.smoke.exit"),
        ("no uninstaller is registered (no Add/Remove Programs entry)", "a.uninstall.none"),
        ("the uninstaller exited successfully but the application files are still present", "a.uninstall.left-files"),
        ("the uninstaller exited successfully but its Add/Remove Programs entry is still registered", "a.uninstall.left-reg"),
        ("uninstalled, but 2 leftover item(s) remain in the install directory", "a.uninstall.leftovers"),
        ("uninstalled cleanly (files and registry entry removed)", "a.uninstall.ok"),
        ("could not start the process: not found", "a.start.fail"),
        ("TEST TIMEOUT — still running after 3s; the process tree was terminated", "a.timeout"),
        ("APPLICATION CRASHED — exit code 0xC0000409", "a.crash"),
        ("exit code 2", "a.exit"),
        ("still running when stopped", "a.running"),
        ("no installed application to run", "a.skip.noapp"),
        ("nothing was installed", "a.skip.nothing"),
        ("disabled by configuration", "a.skip.disabled"),
        ("launch test not requested", "a.skip.nolaunch"),
        ("could not prepare the sandbox: icacls failed", "a.skip.prepfail"),
    ];

    #[test]
    fn every_agent_message_maps_to_a_catalog_key_that_exists_in_both_languages() {
        let (en, tr) = (I18n::new("en"), I18n::new("tr"));
        for (text, key) in SAMPLES {
            let m = localize(text).unwrap_or_else(|| panic!("no rule for agent message {text:?}"));
            assert_eq!(m.key, *key, "{text}");
            assert_ne!(en.t(key), *key, "EN catalog lacks {key}");
            assert_ne!(tr.t(key), *key, "TR catalog lacks {key}");
            assert!(!m.render(&en).contains('{'), "unresolved placeholder in EN for {text}: {}", m.render(&en));
            assert!(!m.render(&tr).contains('{'), "unresolved placeholder in TR for {text}: {}", m.render(&tr));
        }
        for (_, key) in HINTS {
            assert_ne!(tr.t(key), *key, "TR catalog lacks hint {key}");
        }
    }

    #[test]
    fn english_rendering_reproduces_what_the_agent_wrote() {
        let en = I18n::new("en");
        for text in [
            "exit code 3, expected 0",
            "extracted 12 files",
            "TEST TIMEOUT — still running after 3s; the process tree was terminated",
            "APPLICATION CRASHED — exit code 0xC0000409",
        ] {
            assert_eq!(localize(text).unwrap().render(&en), text);
        }
    }

    #[test]
    fn turkish_rendering_translates_arguments_and_nested_hints() {
        let tr = I18n::new("tr");
        let m = localize("msiexec returned exit code 1603: fatal error during installation (see the MSI log)").unwrap();
        let s = m.render(&tr);
        assert!(s.contains("1603") && s.contains("MSI günlüğü"), "{s}");
        assert!(localize("something brand new").is_none());
    }
}
