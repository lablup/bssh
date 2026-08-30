//! Runtime support classification for accepted `ssh_config` keywords.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeywordSupport {
    Runtime(RuntimeConsumer),
    Unimplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimeConsumer {
    NodeResolution,
    Authentication,
    HostVerification,
    Transport,
    Proxy,
    Session,
    Forwarding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct KeywordSpec {
    pub canonical: &'static str,
    pub support: KeywordSupport,
}

use KeywordSupport::{Runtime, Unimplemented};
use RuntimeConsumer::{
    Authentication, Forwarding, HostVerification, NodeResolution, Proxy, Session, Transport,
};

pub(super) const ACCEPTED_KEYWORDS: &[(&str, &str, KeywordSupport)] = &[
    ("hostname", "hostname", Runtime(NodeResolution)),
    ("user", "user", Runtime(NodeResolution)),
    ("port", "port", Runtime(NodeResolution)),
    ("identityfile", "identityfile", Runtime(Authentication)),
    ("identitiesonly", "identitiesonly", Runtime(Authentication)),
    ("addkeystoagent", "addkeystoagent", Unimplemented),
    ("identityagent", "identityagent", Unimplemented),
    (
        "pubkeyacceptedalgorithms",
        "pubkeyacceptedalgorithms",
        Runtime(Authentication),
    ),
    (
        "pubkeyacceptedkeytypes",
        "pubkeyacceptedalgorithms",
        Runtime(Authentication),
    ),
    (
        "certificatefile",
        "certificatefile",
        Runtime(Authentication),
    ),
    (
        "pubkeyauthentication",
        "pubkeyauthentication",
        Runtime(Authentication),
    ),
    (
        "passwordauthentication",
        "passwordauthentication",
        Runtime(Authentication),
    ),
    (
        "kbdinteractiveauthentication",
        "kbdinteractiveauthentication",
        Unimplemented,
    ),
    (
        "challengeresponseauthentication",
        "kbdinteractiveauthentication",
        Unimplemented,
    ),
    (
        "gssapiauthentication",
        "gssapiauthentication",
        Unimplemented,
    ),
    (
        "preferredauthentications",
        "preferredauthentications",
        Runtime(Authentication),
    ),
    (
        "hostbasedauthentication",
        "hostbasedauthentication",
        Unimplemented,
    ),
    (
        "hostbasedacceptedalgorithms",
        "hostbasedacceptedalgorithms",
        Unimplemented,
    ),
    (
        "hostbasedkeytypes",
        "hostbasedacceptedalgorithms",
        Unimplemented,
    ),
    (
        "numberofpasswordprompts",
        "numberofpasswordprompts",
        Runtime(Authentication),
    ),
    ("enablesshkeysign", "enablesshkeysign", Unimplemented),
    ("usekeychain", "usekeychain", Unimplemented),
    (
        "stricthostkeychecking",
        "stricthostkeychecking",
        Runtime(HostVerification),
    ),
    (
        "userknownhostsfile",
        "userknownhostsfile",
        Runtime(HostVerification),
    ),
    (
        "globalknownhostsfile",
        "globalknownhostsfile",
        Runtime(HostVerification),
    ),
    ("hostkeyalgorithms", "hostkeyalgorithms", Runtime(Transport)),
    ("kexalgorithms", "kexalgorithms", Runtime(Transport)),
    ("ciphers", "ciphers", Runtime(Transport)),
    ("macs", "macs", Runtime(Transport)),
    (
        "casignaturealgorithms",
        "casignaturealgorithms",
        Unimplemented,
    ),
    (
        "nohostauthenticationforlocalhost",
        "nohostauthenticationforlocalhost",
        Unimplemented,
    ),
    (
        "hashknownhosts",
        "hashknownhosts",
        Runtime(HostVerification),
    ),
    ("checkhostip", "checkhostip", Runtime(HostVerification)),
    ("visualhostkey", "visualhostkey", Unimplemented),
    ("hostkeyalias", "hostkeyalias", Runtime(HostVerification)),
    (
        "verifyhostkeydns",
        "verifyhostkeydns",
        Runtime(HostVerification),
    ),
    (
        "updatehostkeys",
        "updatehostkeys",
        Runtime(HostVerification),
    ),
    ("requiredrsasize", "requiredrsasize", Unimplemented),
    ("fingerprinthash", "fingerprinthash", Unimplemented),
    ("forwardagent", "forwardagent", Unimplemented),
    ("forwardx11", "forwardx11", Unimplemented),
    ("localforward", "localforward", Runtime(Forwarding)),
    ("remoteforward", "remoteforward", Runtime(Forwarding)),
    ("dynamicforward", "dynamicforward", Runtime(Forwarding)),
    ("gatewayports", "gatewayports", Unimplemented),
    (
        "exitonforwardfailure",
        "exitonforwardfailure",
        Runtime(Forwarding),
    ),
    ("permitremoteopen", "permitremoteopen", Unimplemented),
    (
        "clearallforwardings",
        "clearallforwardings",
        Runtime(Forwarding),
    ),
    ("forwardx11timeout", "forwardx11timeout", Unimplemented),
    ("forwardx11trusted", "forwardx11trusted", Unimplemented),
    (
        "serveraliveinterval",
        "serveraliveinterval",
        Runtime(Transport),
    ),
    (
        "serveralivecountmax",
        "serveralivecountmax",
        Runtime(Transport),
    ),
    ("connecttimeout", "connecttimeout", Unimplemented),
    (
        "connectionattempts",
        "connectionattempts",
        Runtime(Transport),
    ),
    ("batchmode", "batchmode", Runtime(Authentication)),
    ("compression", "compression", Runtime(Transport)),
    ("tcpkeepalive", "tcpkeepalive", Runtime(Transport)),
    ("addressfamily", "addressfamily", Runtime(Transport)),
    ("bindaddress", "bindaddress", Runtime(Transport)),
    ("bindinterface", "bindinterface", Runtime(Transport)),
    ("ipqos", "ipqos", Runtime(Transport)),
    ("rekeylimit", "rekeylimit", Runtime(Transport)),
    ("proxyjump", "proxyjump", Runtime(Proxy)),
    ("proxycommand", "proxycommand", Runtime(Proxy)),
    ("proxyusefdpass", "proxyusefdpass", Runtime(Proxy)),
    ("controlmaster", "controlmaster", Unimplemented),
    ("controlpath", "controlpath", Unimplemented),
    ("controlpersist", "controlpersist", Unimplemented),
    ("sendenv", "sendenv", Runtime(Session)),
    ("setenv", "setenv", Runtime(Session)),
    ("requesttty", "requesttty", Runtime(Session)),
    ("escapechar", "escapechar", Unimplemented),
    ("loglevel", "loglevel", Unimplemented),
    ("syslogfacility", "syslogfacility", Unimplemented),
    ("protocol", "protocol", Unimplemented),
    ("permitlocalcommand", "permitlocalcommand", Runtime(Session)),
    ("localcommand", "localcommand", Runtime(Session)),
    ("remotecommand", "remotecommand", Runtime(Session)),
    (
        "knownhostscommand",
        "knownhostscommand",
        Runtime(HostVerification),
    ),
    (
        "forkafterauthentication",
        "forkafterauthentication",
        Unimplemented,
    ),
    ("sessiontype", "sessiontype", Runtime(Session)),
    ("stdinnull", "stdinnull", Unimplemented),
    ("cipher", "cipher", Unimplemented),
    ("fallbacktorsh", "fallbacktorsh", Unimplemented),
    (
        "globalknownhostsfile2",
        "globalknownhostsfile2",
        Unimplemented,
    ),
    (
        "rhostsauthentication",
        "rhostsauthentication",
        Unimplemented,
    ),
    ("securitykeyprovider", "securitykeyprovider", Unimplemented),
    ("userknownhostsfile2", "userknownhostsfile2", Unimplemented),
    ("useroaming", "useroaming", Unimplemented),
    ("usersh", "usersh", Unimplemented),
    ("useprivilegedport", "useprivilegedport", Unimplemented),
    ("tunneldevice", "tunneldevice", Unimplemented),
];

pub(super) fn keyword_spec(keyword: &str) -> Option<KeywordSpec> {
    ACCEPTED_KEYWORDS
        .iter()
        .find_map(|(accepted, canonical, support)| {
            (*accepted == keyword).then_some(KeywordSpec {
                canonical,
                support: *support,
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const ACCEPTED_SPELLING_COUNT: usize = 92;
    const RUNTIME_SPELLING_COUNT: usize = 51;
    const UNIMPLEMENTED_SPELLING_COUNT: usize = 41;

    #[test]
    fn accepted_keywords_and_aliases_have_one_consistent_classification() {
        let mut seen = HashSet::new();
        for (keyword, canonical, support) in ACCEPTED_KEYWORDS {
            assert!(seen.insert(*keyword), "duplicate keyword: {keyword}");
            assert_eq!(
                keyword_spec(keyword),
                Some(KeywordSpec {
                    canonical,
                    support: *support
                })
            );
            let canonical_spec = keyword_spec(canonical)
                .unwrap_or_else(|| panic!("alias {keyword} has no canonical entry {canonical}"));
            assert_eq!(canonical_spec.canonical, *canonical);
            assert_eq!(canonical_spec.support, *support);
        }

        let runtime_count = ACCEPTED_KEYWORDS
            .iter()
            .filter(|(_, _, support)| matches!(support, KeywordSupport::Runtime(_)))
            .count();
        let unimplemented_count = ACCEPTED_KEYWORDS
            .iter()
            .filter(|(_, _, support)| matches!(support, KeywordSupport::Unimplemented))
            .count();

        assert_eq!(ACCEPTED_KEYWORDS.len(), ACCEPTED_SPELLING_COUNT);
        assert_eq!(runtime_count, RUNTIME_SPELLING_COUNT);
        assert_eq!(unimplemented_count, UNIMPLEMENTED_SPELLING_COUNT);
        assert_eq!(runtime_count + unimplemented_count, ACCEPTED_KEYWORDS.len());
    }

    #[test]
    fn runtime_keywords_are_exactly_the_audited_consumer_set() {
        // Every entry here has both a concrete production consumer and a
        // behavior test at that consumer boundary. Adding a Runtime entry
        // requires extending this audited set, making optimistic parse-only
        // classifications visible in review.
        let expected = [
            ("hostname", NodeResolution),
            ("user", NodeResolution),
            ("port", NodeResolution),
            ("identityfile", Authentication),
            ("identitiesonly", Authentication),
            ("pubkeyacceptedalgorithms", Authentication),
            ("certificatefile", Authentication),
            ("pubkeyauthentication", Authentication),
            ("passwordauthentication", Authentication),
            ("preferredauthentications", Authentication),
            ("numberofpasswordprompts", Authentication),
            ("stricthostkeychecking", HostVerification),
            ("userknownhostsfile", HostVerification),
            ("globalknownhostsfile", HostVerification),
            ("hostkeyalgorithms", Transport),
            ("kexalgorithms", Transport),
            ("ciphers", Transport),
            ("macs", Transport),
            ("hashknownhosts", HostVerification),
            ("checkhostip", HostVerification),
            ("hostkeyalias", HostVerification),
            ("verifyhostkeydns", HostVerification),
            ("updatehostkeys", HostVerification),
            ("localforward", Forwarding),
            ("remoteforward", Forwarding),
            ("dynamicforward", Forwarding),
            ("exitonforwardfailure", Forwarding),
            ("clearallforwardings", Forwarding),
            ("serveraliveinterval", Transport),
            ("serveralivecountmax", Transport),
            ("connectionattempts", Transport),
            ("batchmode", Authentication),
            ("compression", Transport),
            ("tcpkeepalive", Transport),
            ("addressfamily", Transport),
            ("bindaddress", Transport),
            ("bindinterface", Transport),
            ("ipqos", Transport),
            ("rekeylimit", Transport),
            ("proxyjump", Proxy),
            ("proxycommand", Proxy),
            ("proxyusefdpass", Proxy),
            ("sendenv", Session),
            ("setenv", Session),
            ("requesttty", Session),
            ("permitlocalcommand", Session),
            ("localcommand", Session),
            ("remotecommand", Session),
            ("knownhostscommand", HostVerification),
            ("sessiontype", Session),
        ];
        let runtime = ACCEPTED_KEYWORDS
            .iter()
            .filter_map(|(keyword, canonical, support)| {
                if keyword != canonical {
                    return None;
                }
                match support {
                    KeywordSupport::Runtime(consumer) => Some((*keyword, *consumer)),
                    KeywordSupport::Unimplemented => None,
                }
            })
            .collect::<Vec<_>>();

        assert_eq!(runtime, expected);
    }

    #[test]
    fn unimplemented_keywords_are_exactly_the_audited_named_set() {
        let expected = [
            "addkeystoagent",
            "identityagent",
            "kbdinteractiveauthentication",
            "gssapiauthentication",
            "hostbasedauthentication",
            "hostbasedacceptedalgorithms",
            "enablesshkeysign",
            "usekeychain",
            "casignaturealgorithms",
            "nohostauthenticationforlocalhost",
            "visualhostkey",
            "requiredrsasize",
            "fingerprinthash",
            "forwardagent",
            "forwardx11",
            "gatewayports",
            "permitremoteopen",
            "forwardx11timeout",
            "forwardx11trusted",
            "connecttimeout",
            "controlmaster",
            "controlpath",
            "controlpersist",
            "escapechar",
            "loglevel",
            "syslogfacility",
            "protocol",
            "forkafterauthentication",
            "stdinnull",
            "cipher",
            "fallbacktorsh",
            "globalknownhostsfile2",
            "rhostsauthentication",
            "securitykeyprovider",
            "userknownhostsfile2",
            "useroaming",
            "usersh",
            "useprivilegedport",
            "tunneldevice",
        ];
        let unimplemented = ACCEPTED_KEYWORDS
            .iter()
            .filter_map(|(keyword, canonical, support)| match support {
                KeywordSupport::Unimplemented if keyword == canonical => Some(*keyword),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(unimplemented, expected);
    }
}
