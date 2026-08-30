//! Runtime support classification for accepted `ssh_config` keywords.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeywordSupport {
    Runtime(RuntimeConsumer),
    Unimplemented,
    Delegated(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimeConsumer {
    NodeResolution,
    Authentication,
    HostVerification,
    Transport,
    Proxy,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct KeywordSpec {
    pub canonical: &'static str,
    pub support: KeywordSupport,
}

use KeywordSupport::{Delegated, Runtime, Unimplemented};
use RuntimeConsumer::{
    Authentication, HostVerification, NodeResolution, Proxy, Session, Transport,
};

pub(super) const ACCEPTED_KEYWORDS: &[(&str, &str, KeywordSupport)] = &[
    ("hostname", "hostname", Runtime(NodeResolution)),
    ("user", "user", Runtime(NodeResolution)),
    ("port", "port", Runtime(NodeResolution)),
    ("identityfile", "identityfile", Runtime(Authentication)),
    ("identitiesonly", "identitiesonly", Delegated(296)),
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
    ("certificatefile", "certificatefile", Delegated(296)),
    (
        "pubkeyauthentication",
        "pubkeyauthentication",
        Delegated(296),
    ),
    (
        "passwordauthentication",
        "passwordauthentication",
        Delegated(296),
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
        Delegated(296),
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
        Delegated(296),
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
    ("localforward", "localforward", Delegated(298)),
    ("remoteforward", "remoteforward", Delegated(298)),
    ("dynamicforward", "dynamicforward", Delegated(298)),
    ("gatewayports", "gatewayports", Unimplemented),
    (
        "exitonforwardfailure",
        "exitonforwardfailure",
        Delegated(298),
    ),
    ("permitremoteopen", "permitremoteopen", Unimplemented),
    ("clearallforwardings", "clearallforwardings", Delegated(298)),
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
    ("batchmode", "batchmode", Delegated(296)),
    ("compression", "compression", Runtime(Transport)),
    ("tcpkeepalive", "tcpkeepalive", Runtime(Transport)),
    ("addressfamily", "addressfamily", Runtime(Transport)),
    ("bindaddress", "bindaddress", Delegated(300)),
    ("bindinterface", "bindinterface", Delegated(300)),
    ("ipqos", "ipqos", Delegated(300)),
    ("rekeylimit", "rekeylimit", Delegated(301)),
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
    use std::collections::{HashMap, HashSet};

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
            ("pubkeyacceptedalgorithms", Authentication),
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
            ("serveraliveinterval", Transport),
            ("serveralivecountmax", Transport),
            ("connectionattempts", Transport),
            ("compression", Transport),
            ("tcpkeepalive", Transport),
            ("addressfamily", Transport),
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
                    KeywordSupport::Delegated(_) | KeywordSupport::Unimplemented => None,
                }
            })
            .collect::<Vec<_>>();

        assert_eq!(runtime, expected);
    }

    #[test]
    fn first_wave_delegations_match_the_split_issue_dag() {
        let expected = HashMap::from([
            ("identitiesonly", 296),
            ("certificatefile", 296),
            ("preferredauthentications", 296),
            ("pubkeyauthentication", 296),
            ("passwordauthentication", 296),
            ("numberofpasswordprompts", 296),
            ("batchmode", 296),
            ("localforward", 298),
            ("remoteforward", 298),
            ("dynamicforward", 298),
            ("clearallforwardings", 298),
            ("exitonforwardfailure", 298),
            ("ipqos", 300),
            ("bindaddress", 300),
            ("bindinterface", 300),
            ("rekeylimit", 301),
        ]);
        let delegated = ACCEPTED_KEYWORDS
            .iter()
            .filter_map(|(keyword, canonical, support)| match support {
                KeywordSupport::Delegated(issue) if keyword == canonical => {
                    Some((*keyword, *issue))
                }
                _ => None,
            })
            .collect::<HashMap<_, _>>();

        assert_eq!(delegated, expected);
    }
}
