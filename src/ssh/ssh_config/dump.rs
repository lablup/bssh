// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//! OpenSSH-shaped resolved configuration rendering.

use anyhow::{Context, Result};
use std::fmt::Write as _;

use super::{IpQosPolicy, IpQosValue, RekeyDataLimit, RekeyLimit, RekeyTimeLimit, SshHostConfig};

mod tokens;
use tokens::TokenContext;

pub fn render_resolved_config(original_host: &str, config: &SshHostConfig) -> Result<String> {
    let mut output = DumpWriter::default();
    let mut tokens = TokenContext::new(original_host, config);
    tokens.effective_host = tokens.expand(&tokens.effective_host)?;
    tokens.remote_user = tokens.expand(&tokens.remote_user)?;
    tokens.refresh_hash(config.proxy_jump.as_deref().unwrap_or(""));

    output.line("host", original_host)?;
    output.line("user", &tokens.remote_user)?;
    output.line("hostname", &tokens.effective_host)?;
    output.line("port", &tokens.port)?;
    output.line(
        "addressfamily",
        config.address_family.as_deref().unwrap_or("any"),
    )?;
    output.bool("batchmode", config.batch_mode.unwrap_or(false))?;
    output.bool("checkhostip", config.check_host_ip.unwrap_or(false))?;
    output.bool("compression", config.compression.unwrap_or(false))?;
    output.line(
        "controlmaster",
        config.control_master.as_deref().unwrap_or("false"),
    )?;
    output.bool(
        "clearallforwardings",
        config.clear_all_forwardings.unwrap_or(false),
    )?;
    output.bool(
        "exitonforwardfailure",
        config.exit_on_forward_failure.unwrap_or(false),
    )?;
    output.bool(
        "enablesshkeysign",
        config.enable_ssh_keysign.unwrap_or(false),
    )?;
    output.bool("forwardx11", config.forward_x11.unwrap_or(false))?;
    output.bool(
        "forwardx11trusted",
        config.forward_x11_trusted.unwrap_or(false),
    )?;
    let forward_agent = raw_option(config, "forwardagent")
        .map(|value| tokens.expand_path(&value))
        .transpose()?
        .unwrap_or_else(|| yes_no(config.forward_agent.unwrap_or(false)).to_string());
    output.line("forwardagent", forward_agent)?;
    output.line(
        "gatewayports",
        config.gateway_ports.as_deref().unwrap_or("no"),
    )?;
    output.bool(
        "gssapiauthentication",
        config.gssapi_authentication.unwrap_or(false),
    )?;
    output.bool("hashknownhosts", config.hash_known_hosts.unwrap_or(false))?;
    output.bool(
        "hostbasedauthentication",
        config.hostbased_authentication.unwrap_or(false),
    )?;
    output.bool("identitiesonly", config.identities_only.unwrap_or(false))?;
    output.bool(
        "kbdinteractiveauthentication",
        config.keyboard_interactive_authentication.unwrap_or(true),
    )?;
    output.bool(
        "nohostauthenticationforlocalhost",
        config.no_host_authentication_for_localhost.unwrap_or(false),
    )?;
    output.bool(
        "passwordauthentication",
        config.password_authentication.unwrap_or(true),
    )?;
    output.bool(
        "permitlocalcommand",
        config.permit_local_command.unwrap_or(false),
    )?;
    output.bool(
        "pubkeyauthentication",
        config.pubkey_authentication.unwrap_or(true),
    )?;
    output.line(
        "requesttty",
        config.request_tty.as_deref().unwrap_or("auto"),
    )?;
    output.line("protocol", list_or(&config.protocol, "2"))?;
    output.line(
        "sessiontype",
        config.session_type.as_deref().unwrap_or("default"),
    )?;
    output.bool("stdinnull", config.stdin_null.unwrap_or(false))?;
    output.bool(
        "forkafterauthentication",
        config.fork_after_authentication.unwrap_or(false),
    )?;
    output.line(
        "stricthostkeychecking",
        config.strict_host_key_checking.as_deref().unwrap_or("ask"),
    )?;
    output.bool("tcpkeepalive", config.tcp_keep_alive.unwrap_or(true))?;
    output.bool("visualhostkey", config.visual_host_key.unwrap_or(false))?;
    output.line(
        "verifyhostkeydns",
        config.verify_host_key_dns.as_deref().unwrap_or("no"),
    )?;
    output.line(
        "updatehostkeys",
        config.update_host_keys.as_deref().unwrap_or("yes"),
    )?;
    output.line("canonicalizefallbacklocal", "yes")?;
    output.line("canonicalizehostname", "false")?;
    output.line(
        "streamlocalbindunlink",
        raw_option(config, "streamlocalbindunlink")
            .as_deref()
            .unwrap_or("no"),
    )?;
    output.line(
        "tunnel",
        raw_option(config, "tunnel").as_deref().unwrap_or("false"),
    )?;
    output.line(
        "enableescapecommandline",
        raw_option(config, "enableescapecommandline")
            .as_deref()
            .unwrap_or("no"),
    )?;
    output.line(
        "warnweakcrypto",
        raw_option(config, "warnweakcrypto")
            .as_deref()
            .unwrap_or("yes"),
    )?;

    output.line(
        "connectionattempts",
        config.connection_attempts.unwrap_or(1),
    )?;
    output.line("connecttimeout", config.connect_timeout.unwrap_or(0))?;
    output.line(
        "forwardx11timeout",
        config.forward_x11_timeout.as_deref().unwrap_or("1200"),
    )?;
    output.line(
        "numberofpasswordprompts",
        config.number_of_password_prompts.unwrap_or(3),
    )?;
    output.line(
        "serveralivecountmax",
        config.server_alive_count_max.unwrap_or(3),
    )?;
    output.line(
        "serveraliveinterval",
        config.server_alive_interval.unwrap_or(0),
    )?;
    output.line("requiredrsasize", config.required_rsa_size.unwrap_or(1024))?;
    output.line("canonicalizemaxdots", 1)?;
    output.line(
        "obscurekeystroketiming",
        raw_option(config, "obscurekeystroketiming")
            .as_deref()
            .unwrap_or("yes"),
    )?;

    output.expanded("bindaddress", config.bind_address.as_deref(), &tokens)?;
    output.expanded("bindinterface", config.bind_interface.as_deref(), &tokens)?;
    output.line("ciphers", cipher_names(config))?;
    if let Some(value) = config.control_path.as_deref() {
        output.line("controlpath", tokens.expand_path(value)?)?;
    }
    output.line("hostkeyalgorithms", host_key_names(config))?;
    output.optional("hostkeyalias", config.host_key_alias.as_deref())?;
    output.line("kexalgorithms", kex_names(config))?;
    output.line("macs", mac_names(config))?;
    if let Some(value) = config.identity_agent.as_deref() {
        output.line("identityagent", tokens.expand_path(value)?)?;
    }
    output.line(
        "securitykeyprovider",
        raw_option(config, "securitykeyprovider")
            .as_deref()
            .unwrap_or("$SSH_SK_PROVIDER"),
    )?;
    output.line(
        "xauthlocation",
        raw_option(config, "xauthlocation")
            .as_deref()
            .unwrap_or("/usr/bin/xauth"),
    )?;
    output.expanded("localcommand", config.local_command.as_deref(), &tokens)?;
    output.expanded("remotecommand", config.remote_command.as_deref(), &tokens)?;
    output.expanded(
        "knownhostscommand",
        config.known_hosts_command.as_deref(),
        &tokens,
    )?;
    if let Some(proxy_jump) = config.proxy_jump.as_deref() {
        output.line("proxyjump", tokens.expand(proxy_jump)?)?;
    } else {
        let proxy_command = config
            .proxy_command
            .as_deref()
            .map(|value| tokens.expand(value))
            .transpose()?
            .unwrap_or_else(|| "none".to_string());
        output.line("proxycommand", proxy_command)?;
    }
    output.bool("proxyusefdpass", config.proxy_use_fdpass.unwrap_or(false))?;
    output.line("loglevel", config.log_level.as_deref().unwrap_or("INFO"))?;
    output.line(
        "syslogfacility",
        config.syslog_facility.as_deref().unwrap_or("USER"),
    )?;
    output.line("escapechar", config.escape_char.as_deref().unwrap_or("~"))?;
    output.line(
        "fingerprinthash",
        config
            .fingerprint_hash
            .as_deref()
            .filter(|value| !value.eq_ignore_ascii_case("sha256"))
            .unwrap_or("SHA256"),
    )?;
    output.line(
        "preferredauthentications",
        list_or(
            &config.preferred_authentications,
            "gssapi-with-mic,hostbased,publickey,keyboard-interactive,password",
        ),
    )?;
    output.line("pubkeyacceptedalgorithms", pubkey_names(config))?;
    output.line(
        "hostbasedacceptedalgorithms",
        list_or(
            &config.hostbased_accepted_algorithms,
            &host_key_names(config),
        ),
    )?;
    output.line(
        "casignaturealgorithms",
        list_or(
            &config.ca_signature_algorithms,
            default_ca_signature_algorithms(),
        ),
    )?;
    output.line("canonicaldomains", "none")?;
    let revoked_host_keys = raw_option(config, "revokedhostkeys")
        .map(|value| tokens.expand_path(&value))
        .transpose()?
        .unwrap_or_else(|| "none".to_string());
    output.line("revokedhostkeys", revoked_host_keys)?;
    output.args(
        "logverbose",
        &raw_option_args(config, "logverbose").unwrap_or_else(|| vec!["none".to_string()]),
    )?;
    output.args(
        "channeltimeout",
        &raw_option_args(config, "channeltimeout").unwrap_or_else(|| vec!["none".to_string()]),
    )?;
    output.line(
        "tunneldevice",
        raw_option(config, "tunneldevice")
            .as_deref()
            .unwrap_or("any:any"),
    )?;
    output.line("canonicalizepermittedcnames", "none")?;
    output.line(
        "streamlocalbindmask",
        raw_option(config, "streamlocalbindmask")
            .as_deref()
            .unwrap_or("0177"),
    )?;

    for identity in identity_files(config) {
        output.line("identityfile", identity)?;
    }
    for certificate in &config.certificate_files {
        output.line("certificatefile", certificate.to_string_lossy())?;
    }
    let user_hosts = config.user_known_hosts_file.clone().unwrap_or_else(|| {
        vec![
            "~/.ssh/known_hosts".to_string(),
            "~/.ssh/known_hosts2".to_string(),
        ]
    });
    let user_hosts = user_hosts
        .iter()
        .map(|value| tokens.expand(value))
        .collect::<Result<Vec<_>>>()?;
    output.args("userknownhostsfile", &user_hosts)?;
    let global_hosts = config.global_known_hosts_file.clone().unwrap_or_else(|| {
        vec![
            "/etc/ssh/ssh_known_hosts".to_string(),
            "/etc/ssh/ssh_known_hosts2".to_string(),
        ]
    });
    let global_hosts = global_hosts
        .iter()
        .map(|value| tokens.expand(value))
        .collect::<Result<Vec<_>>>()?;
    output.args("globalknownhostsfile", &global_hosts)?;
    for value in &config.send_env {
        output.line("sendenv", value)?;
    }
    let mut set_env = config.set_env.iter().collect::<Vec<_>>();
    set_env.sort_by(|left, right| left.0.cmp(right.0));
    for (name, value) in set_env {
        output.line("setenv", format!("{name}={}", tokens.expand(value)?))?;
    }
    if !config.clear_all_forwardings.unwrap_or(false) {
        for value in &config.local_forward {
            output.args("localforward", &expanded_args(value, &tokens)?)?;
        }
        for value in &config.remote_forward {
            output.args("remoteforward", &expanded_args(value, &tokens)?)?;
        }
        for value in &config.dynamic_forward {
            output.args("dynamicforward", &expanded_args(value, &tokens)?)?;
        }
    }
    let permit_remote_open = if config.permit_remote_open.is_empty() {
        vec!["any".to_string()]
    } else {
        config.permit_remote_open.clone()
    };
    output.args("permitremoteopen", &permit_remote_open)?;
    output.line(
        "addkeystoagent",
        config.add_keys_to_agent.as_deref().unwrap_or("no"),
    )?;
    output.line(
        "controlpersist",
        config.control_persist.as_deref().unwrap_or("no"),
    )?;
    output.args("ipqos", &format_ipqos(config.ipqos.unwrap_or_default()))?;
    output.args(
        "rekeylimit",
        &format_rekey(config.rekey_limit.unwrap_or_default()),
    )?;

    for (keyword, args) in &config.unimplemented_options {
        if !EMITTED_UNIMPLEMENTED.contains(&keyword.as_str()) {
            let args = args
                .iter()
                .map(|value| tokens.expand(value))
                .collect::<Result<Vec<_>>>()?;
            output.args(keyword, &args)?;
        }
    }
    Ok(output.value)
}

const EMITTED_UNIMPLEMENTED: &[&str] = &[
    "addkeystoagent",
    "casignaturealgorithms",
    "connecttimeout",
    "controlmaster",
    "controlpath",
    "controlpersist",
    "enablesshkeysign",
    "escapechar",
    "fingerprinthash",
    "forkafterauthentication",
    "forwardagent",
    "forwardx11",
    "forwardx11timeout",
    "forwardx11trusted",
    "gatewayports",
    "gssapiauthentication",
    "hostbasedacceptedalgorithms",
    "hostbasedauthentication",
    "identityagent",
    "kbdinteractiveauthentication",
    "loglevel",
    "nohostauthenticationforlocalhost",
    "permitremoteopen",
    "protocol",
    "requiredrsasize",
    "stdinnull",
    "syslogfacility",
    "visualhostkey",
    "canonicalizefallbacklocal",
    "canonicalizehostname",
    "canonicalizemaxdots",
    "canonicaldomains",
    "canonicalizepermittedcnames",
    "channeltimeout",
    "enableescapecommandline",
    "logverbose",
    "obscurekeystroketiming",
    "revokedhostkeys",
    "securitykeyprovider",
    "streamlocalbindunlink",
    "streamlocalbindmask",
    "tunnel",
    "tunneldevice",
    "warnweakcrypto",
    "xauthlocation",
];

#[derive(Default)]
struct DumpWriter {
    value: String,
}

impl DumpWriter {
    fn line(&mut self, keyword: &str, value: impl std::fmt::Display) -> Result<()> {
        let value = value.to_string();
        if keyword.is_empty()
            || keyword.chars().any(|ch| !ch.is_ascii_alphanumeric())
            || value.chars().any(char::is_control)
        {
            anyhow::bail!("Resolved SSH configuration contains an unsafe value");
        }
        let value = super::value::encode(&value)?;
        writeln!(self.value, "{} {}", keyword.to_ascii_lowercase(), value)
            .context("Failed to format resolved SSH configuration")
    }

    fn args(&mut self, keyword: &str, values: &[String]) -> Result<()> {
        if values.is_empty() {
            anyhow::bail!("Resolved SSH configuration contains an empty argument list");
        }
        if keyword.is_empty()
            || keyword.chars().any(|ch| !ch.is_ascii_alphanumeric())
            || values
                .iter()
                .flat_map(|value| value.chars())
                .any(char::is_control)
        {
            anyhow::bail!("Resolved SSH configuration contains an unsafe value");
        }
        let encoded = values
            .iter()
            .map(|value| super::value::encode(value))
            .collect::<Result<Vec<_>>>()?;
        writeln!(
            self.value,
            "{} {}",
            keyword.to_ascii_lowercase(),
            encoded.join(" ")
        )
        .context("Failed to format resolved SSH configuration")
    }

    fn bool(&mut self, keyword: &str, value: bool) -> Result<()> {
        self.line(keyword, yes_no(value))
    }

    fn optional(&mut self, keyword: &str, value: Option<&str>) -> Result<()> {
        if let Some(value) = value {
            self.line(keyword, value)?;
        }
        Ok(())
    }

    fn expanded(
        &mut self,
        keyword: &str,
        value: Option<&str>,
        tokens: &TokenContext,
    ) -> Result<()> {
        if let Some(value) = value {
            self.line(keyword, tokens.expand(value)?)?;
        }
        Ok(())
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn raw_option(config: &SshHostConfig, keyword: &str) -> Option<String> {
    config
        .unimplemented_options
        .get(keyword)
        .map(|args| args.join(" "))
}

fn raw_option_args(config: &SshHostConfig, keyword: &str) -> Option<Vec<String>> {
    config.unimplemented_options.get(keyword).cloned()
}

fn expanded_args(value: &str, tokens: &TokenContext) -> Result<Vec<String>> {
    super::value::tokenize(&tokens.expand(value)?, 0)
}

fn list_or(values: &[String], default: &str) -> String {
    if values.is_empty() {
        default.to_string()
    } else {
        values.join(",")
    }
}

fn cipher_names(config: &SshHostConfig) -> String {
    config
        .resolved_ciphers
        .as_deref()
        .unwrap_or(russh::Preferred::DEFAULT.cipher.as_ref())
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(",")
}

fn mac_names(config: &SshHostConfig) -> String {
    config
        .resolved_macs
        .as_deref()
        .unwrap_or(russh::Preferred::DEFAULT.mac.as_ref())
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(",")
}

fn kex_names(config: &SshHostConfig) -> String {
    config
        .resolved_kex_algorithms
        .as_deref()
        .unwrap_or(russh::Preferred::DEFAULT.kex.as_ref())
        .iter()
        .map(AsRef::as_ref)
        .filter(|name| {
            !matches!(
                *name,
                "ext-info-c"
                    | "ext-info-s"
                    | "kex-strict-c-v00@openssh.com"
                    | "kex-strict-s-v00@openssh.com"
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn host_key_names(config: &SshHostConfig) -> String {
    config
        .resolved_host_key_algorithms
        .as_deref()
        .unwrap_or(russh::Preferred::DEFAULT.key.as_ref())
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn pubkey_names(config: &SshHostConfig) -> String {
    config
        .resolved_pubkey_accepted_algorithms
        .clone()
        .unwrap_or_else(crate::ssh::tokio_client::algorithms::default_pubkey_algorithms)
        .join(",")
}

fn identity_files(config: &SshHostConfig) -> Vec<String> {
    let default_names = [
        "id_rsa",
        "id_ecdsa",
        "id_ecdsa_sk",
        "id_ed25519",
        "id_ed25519_sk",
    ];
    let is_expanded_default = dirs::home_dir().is_some_and(|home| {
        config.identity_files.len() == default_names.len()
            && config
                .identity_files
                .iter()
                .zip(default_names)
                .all(|(path, name)| path == &home.join(".ssh").join(name))
    });
    if !config.identity_files.is_empty() && !is_expanded_default {
        return config
            .identity_files
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
    }
    default_names
        .into_iter()
        .map(|name| format!("~/.ssh/{name}"))
        .collect()
}

fn format_ipqos(policy: IpQosPolicy) -> Vec<String> {
    vec![qos_value(policy.interactive), qos_value(policy.bulk)]
}

fn qos_value(value: IpQosValue) -> String {
    match value {
        IpQosValue::None => "none".to_string(),
        IpQosValue::Class(0x28) => "af11".to_string(),
        IpQosValue::Class(0x30) => "af12".to_string(),
        IpQosValue::Class(0x38) => "af13".to_string(),
        IpQosValue::Class(0x48) => "af21".to_string(),
        IpQosValue::Class(0x50) => "af22".to_string(),
        IpQosValue::Class(0x58) => "af23".to_string(),
        IpQosValue::Class(0x68) => "af31".to_string(),
        IpQosValue::Class(0x70) => "af32".to_string(),
        IpQosValue::Class(0x78) => "af33".to_string(),
        IpQosValue::Class(0x88) => "af41".to_string(),
        IpQosValue::Class(0x90) => "af42".to_string(),
        IpQosValue::Class(0x98) => "af43".to_string(),
        IpQosValue::Class(0x20) => "cs1".to_string(),
        IpQosValue::Class(0x40) => "cs2".to_string(),
        IpQosValue::Class(0x60) => "cs3".to_string(),
        IpQosValue::Class(0x80) => "cs4".to_string(),
        IpQosValue::Class(0xa0) => "cs5".to_string(),
        IpQosValue::Class(0xc0) => "cs6".to_string(),
        IpQosValue::Class(0xe0) => "cs7".to_string(),
        IpQosValue::Class(0xb8) => "ef".to_string(),
        IpQosValue::Class(0x04) => "le".to_string(),
        IpQosValue::Class(0xb0) => "va".to_string(),
        IpQosValue::Class(0) => "cs0".to_string(),
        IpQosValue::Class(value) => value.to_string(),
    }
}

fn format_rekey(limit: RekeyLimit) -> Vec<String> {
    let data = match limit.data {
        RekeyDataLimit::Default => 0,
        RekeyDataLimit::Bytes(value) => value,
    };
    let time = match limit.time {
        RekeyTimeLimit::Default | RekeyTimeLimit::None => 0,
        RekeyTimeLimit::Seconds(value) => value,
    };
    vec![data.to_string(), time.to_string()]
}

fn default_ca_signature_algorithms() -> &'static str {
    "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,webauthn-sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256"
}
