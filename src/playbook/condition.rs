// Copyright 2025 Lablup Inc. and Jeongkyu Shin
// SPDX-License-Identifier: Apache-2.0

use super::model::Variables;
use anyhow::{Result, bail};
use serde_yaml::Value;

/// Evaluate the deliberately small condition language supported by playbooks.
/// No truthiness, boolean composition, filters, or arbitrary expressions are accepted.
pub fn evaluate(expression: &str, variables: &Variables) -> Result<bool> {
    let expression = expression.trim();
    if expression.is_empty() {
        bail!("condition cannot be empty");
    }
    if let Some(name) = expression.strip_suffix(" is not defined") {
        let name = normalize_identifier(name);
        validate_identifier(&name)?;
        return Ok(resolve(variables, &name).is_none());
    }
    if let Some(name) = expression.strip_suffix(" is defined") {
        let name = normalize_identifier(name);
        validate_identifier(&name)?;
        return Ok(resolve(variables, &name).is_some());
    }
    if let Some((left, right)) = expression.split_once(" != ") {
        return compare(left, right, variables).map(|equal| !equal);
    }
    if let Some((left, right)) = expression.split_once(" == ") {
        return compare(left, right, variables);
    }
    bail!(
        "unsupported condition '{expression}'; supported forms are ==, !=, is defined, and is not defined"
    )
}

fn compare(left: &str, right: &str, variables: &Variables) -> Result<bool> {
    let left = normalize_identifier(left);
    validate_identifier(&left)?;
    let actual = resolve(variables, &left)
        .ok_or_else(|| anyhow::anyhow!("condition references undefined variable '{left}'"))?;
    let expected: Value = serde_yaml::from_str(right.trim())
        .map_err(|_| anyhow::anyhow!("invalid condition literal '{}'", right.trim()))?;
    Ok(actual == &expected)
}

fn normalize_identifier(name: &str) -> String {
    let name = name.trim();
    let name = name
        .strip_prefix("{{")
        .and_then(|value| value.strip_suffix("}}"))
        .unwrap_or(name);
    name.trim().trim_start_matches('.').to_owned()
}

fn validate_identifier(name: &str) -> Result<()> {
    if name.is_empty()
        || name.split('.').any(|part| {
            part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
    {
        bail!("invalid variable name '{name}' in condition");
    }
    Ok(())
}

pub fn resolve<'a>(variables: &'a Variables, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut value = variables.get(parts.next()?)?;
    for part in parts {
        value = value.as_mapping()?.get(Value::String(part.to_owned()))?;
    }
    Some(value)
}

pub fn render(input: &str, variables: &Variables) -> Result<String> {
    render_inner(input, variables, false)
}

/// Render values known during planning while preserving runtime-produced
/// fact/register placeholders verbatim.
pub fn render_planning(input: &str, variables: &Variables) -> Result<String> {
    render_inner(input, variables, true)
}

fn render_inner(input: &str, variables: &Variables, allow_unknown: bool) -> Result<String> {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("{{") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .ok_or_else(|| anyhow::anyhow!("unterminated variable template in '{input}'"))?;
        let raw_name = after[..end].trim();
        let name = normalize_identifier(raw_name);
        validate_identifier(&name)?;
        if let Some(value) = resolve(variables, &name) {
            output.push_str(&display_value(value)?);
        } else if allow_unknown {
            output.push_str("{{ ");
            output.push_str(raw_name);
            output.push_str(" }}");
        } else {
            bail!("template references undefined variable '{name}'");
        }
        rest = &after[end + 2..];
    }
    if rest.contains("}}") {
        bail!("unexpected template terminator in '{input}'");
    }
    output.push_str(rest);
    Ok(output)
}

fn display_value(value: &Value) -> Result<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Bool(v) => Ok(v.to_string()),
        Value::Number(v) => Ok(v.to_string()),
        Value::Null => Ok("null".to_owned()),
        _ => serde_json::to_string(value).map_err(Into::into),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn vars() -> Variables {
        BTreeMap::from([
            ("env".into(), Value::String("prod".into())),
            ("enabled".into(), Value::Bool(true)),
            ("count".into(), Value::Number(2.into())),
        ])
    }

    #[test]
    fn evaluates_only_supported_conditions() {
        let vars = vars();
        assert!(evaluate("env == prod", &vars).unwrap());
        assert!(
            evaluate(
                "{{ .env }} == production",
                &BTreeMap::from([("env".into(), Value::String("production".into()))])
            )
            .unwrap()
        );
        assert!(evaluate("count != 3", &vars).unwrap());
        assert!(evaluate("enabled is defined", &vars).unwrap());
        assert!(evaluate("missing is not defined", &vars).unwrap());
        assert!(evaluate("enabled and env == prod", &vars).is_err());
        assert!(evaluate("enabled", &vars).is_err());
    }

    #[test]
    fn renders_variables_and_rejects_missing_values() {
        assert_eq!(
            render("deploy {{ env }} {{ count }}", &vars()).unwrap(),
            "deploy prod 2"
        );
        assert_eq!(render("{{ .env }}", &vars()).unwrap(), "prod");
        assert!(render("{{ missing }}", &vars()).is_err());
    }
}
