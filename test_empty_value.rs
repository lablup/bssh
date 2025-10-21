use std::collections::HashMap;

fn main() {
    let content = r#"
Host example.com
    User=
"#;

    // Simulate parsing
    let line = "    User=";
    let eq_pos = line.find('=').unwrap();
    let key_part = line[..eq_pos].trim();
    let value_part = &line[eq_pos + 1..];
    let trimmed_value = value_part.trim();

    println!("Key: {:?}", key_part);
    println!("Value part: {:?}", value_part);
    println!("Trimmed value: {:?}", trimmed_value);
    println!("Is empty: {}", trimmed_value.is_empty());

    let args: Vec<&str> = if trimmed_value.is_empty() {
        vec![]
    } else {
        vec![trimmed_value]
    };

    println!("Args: {:?}", args);
    println!("Args is empty: {}", args.is_empty());
}