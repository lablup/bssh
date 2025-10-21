fn main() {
    let line = "    HostName=actual.example.com";

    let trimmed_line = line.trim_start();
    let uses_equals_syntax = if trimmed_line.to_lowercase().starts_with("host") {
        // Host directive should never use equals syntax
        false
    } else {
        // Check for equals sign in the line
        line.contains('=')
    };

    println!("Line: {:?}", line);
    println!("Uses equals syntax: {}", uses_equals_syntax);

    if uses_equals_syntax {
        if let Some(eq_pos) = line.find('=') {
            let key_part = line[..eq_pos].trim();
            let value_part = &line[eq_pos + 1..];
            let trimmed_value = value_part.trim();

            println!("Key part: {:?}", key_part);
            println!("Value part: {:?}", value_part);
            println!("Trimmed value: {:?}", trimmed_value);
            println!("Keyword lowercase: {:?}", key_part.to_lowercase());
        }
    }
}