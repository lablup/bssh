use bssh::config::{Config, InteractiveConfigUpdate, InteractiveMode};
use tempfile::tempdir;

#[tokio::test]
async fn test_config_save_and_load() -> Result<(), Box<dyn std::error::Error>> {
    // Create a config with interactive settings
    let mut config = Config::default();
    config.interactive.default_mode = InteractiveMode::Multiplex;
    config.interactive.prompt_format = "test> ".to_string();
    config.interactive.show_timestamps = true;

    // Save to a temporary file
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("test_config.yaml");
    config.save(&config_path).await?;

    // Load it back
    let loaded_config = Config::load(&config_path).await?;

    // Verify the settings were saved and loaded correctly
    assert!(matches!(
        loaded_config.interactive.default_mode,
        InteractiveMode::Multiplex
    ));
    assert_eq!(loaded_config.interactive.prompt_format, "test> ");
    assert!(loaded_config.interactive.show_timestamps);

    println!("✅ Configuration save and load test passed!");

    Ok(())
}

#[tokio::test]
async fn test_config_update_preferences() -> Result<(), Box<dyn std::error::Error>> {
    // Create a base config
    let mut config = Config::default();
    config.interactive.prompt_format = "original> ".to_string();
    config.interactive.show_timestamps = true;

    // Save to a temporary file
    let temp_dir = tempdir()?;
    let config_path = temp_dir.path().join("test_config.yaml");
    config.save(&config_path).await?;

    // Apply updates
    let updates = InteractiveConfigUpdate {
        prompt_format: Some("updated> ".to_string()),
        show_timestamps: Some(false),
        ..Default::default()
    };

    config.update_interactive_preferences(None, updates).await?;

    // Verify updates were applied
    assert_eq!(config.interactive.prompt_format, "updated> ");
    assert!(!config.interactive.show_timestamps);

    println!("✅ Configuration update test passed!");

    Ok(())
}
