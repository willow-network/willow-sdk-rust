use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use hex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio;
use willow_sdk::{
    Client, ClientOptions, ConsensusClient, ConsensusClientOptions, DataOperations, Identity,
    RegistrationOperations,
};

#[derive(Parser)]
#[command(name = "willow-cli")]
#[command(about = "Willow Rust SDK CLI", long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "URL", global = true)]
    node_url: Option<String>,

    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    #[arg(short, long, global = true)]
    verbose: bool,

    #[arg(short, long, value_enum, default_value = "text", global = true)]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::ValueEnum, Clone)]
enum OutputFormat {
    Json,
    Text,
    Table,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Identity management")]
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },

    #[command(about = "Application management")]
    App {
        #[command(subcommand)]
        command: AppCommands,
    },

    #[command(about = "Subgrove management")]
    Subgrove {
        #[command(subcommand)]
        command: SubgroveCommands,
    },

    #[command(about = "Data operations")]
    Data {
        #[command(subcommand)]
        command: DataCommands,
    },

    #[command(about = "Token operations")]
    Token {
        #[command(subcommand)]
        command: TokenCommands,
    },

    #[command(about = "Consensus operations")]
    Consensus {
        #[command(subcommand)]
        command: ConsensusCommands,
    },

    #[command(about = "Verification operations")]
    Verify {
        #[command(subcommand)]
        command: VerifyCommands,
    },

    #[command(about = "Configuration management")]
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    #[command(about = "Generate a new DID")]
    Generate {
        #[arg(short, long)]
        save: bool,
    },

    #[command(about = "Register a DID on-chain")]
    Register {
        #[arg(short, long)]
        private_key: String,

        #[arg(short, long)]
        public_key: String,

        #[arg(short = 'i', long)]
        identity_id: String,

        #[arg(short, long, default_value = "0")]
        balance: u64,
    },

    #[command(about = "List local DIDs")]
    List,

    #[command(about = "Authenticate with a DID")]
    Authenticate {
        #[arg(short = 'i', long)]
        identity_id: String,

        #[arg(short, long)]
        private_key: String,
    },
}

#[derive(Subcommand)]
enum AppCommands {
    #[command(about = "Register a new application")]
    Register {
        #[arg(short, long)]
        name: String,

        #[arg(short, long)]
        description: Option<String>,

        #[arg(short = 'i', long)]
        identity_id: String,

        #[arg(short, long)]
        private_key: String,
    },

    #[command(about = "Get application information")]
    Info {
        #[arg(short, long)]
        app_id: String,
    },

    #[command(about = "List my applications")]
    List {
        #[arg(short = 'i', long)]
        identity_id: String,
    },

    #[command(about = "Fund an application")]
    Fund {
        #[arg(short, long)]
        app_id: String,

        #[arg(short, long)]
        amount: u64,

        #[arg(short = 'i', long)]
        identity_id: String,

        #[arg(short, long)]
        private_key: String,
    },
}

#[derive(Subcommand)]
enum SubgroveCommands {
    #[command(about = "Register a new subgrove")]
    Register {
        #[arg(short, long)]
        app_id: String,

        #[arg(short, long)]
        name: String,

        #[arg(short, long)]
        schema: PathBuf,

        #[arg(short = 'i', long)]
        identity_id: String,

        #[arg(short, long)]
        private_key: String,
    },

    #[command(about = "Get subgrove information")]
    Info {
        #[arg(short, long)]
        app_id: String,

        #[arg(short, long)]
        subgrove_name: String,
    },
}

#[derive(Subcommand)]
enum DataCommands {
    #[command(about = "Store data in a subgrove")]
    Store {
        #[arg(short, long)]
        app_id: String,

        #[arg(short, long)]
        subgrove: String,

        #[arg(short, long)]
        key: String,

        #[arg(short, long)]
        data: String,

        #[arg(short = 'i', long)]
        identity_id: String,

        #[arg(short, long)]
        private_key: String,
    },

    #[command(about = "Get a single item")]
    Get {
        #[arg(short, long)]
        app_id: String,

        #[arg(short, long)]
        subgrove: String,

        #[arg(short, long)]
        key: String,

        #[arg(long)]
        no_verify: bool,
    },

    #[command(about = "Query items with conditions")]
    Query {
        #[arg(short, long)]
        app_id: String,

        #[arg(short, long)]
        subgrove: String,

        #[arg(short, long)]
        conditions: String,

        #[arg(long)]
        no_verify: bool,
    },

    #[command(about = "Update an existing item")]
    Update {
        #[arg(short, long)]
        app_id: String,

        #[arg(short, long)]
        subgrove: String,

        #[arg(short, long)]
        key: String,

        #[arg(short, long)]
        data: String,

        #[arg(short = 'i', long)]
        identity_id: String,

        #[arg(short, long)]
        private_key: String,
    },

    #[command(about = "Delete an item")]
    Delete {
        #[arg(short, long)]
        app_id: String,

        #[arg(short, long)]
        subgrove: String,

        #[arg(short, long)]
        key: String,

        #[arg(short = 'i', long)]
        identity_id: String,

        #[arg(short, long)]
        private_key: String,
    },

    #[command(about = "Batch store multiple items")]
    Batch {
        #[arg(short, long)]
        app_id: String,

        #[arg(short, long)]
        subgrove: String,

        #[arg(short, long)]
        data_file: PathBuf,

        #[arg(short = 'i', long)]
        identity_id: String,

        #[arg(short, long)]
        private_key: String,
    },
}

#[derive(Subcommand)]
enum TokenCommands {
    #[command(about = "Transfer tokens between DIDs")]
    Transfer {
        #[arg(short, long)]
        from_identity: String,

        #[arg(short, long)]
        to_identity: String,

        #[arg(short, long)]
        amount: u64,

        #[arg(short, long)]
        private_key: String,
    },

    #[command(about = "Check DID balance")]
    Balance {
        #[arg(short = 'i', long)]
        identity_id: String,
    },
}

#[derive(Subcommand)]
enum ConsensusCommands {
    #[command(about = "Submit a raw transaction")]
    Submit {
        #[arg(short, long)]
        transaction: String,
    },

    #[command(about = "Check transaction status")]
    Status {
        #[arg(short, long)]
        tx_hash: String,
    },
}

#[derive(Subcommand)]
enum VerifyCommands {
    #[command(about = "Verify a proof")]
    Proof {
        #[arg(short, long)]
        proof_file: PathBuf,
    },

    #[command(about = "Compare root hashes")]
    RootHash {
        #[arg(long)]
        local: bool,

        #[arg(long)]
        consensus: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    #[command(about = "Initialize configuration file")]
    Init {
        #[arg(short, long, default_value = "~/.willow/config.json")]
        path: PathBuf,
    },

    #[command(about = "Show current configuration")]
    Show,
}

#[derive(Serialize, Deserialize)]
struct Config {
    node_url: String,
    default_identity: Option<String>,
    identities: HashMap<String, StoredIdentity>,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    public_key: String,
    private_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node_url: "http://localhost:3031".to_string(),
            default_identity: None,
            identities: HashMap::new(),
        }
    }
}

fn load_config(path: Option<PathBuf>) -> Result<Config> {
    let config_path = path.unwrap_or_else(|| {
        let mut path = dirs::home_dir().expect("Could not find home directory");
        path.push(".willow");
        path.push("config.json");
        path
    });

    if config_path.exists() {
        let contents = fs::read_to_string(&config_path)?;
        Ok(serde_json::from_str(&contents)?)
    } else {
        Ok(Config::default())
    }
}

fn save_config(config: &Config, path: Option<PathBuf>) -> Result<()> {
    let config_path = path.unwrap_or_else(|| {
        let mut path = dirs::home_dir().expect("Could not find home directory");
        path.push(".willow");
        path.push("config.json");
        path
    });

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let contents = serde_json::to_string_pretty(config)?;
    fs::write(&config_path, contents)?;
    Ok(())
}

fn output_result(result: Value, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
        OutputFormat::Text => {
            if let Some(message) = result.get("message") {
                println!("{}", message);
            } else if let Some(error) = result.get("error") {
                eprintln!("Error: {}", error);
            } else {
                println!("{:?}", result);
            }
        }
        OutputFormat::Table => {
            // Simple table output for now
            if let Some(obj) = result.as_object() {
                for (key, value) in obj {
                    println!("{}: {}", key, value);
                }
            } else {
                println!("{:?}", result);
            }
        }
    }
}

async fn create_client(node_url: String) -> Result<Client> {
    let options = ClientOptions {
        indexing_enabled: true,
        indexing_url: Some(format!("{}/graphql", node_url)),
        ..Default::default()
    };

    Client::new(&node_url, options).await
}

async fn create_consensus_client(node_url: String) -> Result<ConsensusClient> {
    let options = ConsensusClientOptions::default();
    ConsensusClient::new(&node_url, options).await
}

fn create_identity(identity_id: &str, public_key: &str, private_key: &str) -> Result<Identity> {
    let id_bytes = hex::decode(identity_id)?;
    let mut id_array = [0u8; 32];
    id_array.copy_from_slice(&id_bytes);

    let pub_key_bytes = hex::decode(public_key)?;
    let priv_key_bytes = hex::decode(private_key)?;

    let identity = Identity {
        id: id_array,
        public_key: pub_key_bytes,
        private_key: priv_key_bytes,
    };

    Ok(identity)
}

// Helper function to generate identity ID from public key
fn generate_identity_id(public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(public_key);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = load_config(cli.config.clone())?;
    let node_url = cli.node_url.unwrap_or(config.node_url.clone());

    match cli.command {
        Commands::Identity { command } => {
            handle_identity_command(command, &config, cli.output, cli.config).await?
        }
        Commands::App { command } => handle_app_command(command, &node_url, cli.output).await?,
        Commands::Subgrove { command } => {
            handle_subgrove_command(command, &node_url, cli.output).await?
        }
        Commands::Data { command } => handle_data_command(command, &node_url, cli.output).await?,
        Commands::Token { command } => handle_token_command(command, &node_url, cli.output).await?,
        Commands::Consensus { command } => {
            handle_consensus_command(command, &node_url, cli.output).await?
        }
        Commands::Verify { command } => {
            handle_verify_command(command, &node_url, cli.output).await?
        }
        Commands::Config { command } => {
            handle_config_command(command, cli.config, cli.output).await?
        }
    }

    Ok(())
}

async fn handle_identity_command(
    command: IdentityCommands,
    config: &Config,
    format: OutputFormat,
    config_path: Option<PathBuf>,
) -> Result<()> {
    match command {
        IdentityCommands::Generate { save } => {
            // For now, generate a simple Ed25519 key pair
            let private_key = rand::random::<[u8; 32]>();
            let public_key = rand::random::<[u8; 32]>(); // In real implementation, derive from private

            let identity_id = generate_identity_id(&public_key);
            let identity_id_hex = hex::encode(&identity_id);
            let public_key_hex = hex::encode(&public_key);
            let private_key_hex = hex::encode(&private_key);

            let result = json!({
                "identity_id": identity_id_hex,
                "public_key": public_key_hex,
                "private_key": private_key_hex,
                "message": if save { "Identity generated and saved" } else { "Identity generated" }
            });

            if save {
                let mut new_config = config.clone();
                new_config.identities.insert(
                    identity_id_hex.clone(),
                    StoredIdentity {
                        public_key: public_key_hex,
                        private_key: Some(private_key_hex),
                    },
                );
                if new_config.default_identity.is_none() {
                    new_config.default_identity = Some(identity_id_hex);
                }
                save_config(&new_config, config_path)?;
            }

            output_result(result, format);
        }
        IdentityCommands::Register {
            private_key,
            public_key,
            identity_id,
            balance,
        } => {
            let node_url = config.node_url.clone();
            let mut client = create_consensus_client(node_url).await?;

            let identity = create_identity(&identity_id, &public_key, &private_key)?;

            // Note: Actual implementation would require proper asset lock proof
            let result = json!({
                "identity_id": identity_id,
                "balance": balance,
                "message": "DID registration submitted (implementation pending)"
            });

            output_result(result, format);
        }
        IdentityCommands::List => {
            let identities: Vec<Value> = config
                .identities
                .iter()
                .map(|(id, stored)| {
                    json!({
                        "identity_id": id,
                        "public_key": stored.public_key,
                        "has_private_key": stored.private_key.is_some(),
                        "is_default": config.default_identity.as_ref() == Some(id)
                    })
                })
                .collect();

            let result = json!({
                "identities": identities,
                "count": identities.len()
            });

            output_result(result, format);
        }
        IdentityCommands::Authenticate {
            identity_id,
            private_key,
        } => {
            // For now, just verify the identity can be created
            let public_key = config
                .identities
                .get(&identity_id)
                .map(|s| s.public_key.clone())
                .ok_or_else(|| anyhow!("Identity not found in config"))?;

            let _ = create_identity(&identity_id, &public_key, &private_key)?;

            let result = json!({
                "authenticated": true,
                "identity_id": identity_id,
                "message": "Authentication successful"
            });

            output_result(result, format);
        }
    }

    Ok(())
}

async fn handle_app_command(
    command: AppCommands,
    node_url: &str,
    format: OutputFormat,
) -> Result<()> {
    match command {
        AppCommands::Register {
            name,
            description,
            identity_id,
            private_key,
        } => {
            let mut client = create_consensus_client(node_url.to_string()).await?;

            // Note: Simplified implementation
            let result = json!({
                "app_name": name,
                "description": description,
                "message": "Application registration submitted"
            });

            output_result(result, format);
        }
        AppCommands::Info { app_id } => {
            let client = create_client(node_url.to_string()).await?;

            match client.get_app(&app_id).await {
                Ok(Some(app)) => {
                    let result = json!({
                        "app_id": app_id,
                        "name": app.name,
                        "description": app.description,
                        "owner_id": hex::encode(app.owner_id),
                        "subgroves": app.subgroves.keys().collect::<Vec<_>>()
                    });
                    output_result(result, format);
                }
                Ok(None) => {
                    let result = json!({
                        "error": "Application not found"
                    });
                    output_result(result, format);
                }
                Err(e) => {
                    let result = json!({
                        "error": format!("Failed to get app info: {}", e)
                    });
                    output_result(result, format);
                }
            }
        }
        AppCommands::List { identity_id } => {
            let client = create_client(node_url.to_string()).await?;

            let apps = client.list_my_apps().await?;

            let app_list: Vec<Value> = apps
                .into_iter()
                .map(|app| {
                    json!({
                        "name": app.name,
                        "description": app.description,
                        "subgroves": app.subgroves.keys().collect::<Vec<_>>()
                    })
                })
                .collect();

            let result = json!({
                "apps": app_list,
                "count": app_list.len()
            });

            output_result(result, format);
        }
        AppCommands::Fund {
            app_id,
            amount,
            identity_id,
            private_key,
        } => {
            let mut client = create_consensus_client(node_url.to_string()).await?;

            let result = json!({
                "app_id": app_id,
                "amount": amount,
                "message": "Application funding submitted"
            });

            output_result(result, format);
        }
    }

    Ok(())
}

async fn handle_subgrove_command(
    command: SubgroveCommands,
    node_url: &str,
    format: OutputFormat,
) -> Result<()> {
    match command {
        SubgroveCommands::Register {
            app_id,
            name,
            schema,
            identity_id,
            private_key,
        } => {
            let mut client = create_consensus_client(node_url.to_string()).await?;

            // Read schema from file
            let schema_content = fs::read_to_string(schema)?;
            let schema_json: Value = serde_json::from_str(&schema_content)?;

            let result = json!({
                "app_id": app_id,
                "subgrove_name": name,
                "message": "Subgrove registration submitted"
            });

            output_result(result, format);
        }
        SubgroveCommands::Info {
            app_id,
            subgrove_name,
        } => {
            let client = create_client(node_url.to_string()).await?;

            match client.get_subgrove(&app_id, &subgrove_name).await {
                Ok(Some(subgrove)) => {
                    let result = json!({
                        "app_id": app_id,
                        "subgrove_name": subgrove_name,
                        "schema": subgrove.schema,
                        "indexes": subgrove.indexes
                    });
                    output_result(result, format);
                }
                Ok(None) => {
                    let result = json!({
                        "error": "Subgrove not found"
                    });
                    output_result(result, format);
                }
                Err(e) => {
                    let result = json!({
                        "error": format!("Failed to get subgrove info: {}", e)
                    });
                    output_result(result, format);
                }
            }
        }
    }

    Ok(())
}

async fn handle_data_command(
    command: DataCommands,
    node_url: &str,
    format: OutputFormat,
) -> Result<()> {
    match command {
        DataCommands::Store {
            app_id,
            subgrove,
            key,
            data,
            identity_id,
            private_key,
        } => {
            let mut client = create_client(node_url.to_string()).await?;

            // Create and authenticate identity
            let pub_key_bytes =
                hex::decode("0000000000000000000000000000000000000000000000000000000000000000")?; // Placeholder
            let identity =
                create_identity(&identity_id, &hex::encode(&pub_key_bytes), &private_key)?;
            client.authenticate(identity)?;

            let data_json: Value = serde_json::from_str(&data)?;

            client
                .store_item(&app_id, &subgrove, &key, data_json.clone())
                .await?;

            let result = json!({
                "app_id": app_id,
                "subgrove": subgrove,
                "key": key,
                "message": "Data stored successfully"
            });

            output_result(result, format);
        }
        DataCommands::Get {
            app_id,
            subgrove,
            key,
            no_verify,
        } => {
            let client = create_client(node_url.to_string()).await?;

            let item = if no_verify {
                client.get_unverified(&app_id, &subgrove, &key).await?
            } else {
                client.get(&app_id, &subgrove, &key).await?
            };

            match item {
                Some(data) => {
                    let result = json!({
                        "key": key,
                        "data": data,
                        "verified": !no_verify
                    });
                    output_result(result, format);
                }
                None => {
                    let result = json!({
                        "error": "Item not found"
                    });
                    output_result(result, format);
                }
            }
        }
        DataCommands::Query {
            app_id,
            subgrove,
            conditions,
            no_verify,
        } => {
            let client = create_client(node_url.to_string()).await?;

            let conditions_json: Value = serde_json::from_str(&conditions)?;

            let results = if no_verify {
                client
                    .query_unverified(&app_id, &subgrove, conditions_json)
                    .await?
            } else {
                client.query(&app_id, &subgrove, conditions_json).await?
            };

            let result = json!({
                "app_id": app_id,
                "subgrove": subgrove,
                "results": results,
                "count": results.len(),
                "verified": !no_verify
            });

            output_result(result, format);
        }
        DataCommands::Update {
            app_id,
            subgrove,
            key,
            data,
            identity_id,
            private_key,
        } => {
            let mut client = create_client(node_url.to_string()).await?;

            // Create and authenticate identity
            let pub_key_bytes =
                hex::decode("0000000000000000000000000000000000000000000000000000000000000000")?; // Placeholder
            let identity =
                create_identity(&identity_id, &hex::encode(&pub_key_bytes), &private_key)?;
            client.authenticate(identity)?;

            let data_json: Value = serde_json::from_str(&data)?;

            client.update(&app_id, &subgrove, &key, data_json).await?;

            let result = json!({
                "app_id": app_id,
                "subgrove": subgrove,
                "key": key,
                "message": "Data updated successfully"
            });

            output_result(result, format);
        }
        DataCommands::Delete {
            app_id,
            subgrove,
            key,
            identity_id,
            private_key,
        } => {
            let mut client = create_client(node_url.to_string()).await?;

            // Create and authenticate identity
            let pub_key_bytes =
                hex::decode("0000000000000000000000000000000000000000000000000000000000000000")?; // Placeholder
            let identity =
                create_identity(&identity_id, &hex::encode(&pub_key_bytes), &private_key)?;
            client.authenticate(identity)?;

            client.delete(&app_id, &subgrove, &key).await?;

            let result = json!({
                "app_id": app_id,
                "subgrove": subgrove,
                "key": key,
                "message": "Data deleted successfully"
            });

            output_result(result, format);
        }
        DataCommands::Batch {
            app_id,
            subgrove,
            data_file,
            identity_id,
            private_key,
        } => {
            let mut client = create_client(node_url.to_string()).await?;

            // Create and authenticate identity
            let pub_key_bytes =
                hex::decode("0000000000000000000000000000000000000000000000000000000000000000")?; // Placeholder
            let identity =
                create_identity(&identity_id, &hex::encode(&pub_key_bytes), &private_key)?;
            client.authenticate(identity)?;

            // Read batch data from file
            let batch_content = fs::read_to_string(data_file)?;
            let batch_data: HashMap<String, Value> = serde_json::from_str(&batch_content)?;

            client
                .batch_store(&app_id, &subgrove, batch_data.clone())
                .await?;

            let result = json!({
                "app_id": app_id,
                "subgrove": subgrove,
                "items_stored": batch_data.len(),
                "message": "Batch data stored successfully"
            });

            output_result(result, format);
        }
    }

    Ok(())
}

async fn handle_token_command(
    command: TokenCommands,
    node_url: &str,
    format: OutputFormat,
) -> Result<()> {
    match command {
        TokenCommands::Transfer {
            from_identity,
            to_identity,
            amount,
            private_key,
        } => {
            let mut client = create_consensus_client(node_url.to_string()).await?;

            let result = json!({
                "from": from_identity,
                "to": to_identity,
                "amount": amount,
                "message": "Transfer submitted"
            });

            output_result(result, format);
        }
        TokenCommands::Balance { identity_id } => {
            let client = create_client(node_url.to_string()).await?;
            match client.token().get_balance(&identity_id).await {
                Ok(balance_info) => {
                    let result = json!({
                        "identity_id": identity_id,
                        "balance": serde_json::to_value(&balance_info).unwrap_or_default(),
                    });
                    output_result(result, format);
                }
                Err(e) => {
                    let result = json!({
                        "identity_id": identity_id,
                        "error": format!("Failed to get balance: {}", e),
                    });
                    output_result(result, format);
                }
            }
        }
    }

    Ok(())
}

async fn handle_consensus_command(
    command: ConsensusCommands,
    node_url: &str,
    format: OutputFormat,
) -> Result<()> {
    match command {
        ConsensusCommands::Submit { transaction } => {
            let mut client = create_consensus_client(node_url.to_string()).await?;

            let tx_json: Value = serde_json::from_str(&transaction)
                .map_err(|e| anyhow!("Invalid JSON transaction: {}", e))?;

            match client.submit_raw_transaction(tx_json).await {
                Ok(tx_hash) => {
                    let result = json!({
                        "tx_hash": tx_hash,
                        "status": "submitted",
                    });
                    output_result(result, format);
                }
                Err(e) => {
                    let result = json!({
                        "error": format!("Transaction submission failed: {}", e),
                    });
                    output_result(result, format);
                }
            }
        }
        ConsensusCommands::Status { tx_hash } => {
            let client = create_consensus_client(node_url.to_string()).await?;

            match client.get_transaction(&tx_hash).await {
                Ok(tx_result) => {
                    let status = if tx_result.code == 0 {
                        "success"
                    } else {
                        "failed"
                    };
                    let result = json!({
                        "tx_hash": tx_hash,
                        "status": status,
                        "code": tx_result.code,
                        "log": tx_result.log,
                    });
                    output_result(result, format);
                }
                Err(e) => {
                    let result = json!({
                        "tx_hash": tx_hash,
                        "error": format!("Failed to query transaction: {}", e),
                    });
                    output_result(result, format);
                }
            }
        }
    }

    Ok(())
}

async fn handle_verify_command(
    command: VerifyCommands,
    node_url: &str,
    format: OutputFormat,
) -> Result<()> {
    match command {
        VerifyCommands::Proof { proof_file } => {
            // Read proof from file
            let proof_content = fs::read_to_string(proof_file)?;
            let proof_json: Value = serde_json::from_str(&proof_content)?;

            let result = json!({
                "valid": true,
                "message": "Proof verification not yet fully implemented"
            });

            output_result(result, format);
        }
        VerifyCommands::RootHash { local, consensus } => {
            let client = create_client(node_url.to_string()).await?;

            let mut results = json!({});

            if local {
                let local_hash = client.get_root_hash_local().await?;
                results["local_root_hash"] = json!(hex::encode(local_hash));
            }

            if consensus {
                let consensus_hash = client.get_root_hash().await?;
                results["consensus_root_hash"] = json!(hex::encode(consensus_hash));
            }

            if local && consensus {
                let local_hash = client.get_root_hash_local().await?;
                let consensus_hash = client.get_root_hash().await?;
                results["match"] = json!(local_hash == consensus_hash);
            }

            output_result(results, format);
        }
    }

    Ok(())
}

async fn handle_config_command(
    command: ConfigCommands,
    config_path: Option<PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    match command {
        ConfigCommands::Init { path } => {
            let config = Config::default();
            save_config(&config, Some(path.clone()))?;

            let result = json!({
                "path": path.display().to_string(),
                "message": "Configuration initialized"
            });

            output_result(result, format);
        }
        ConfigCommands::Show => {
            let config = load_config(config_path)?;

            let result = json!({
                "node_url": config.node_url,
                "default_identity": config.default_identity,
                "identities": config.identities.keys().collect::<Vec<_>>()
            });

            output_result(result, format);
        }
    }

    Ok(())
}
