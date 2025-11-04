use anyhow::Result;
use reqwest::blocking::Client;
use std::time::Duration;

/// Client for debuginfod servers (ELF symbol servers)
pub struct DebuginfodClient {
    servers: Vec<String>,
    client: Client,
}

impl DebuginfodClient {
    pub fn new(custom_servers: Vec<String>) -> Self {
        let mut servers = custom_servers;
        
        // Add default servers if none specified
        if servers.is_empty() {
            // Check environment variable
            if let Ok(env_servers) = std::env::var("DEBUGINFOD_URLS") {
                servers.extend(env_servers.split_whitespace().map(|s| s.to_string()));
            }
            
            // Add common public servers
            if servers.is_empty() {
                servers.push("https://debuginfod.elfutils.org/".to_string());
                servers.push("https://debuginfod.ubuntu.com/".to_string());
                servers.push("https://debuginfod.fedoraproject.org/".to_string());
                servers.push("https://debuginfod.debian.net/".to_string());
            }
        }
        
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| Client::new());
        
        Self { servers, client }
    }
    
    /// Check if debug symbols are available for given build-id
    pub fn check_available(&self, build_id: &str) -> Result<(bool, Option<String>)> {
        for server in &self.servers {
            let url = format!("{}/buildid/{}/debuginfo", server.trim_end_matches('/'), build_id);
            
            // Send HEAD request to check availability
            match self.client.head(&url).send() {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok((true, Some(url)));
                    }
                }
                Err(_) => continue,
            }
        }
        
        Ok((false, None))
    }
    
    /// Download debug symbols for given build-id
    pub fn download(&self, build_id: &str, output_path: &std::path::Path) -> Result<()> {
        for server in &self.servers {
            let url = format!("{}/buildid/{}/debuginfo", server.trim_end_matches('/'), build_id);
            
            match self.client.get(&url).send() {
                Ok(response) => {
                    if response.status().is_success() {
                        let bytes = response.bytes()?;
                        std::fs::write(output_path, bytes)?;
                        return Ok(());
                    }
                }
                Err(_) => continue,
            }
        }
        
        anyhow::bail!("Failed to download debug symbols from any server")
    }
    
    /// Get list of configured servers
    pub fn servers(&self) -> &[String] {
        &self.servers
    }
}

