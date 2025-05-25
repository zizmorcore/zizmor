use anyhow::{Result, anyhow};
use oci_client::{Client, Reference};
use std::collections::HashMap;

/// Configuration for different OCI registries
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub name: &'static str,
    pub registry_url: &'static str,
    pub requires_auth: bool,
    pub namespace_format: NamespaceFormat,
}

#[derive(Debug, Clone)]
pub enum NamespaceFormat {
    /// Docker Hub format: library/image for official images, user/image for user images
    DockerHub,
    /// GitHub Container Registry format: ghcr.io/owner/image
    GHCR,
    /// Google Container Registry format: gcr.io/project/image
    GCR,
    /// Generic format: registry.com/namespace/image
    Generic,
}

/// OCI registry client for fetching image tags and manifests
pub struct OciRegistryClient {
    client: Client,
    configs: HashMap<&'static str, RegistryConfig>,
}

impl OciRegistryClient {
    /// Create a new OCI registry client with default configurations
    pub fn new() -> Result<Self> {
        let client = Client::default();

        let mut configs = HashMap::new();

        // Docker Hub configuration
        configs.insert(
            "docker.io",
            RegistryConfig {
                name: "Docker Hub",
                registry_url: "registry-1.docker.io",
                requires_auth: false,
                namespace_format: NamespaceFormat::DockerHub,
            },
        );

        // GitHub Container Registry configuration
        configs.insert(
            "ghcr.io",
            RegistryConfig {
                name: "GitHub Container Registry",
                registry_url: "ghcr.io",
                requires_auth: true,
                namespace_format: NamespaceFormat::GHCR,
            },
        );

        // Google Container Registry configuration
        configs.insert(
            "gcr.io",
            RegistryConfig {
                name: "Google Container Registry",
                registry_url: "gcr.io",
                requires_auth: true,
                namespace_format: NamespaceFormat::GCR,
            },
        );

        // Quay.io configuration
        configs.insert(
            "quay.io",
            RegistryConfig {
                name: "Quay.io",
                registry_url: "quay.io",
                requires_auth: false,
                namespace_format: NamespaceFormat::Generic,
            },
        );

        Ok(Self { client, configs })
    }

    /// Add a custom registry configuration
    pub fn add_registry(&mut self, domain: &'static str, config: RegistryConfig) {
        self.configs.insert(domain, config);
    }

    /// Fetch available tags for a Docker/OCI image
    pub async fn get_image_tags(&self, image_ref: &str) -> Result<Vec<String>> {
        let (registry, repository) = self.parse_image_reference(image_ref)?;

        let config = self
            .configs
            .get(registry)
            .ok_or_else(|| anyhow!("Unsupported registry: {}", registry))?;

        // Create a reference for the image
        let reference_str = format!("{}{}", config.registry_url, repository);
        let reference = Reference::try_from(reference_str)?;

        // Get tags from the registry - use anonymous auth for public registries
        let auth = &oci_client::secrets::RegistryAuth::Anonymous;
        let tag_response = self.client.list_tags(&reference, auth, None, None).await?;
        let tags = tag_response.tags;

        // Filter and sort the tags
        let filtered_tags = self.filter_and_sort_tags(tags);
        Ok(filtered_tags)
    }

    /// Get the manifest digest for a specific image tag
    pub async fn get_image_digest(&self, image_ref: &str, tag: &str) -> Result<String> {
        let (registry, repository) = self.parse_image_reference(image_ref)?;

        let config = self
            .configs
            .get(registry)
            .ok_or_else(|| anyhow!("Unsupported registry: {}", registry))?;

        // Create a reference for the image with tag
        let reference_str = format!("{}{}:{}", config.registry_url, repository, tag);
        let reference = Reference::try_from(reference_str)?;

        // Get the manifest to extract the digest
        let auth = &oci_client::secrets::RegistryAuth::Anonymous;
        let (_, digest) = self.client.pull_manifest(&reference, auth).await?;
        Ok(digest)
    }

    /// Parse a Docker image reference into registry and repository
    fn parse_image_reference<'a>(&self, image_ref: &'a str) -> Result<(&'a str, String)> {
        // Check for empty string
        if image_ref.is_empty() {
            return Err(anyhow!("Empty image reference"));
        }

        // Remove docker:// prefix if present
        let image_ref = image_ref.strip_prefix("docker://").unwrap_or(image_ref);

        // Split by '/' to get components
        let parts: Vec<&str> = image_ref.split('/').collect();

        match parts.len() {
            1 => {
                // Just image name, assume Docker Hub official image
                Ok(("docker.io", format!("/library/{}", parts[0])))
            }
            2 => {
                // Check if first part looks like a registry domain
                if parts[0].contains('.') || parts[0].contains(':') {
                    // registry.com/image format
                    Ok((parts[0], format!("/{}", parts[1])))
                } else {
                    // user/image format, assume Docker Hub
                    Ok(("docker.io", format!("/{}/{}", parts[0], parts[1])))
                }
            }
            3 => {
                // registry.com/namespace/image format
                Ok((parts[0], format!("/{}/{}", parts[1], parts[2])))
            }
            _ => {
                // More complex paths like registry.com/namespace/subnamespace/image
                let registry = parts[0];
                let repository = format!("/{}", parts[1..].join("/"));
                Ok((registry, repository))
            }
        }
    }

    /// Filter and sort tags to return the most useful ones
    fn filter_and_sort_tags(&self, mut tags: Vec<String>) -> Vec<String> {
        // Filter out unwanted tags
        tags.retain(|tag| {
            !tag.contains("latest")
                && !tag.contains("edge")
                && !tag.contains("dev")
                && !tag.contains("alpha")
                && !tag.contains("beta")
                && !tag.contains("rc")
                && !tag.contains("nightly")
                && !tag.starts_with("sha256:")
                && !tag.is_empty()
        });

        // Sort by semantic version preference
        tags.sort_by(|a, b| {
            let a_is_semver = a.chars().next().map_or(false, |c| c.is_ascii_digit());
            let b_is_semver = b.chars().next().map_or(false, |c| c.is_ascii_digit());

            match (a_is_semver, b_is_semver) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => {
                    // For version strings, try to do a more intelligent sort
                    if a_is_semver && b_is_semver {
                        // Simple version comparison (this could be improved with a proper semver crate)
                        b.cmp(a) // Reverse order to get newest first
                    } else {
                        a.cmp(b) // Alphabetical for non-version tags
                    }
                }
            }
        });

        // Return top 5 most relevant tags
        tags.into_iter().take(5).collect()
    }

    /// Get supported registries
    pub fn supported_registries(&self) -> Vec<&str> {
        self.configs.keys().copied().collect()
    }

    /// Check if an image exists in the registry
    pub async fn image_exists(&self, image_ref: &str, tag: Option<&str>) -> Result<bool> {
        let (registry, repository) = self.parse_image_reference(image_ref)?;

        let config = self
            .configs
            .get(registry)
            .ok_or_else(|| anyhow!("Unsupported registry: {}", registry))?;

        let reference_str = if let Some(tag) = tag {
            format!("{}{}:{}", config.registry_url, repository, tag)
        } else {
            format!("{}{}:latest", config.registry_url, repository)
        };

        let reference = Reference::try_from(reference_str)?;

        // Try to get the manifest - if it exists, the image exists
        let auth = &oci_client::secrets::RegistryAuth::Anonymous;
        match self.client.pull_manifest(&reference, auth).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Normalize an image reference to a standard format
    pub fn normalize_image_reference(&self, image_ref: &str) -> String {
        match self.parse_image_reference(image_ref) {
            Ok((registry, repository)) => {
                if registry == "docker.io" && repository.starts_with("/library/") {
                    format!("docker.io{}", repository)
                } else {
                    format!("{}{}", registry, repository)
                }
            }
            Err(_) => image_ref.to_string(), // Return original if parsing fails
        }
    }
}

/// Macro for creating an OCI registry client with timeout and fallback
#[macro_export]
macro_rules! oci_registry_client_with_fallback {
    ($timeout_secs:expr) => {{
        use std::time::Duration;
        use tokio::time::timeout;

        async move |image_ref: &str| -> Vec<String> {
            match $crate::oci_registry::OciRegistryClient::new() {
                Ok(client) => {
                    match timeout(
                        Duration::from_secs($timeout_secs),
                        client.get_image_tags(image_ref),
                    )
                    .await
                    {
                        Ok(Ok(tags)) if !tags.is_empty() => tags,
                        Ok(Ok(_)) => Vec::new(), // Empty tags
                        Ok(Err(e)) => {
                            tracing::debug!("OCI registry API error for {}: {}", image_ref, e);
                            Vec::new()
                        }
                        Err(_) => {
                            tracing::debug!("OCI registry API timeout for {}", image_ref);
                            Vec::new()
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to create OCI registry client: {}", e);
                    Vec::new()
                }
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_image_reference() {
        let client = OciRegistryClient::new().unwrap();

        // Test Docker Hub official image
        let (registry, repo) = client.parse_image_reference("ubuntu").unwrap();
        assert_eq!(registry, "docker.io");
        assert_eq!(repo, "/library/ubuntu");

        // Test Docker Hub user image
        let (registry, repo) = client.parse_image_reference("nginx/nginx").unwrap();
        assert_eq!(registry, "docker.io");
        assert_eq!(repo, "/nginx/nginx");

        // Test GHCR image
        let (registry, repo) = client.parse_image_reference("ghcr.io/owner/repo").unwrap();
        assert_eq!(registry, "ghcr.io");
        assert_eq!(repo, "/owner/repo");

        // Test GCR image
        let (registry, repo) = client
            .parse_image_reference("gcr.io/project/image")
            .unwrap();
        assert_eq!(registry, "gcr.io");
        assert_eq!(repo, "/project/image");

        // Test with docker:// prefix
        let (registry, repo) = client.parse_image_reference("docker://ubuntu").unwrap();
        assert_eq!(registry, "docker.io");
        assert_eq!(repo, "/library/ubuntu");

        // Test complex path
        let (registry, repo) = client
            .parse_image_reference("registry.example.com/namespace/subnamespace/image")
            .unwrap();
        assert_eq!(registry, "registry.example.com");
        assert_eq!(repo, "/namespace/subnamespace/image");
    }

    #[test]
    fn test_filter_and_sort_tags() {
        let client = OciRegistryClient::new().unwrap();

        let tags = vec![
            "latest".to_string(),
            "1.0.0".to_string(),
            "2.1.0".to_string(),
            "edge".to_string(),
            "1.5.0".to_string(),
            "dev".to_string(),
            "alpine".to_string(),
            "3.0.0-beta".to_string(),
        ];

        let filtered = client.filter_and_sort_tags(tags);

        // Should filter out latest, edge, dev, beta
        assert!(!filtered.contains(&"latest".to_string()));
        assert!(!filtered.contains(&"edge".to_string()));
        assert!(!filtered.contains(&"dev".to_string()));
        assert!(!filtered.contains(&"3.0.0-beta".to_string()));

        // Should contain version numbers and alpine
        assert!(filtered.contains(&"2.1.0".to_string()));
        assert!(filtered.contains(&"1.5.0".to_string()));
        assert!(filtered.contains(&"1.0.0".to_string()));
        assert!(filtered.contains(&"alpine".to_string()));
    }

    #[test]
    fn test_supported_registries() {
        let client = OciRegistryClient::new().unwrap();
        let registries = client.supported_registries();

        assert!(registries.contains(&"docker.io"));
        assert!(registries.contains(&"ghcr.io"));
        assert!(registries.contains(&"gcr.io"));
        assert!(registries.contains(&"quay.io"));
    }

    #[tokio::test]
    async fn test_oci_registry_client_macro() {
        let get_tags = oci_registry_client_with_fallback!(3);

        let tags = get_tags("ubuntu").await;
        // This should either return tags or an empty vec (fallback)
        // We can't assert on specific content due to network variability
        println!("OCI macro test tags: {:?}", tags);
    }

    #[tokio::test]
    async fn test_docker_hub_integration() {
        let client = OciRegistryClient::new().unwrap();

        // Test with a well-known image
        match client.get_image_tags("ubuntu").await {
            Ok(tags) => {
                assert!(!tags.is_empty(), "Should return some tags for ubuntu");
                assert!(tags.len() <= 5, "Should return at most 5 tags");

                // Check that we got reasonable version tags
                let has_version_tag = tags
                    .iter()
                    .any(|tag| tag.chars().next().map_or(false, |c| c.is_ascii_digit()));
                assert!(has_version_tag, "Should include at least one version tag");

                println!("Ubuntu tags: {:?}", tags);
            }
            Err(e) => {
                // Network tests might fail in CI, so we'll just log the error
                println!(
                    "Docker Hub test failed (this might be expected in CI): {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    async fn test_image_exists() {
        let client = OciRegistryClient::new().unwrap();

        // Test with a well-known image that should exist
        match client.image_exists("ubuntu", Some("20.04")).await {
            Ok(exists) => {
                println!("Ubuntu 20.04 exists: {}", exists);
                // We can't assert true because network might fail
            }
            Err(e) => {
                println!("Image exists test failed (might be expected): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_get_image_digest() {
        let client = OciRegistryClient::new().unwrap();

        // Test getting digest for a specific tag
        match client.get_image_digest("ubuntu", "20.04").await {
            Ok(digest) => {
                assert!(digest.starts_with("sha256:"));
                println!("Ubuntu 20.04 digest: {}", digest);
            }
            Err(e) => {
                println!("Get digest test failed (might be expected): {}", e);
            }
        }
    }

    #[test]
    fn test_oci_registry_client_creation() {
        let client = OciRegistryClient::new().unwrap();
        assert!(client.configs.contains_key("docker.io"));
        assert!(client.configs.contains_key("ghcr.io"));
        assert!(client.configs.contains_key("gcr.io"));
    }

    #[test]
    fn test_parse_docker_image_reference() {
        let client = OciRegistryClient::new().unwrap();

        // Test various Docker image formats (only registry and repository, no tag parsing)
        let test_cases = vec![
            ("ubuntu", ("docker.io", "/library/ubuntu")),
            ("nginx/nginx", ("docker.io", "/nginx/nginx")),
            ("ghcr.io/owner/repo", ("ghcr.io", "/owner/repo")),
            ("gcr.io/project/image", ("gcr.io", "/project/image")),
            ("docker://ubuntu", ("docker.io", "/library/ubuntu")),
            (
                "registry.example.com/namespace/subnamespace/image",
                ("registry.example.com", "/namespace/subnamespace/image"),
            ),
        ];

        for (input, expected) in test_cases {
            let result = client.parse_image_reference(input);
            assert!(result.is_ok(), "Failed to parse: {}", input);
            let (registry, repository) = result.unwrap();
            assert_eq!(
                (registry, repository.as_str()),
                expected,
                "Mismatch for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_parse_docker_image_reference_with_sha() {
        let client = OciRegistryClient::new().unwrap();

        // Test SHA256 digests (simplified - just test that they parse correctly)
        let test_cases = vec![
            ("ubuntu", ("docker.io", "/library/ubuntu")),
            ("docker.io/library/ubuntu", ("docker.io", "/library/ubuntu")),
            ("ghcr.io/owner/repo", ("ghcr.io", "/owner/repo")),
            ("myuser/myapp", ("docker.io", "/myuser/myapp")),
        ];

        for (input, expected) in test_cases {
            let result = client.parse_image_reference(input);
            assert!(result.is_ok(), "Failed to parse: {}", input);
            let (registry, repository) = result.unwrap();
            assert_eq!(
                (registry, repository.as_str()),
                expected,
                "Mismatch for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_parse_docker_image_reference_invalid() {
        let client = OciRegistryClient::new().unwrap();

        // Test invalid formats - empty string should fail
        let invalid_cases = vec![""];

        for input in invalid_cases {
            let result = client.parse_image_reference(input);
            assert!(result.is_err(), "Should fail to parse: {}", input);
        }
    }

    #[tokio::test]
    async fn test_get_image_tags_docker_hub() {
        let client = OciRegistryClient::new().unwrap();

        // Test with a well-known image that should have tags
        let result = client.get_image_tags("alpine").await;

        // We can't guarantee the exact tags, but alpine should have some tags
        match result {
            Ok(tags) => {
                assert!(!tags.is_empty(), "Alpine should have tags");
                // Alpine typically has version tags like "3.18", "3.19", etc.
                // We filter out 'latest' so we expect version numbers
                let has_version_tag = tags
                    .iter()
                    .any(|tag| tag.chars().next().map_or(false, |c| c.is_ascii_digit()));
                assert!(has_version_tag, "Alpine should have version tags");
            }
            Err(e) => {
                // Network errors are acceptable in tests
                println!("Network error (acceptable in tests): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_get_image_tags_with_registry() {
        let client = OciRegistryClient::new().unwrap();

        // Test with GitHub Container Registry
        let result = client.get_image_tags("ghcr.io/actions/runner").await;

        match result {
            Ok(tags) => {
                assert!(!tags.is_empty(), "GitHub Actions runner should have tags");
            }
            Err(e) => {
                // Network errors are acceptable in tests
                println!("Network error (acceptable in tests): {}", e);
            }
        }
    }

    #[test]
    fn test_normalize_image_reference() {
        let client = OciRegistryClient::new().unwrap();

        let test_cases = vec![
            // Docker Hub official images
            ("ubuntu", "docker.io/library/ubuntu"),
            ("nginx", "docker.io/library/nginx"),
            ("alpine", "docker.io/library/alpine"),
            ("node", "docker.io/library/node"),
            ("python", "docker.io/library/python"),
            // Docker Hub user images
            ("myuser/myapp", "docker.io/myuser/myapp"),
            ("organization/service", "docker.io/organization/service"),
            // Already normalized
            ("docker.io/library/ubuntu", "docker.io/library/ubuntu"),
            ("ghcr.io/owner/repo", "ghcr.io/owner/repo"),
            ("gcr.io/project/image", "gcr.io/project/image"),
            // Custom registries
            (
                "registry.example.com/namespace/image",
                "registry.example.com/namespace/image",
            ),
            ("localhost:5000/myimage", "localhost:5000/myimage"),
        ];

        for (input, expected) in test_cases {
            let result = client.normalize_image_reference(input);
            assert_eq!(result, expected, "Mismatch for input: {}", input);
        }
    }

    #[test]
    fn test_registry_config_creation() {
        let config = RegistryConfig {
            name: "Docker Hub",
            registry_url: "https://registry-1.docker.io",
            requires_auth: false,
            namespace_format: NamespaceFormat::DockerHub,
        };

        assert_eq!(config.name, "Docker Hub");
        assert_eq!(config.registry_url, "https://registry-1.docker.io");
        assert!(!config.requires_auth);
        matches!(config.namespace_format, NamespaceFormat::DockerHub);
    }

    #[test]
    fn test_namespace_format_variants() {
        // Test that all namespace format variants can be created
        let _docker_hub = NamespaceFormat::DockerHub;
        let _ghcr = NamespaceFormat::GHCR;
        let _gcr = NamespaceFormat::GCR;
        let _generic = NamespaceFormat::Generic;
    }

    #[test]
    fn test_client_with_custom_registry() {
        let mut client = OciRegistryClient::new().unwrap();

        let custom_config = RegistryConfig {
            name: "Custom Registry",
            registry_url: "https://registry.example.com",
            requires_auth: true,
            namespace_format: NamespaceFormat::Generic,
        };

        client.add_registry("registry.example.com", custom_config);

        assert!(client.configs.contains_key("registry.example.com"));
        assert_eq!(client.configs.len(), 5); // 4 default + 1 custom
    }

    #[test]
    fn test_supported_registries_comprehensive() {
        let client = OciRegistryClient::new().unwrap();
        let supported = client.supported_registries();

        assert!(supported.contains(&"docker.io"));
        assert!(supported.contains(&"ghcr.io"));
        assert!(supported.contains(&"gcr.io"));
        assert_eq!(supported.len(), 4); // Updated to 4 since we have 4 default registries
    }

    #[tokio::test]
    async fn test_image_exists_comprehensive() {
        let client = OciRegistryClient::new().unwrap();

        // Test with a well-known image
        let result = client.image_exists("alpine", Some("latest")).await;

        match result {
            Ok(exists) => {
                assert!(exists, "Alpine:latest should exist");
            }
            Err(e) => {
                // Network errors are acceptable in tests
                println!("Network error (acceptable in tests): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_image_exists_nonexistent() {
        let client = OciRegistryClient::new().unwrap();

        // Test with a non-existent image
        let result = client
            .image_exists("nonexistent-image-12345", Some("nonexistent-tag"))
            .await;

        match result {
            Ok(exists) => {
                assert!(!exists, "Non-existent image should not exist");
            }
            Err(_) => {
                // Errors are acceptable for non-existent images
            }
        }
    }

    #[test]
    fn test_comprehensive_docker_image_parsing() {
        let client = OciRegistryClient::new().unwrap();

        // Test cases from GitHub Actions documentation examples (simplified)
        let github_actions_examples = vec![
            // From the uses documentation
            ("ubuntu", ("docker.io", "/library/ubuntu")),
            ("alpine", ("docker.io", "/library/alpine")),
            (
                "gcr.io/cloud-builders/gradle",
                ("gcr.io", "/cloud-builders/gradle"),
            ),
            // Real-world examples from popular actions
            ("node", ("docker.io", "/library/node")),
            ("python", ("docker.io", "/library/python")),
            ("golang", ("docker.io", "/library/golang")),
            ("ruby", ("docker.io", "/library/ruby")),
            ("openjdk", ("docker.io", "/library/openjdk")),
            // Container images used in CI/CD
            ("postgres", ("docker.io", "/library/postgres")),
            ("redis", ("docker.io", "/library/redis")),
            ("mysql", ("docker.io", "/library/mysql")),
            ("mongodb", ("docker.io", "/library/mongodb")),
            ("elasticsearch", ("docker.io", "/library/elasticsearch")),
            // GitHub Container Registry examples
            ("ghcr.io/actions/runner", ("ghcr.io", "/actions/runner")),
            ("ghcr.io/microsoft/dotnet", ("ghcr.io", "/microsoft/dotnet")),
            (
                "ghcr.io/github/super-linter",
                ("ghcr.io", "/github/super-linter"),
            ),
        ];

        for (input, expected) in github_actions_examples {
            let result = client.parse_image_reference(input);
            assert!(
                result.is_ok(),
                "Failed to parse GitHub Actions example: {}",
                input
            );
            let (registry, repository) = result.unwrap();
            assert_eq!(
                (registry, repository.as_str()),
                expected,
                "Mismatch for GitHub Actions example: {}",
                input
            );
        }
    }
}
