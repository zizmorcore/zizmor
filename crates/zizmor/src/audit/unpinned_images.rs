use anyhow::Result;

use crate::{
    apply_yaml_patch,
    finding::{Confidence, Finding, Fix, Persona, Severity, SymbolicLocation},
    models::JobExt as _,
    state::AuditState,
    yaml_patch::YamlPatchOperation,
};

use github_actions_models::common::DockerUses;
use github_actions_models::workflow::job::Container;

use super::{Audit, AuditLoadError, audit_meta};

pub(crate) struct UnpinnedImages;

impl UnpinnedImages {
    fn build_finding<'doc>(
        &self,
        location: SymbolicLocation<'doc>,
        annotation: &str,
        persona: Persona,
        fixes: Vec<Fix>,
        job: &super::NormalJob<'doc>,
    ) -> Result<Finding<'doc>> {
        let mut annotated_location = location;
        annotated_location = annotated_location.annotated(annotation);
        let mut finding_builder = Self::finding()
            .severity(Severity::High)
            .confidence(Confidence::High)
            .add_location(annotated_location)
            .persona(persona);

        for fix in fixes {
            finding_builder = finding_builder.fix(fix);
        }

        finding_builder.build(job.parent())
    }

    /// Create a fix that provides guidance on pinning to SHA256 hash
    fn create_sha256_pin_guidance_fix(image_name: &str) -> Fix {
        Fix {
            title: "Pin container image to SHA256 hash".to_string(),
            description: format!(
                "Pin the container image '{}' to a specific SHA256 hash for security and reproducibility. \
                You can find the SHA256 hash by:\n\
                1. Checking your container registry's web interface\n\
                2. Running 'docker inspect {}' locally if you have the image\n\
                3. Using 'docker pull {}' and checking the digest\n\
                4. Looking at the registry API or manifest\n\n\
                Example: {}@sha256:abcd1234...",
                image_name, image_name, image_name, image_name
            ),
            apply: Box::new(|content| Ok(Some(content.to_string()))),
        }
    }

    /// Create a fix that adds a specific tag instead of latest
    fn create_specific_tag_fix(image_path: &str, image_name: &str) -> Fix {
        Fix {
            title: "Replace 'latest' tag with specific version".to_string(),
            description: format!(
                "Replace the 'latest' tag with a specific version tag for '{}'. \
                Check the container registry for available tags and choose a specific version. \
                This provides better reproducibility than 'latest' which can change over time.",
                image_name
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: image_path.to_string(),
                value: serde_yaml::Value::String(format!("{}:v1.0.0", image_name)),
            }]),
        }
    }

    /// Create a fix that adds a tag to completely unpinned images
    fn create_add_tag_fix(image_path: &str, image_name: &str) -> Fix {
        Fix {
            title: "Add version tag to image".to_string(),
            description: format!(
                "Add a specific version tag to the unpinned image '{}'. \
                Check the container registry for available tags and choose an appropriate version.",
                image_name
            ),
            apply: apply_yaml_patch!(vec![YamlPatchOperation::Replace {
                path: image_path.to_string(),
                value: serde_yaml::Value::String(format!("{}:v1.0.0", image_name)),
            }]),
        }
    }

    /// Create a fix that provides guidance on using docker inspect
    fn create_docker_inspect_guidance_fix(image_name: &str) -> Fix {
        Fix {
            title: "Use docker inspect to find SHA256 hash".to_string(),
            description: format!(
                "Use 'docker inspect' to find the SHA256 hash for '{}'. \
                Run the following commands:\n\
                1. docker pull {}\n\
                2. docker inspect {} --format='{{{{.RepoDigests}}}}'\n\
                3. Use the SHA256 hash from the output to pin the image",
                image_name, image_name, image_name
            ),
            apply: Box::new(|content| Ok(Some(content.to_string()))),
        }
    }

    /// Create a fix that provides registry-specific guidance
    fn create_registry_guidance_fix(image_name: &str) -> Fix {
        let registry_hint = if image_name.contains("docker.io") || !image_name.contains('/') {
            "Docker Hub"
        } else if image_name.contains("ghcr.io") {
            "GitHub Container Registry"
        } else if image_name.contains("gcr.io") {
            "Google Container Registry"
        } else if image_name.contains("quay.io") {
            "Quay.io"
        } else {
            "your container registry"
        };

        Fix {
            title: "Check container registry for SHA256 hash".to_string(),
            description: format!(
                "Check {} for the SHA256 hash of '{}'. \
                Most container registries display the SHA256 digest in their web interface. \
                Look for the 'digest' or 'sha256' field in the image details.",
                registry_hint, image_name
            ),
            apply: Box::new(|content| Ok(Some(content.to_string()))),
        }
    }

    /// Get the appropriate fixes based on the image state
    fn get_fixes_for_image(image: &DockerUses, image_path: &str) -> Vec<Fix> {
        let image_name = if let Some(ref tag) = image.tag {
            format!("{}:{}", image.image, tag)
        } else {
            image.image.clone()
        };

        let mut fixes = vec![];

        match image.hash {
            Some(_) => {
                // Already has hash, no fixes needed
            }
            None => match image.tag.as_deref() {
                Some("latest") => {
                    // Has latest tag - suggest specific tag and SHA256
                    fixes.push(Self::create_specific_tag_fix(image_path, &image.image));
                    fixes.push(Self::create_sha256_pin_guidance_fix(&image.image));
                    fixes.push(Self::create_registry_guidance_fix(&image.image));
                }
                None => {
                    // Completely unpinned - suggest adding tag and SHA256
                    fixes.push(Self::create_add_tag_fix(image_path, &image.image));
                    fixes.push(Self::create_sha256_pin_guidance_fix(&image.image));
                    fixes.push(Self::create_docker_inspect_guidance_fix(&image.image));
                }
                Some(_) => {
                    // Has specific tag but no SHA256 - suggest SHA256 pinning
                    fixes.push(Self::create_sha256_pin_guidance_fix(&image_name));
                    fixes.push(Self::create_docker_inspect_guidance_fix(&image_name));
                    fixes.push(Self::create_registry_guidance_fix(&image_name));
                }
            },
        }

        fixes
    }
}

audit_meta!(
    UnpinnedImages,
    "unpinned-images",
    "unpinned image references"
);

impl Audit for UnpinnedImages {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError> {
        Ok(Self)
    }

    fn audit_normal_job<'doc>(
        &self,
        job: &super::NormalJob<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];
        let mut image_refs_with_locations: Vec<(DockerUses, SymbolicLocation<'doc>, String)> =
            vec![];

        if let Some(Container::Container { image, .. }) = &job.container {
            let image_path = format!("/jobs/{}/container/image", job.id());
            image_refs_with_locations.push((
                image.parse().unwrap(),
                job.location()
                    .primary()
                    .with_keys(&["container".into(), "image".into()]),
                image_path,
            ));
        }

        for (service, config) in job.services.iter() {
            if let Container::Container { image, .. } = &config {
                let image_path = format!("/jobs/{}/services/{}/image", job.id(), service);
                image_refs_with_locations.push((
                    image.parse().unwrap(),
                    job.location().primary().with_keys(&[
                        "services".into(),
                        service.as_str().into(),
                        "image".into(),
                    ]),
                    image_path,
                ));
            }
        }

        for (image, location, image_path) in image_refs_with_locations {
            let fixes = Self::get_fixes_for_image(&image, &image_path);

            match image.hash {
                Some(_) => continue, // Already pinned to hash, no finding needed
                None => match image.tag.as_deref() {
                    Some("latest") => {
                        findings.push(self.build_finding(
                            location,
                            "container image is pinned to latest",
                            Persona::Regular,
                            fixes,
                            job,
                        )?);
                    }
                    None => {
                        findings.push(self.build_finding(
                            location,
                            "container image is unpinned",
                            Persona::Regular,
                            fixes,
                            job,
                        )?);
                    }
                    Some(_) => {
                        findings.push(self.build_finding(
                            location,
                            "container image is not pinned to a SHA256 hash",
                            Persona::Pedantic,
                            fixes,
                            job,
                        )?);
                    }
                },
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use github_actions_models::common::DockerUses;

    #[test]
    fn test_sha256_pin_guidance_fix() {
        let fix = UnpinnedImages::create_sha256_pin_guidance_fix("nginx");

        assert_eq!(fix.title, "Pin container image to SHA256 hash");
        assert!(fix.description.contains("nginx"));
        assert!(fix.description.contains("docker inspect"));
        assert!(fix.description.contains("sha256:abcd1234"));

        // Test that the fix doesn't modify content (guidance only)
        let result = fix.apply_to_content("test content").unwrap();
        assert_eq!(result, Some("test content".to_string()));
    }

    #[test]
    fn test_specific_tag_fix() {
        let fix = UnpinnedImages::create_specific_tag_fix("/jobs/test/container/image", "nginx");

        assert_eq!(fix.title, "Replace 'latest' tag with specific version");
        assert!(fix.description.contains("nginx"));
        assert!(fix.description.contains("latest"));
    }

    #[test]
    fn test_add_tag_fix() {
        let fix = UnpinnedImages::create_add_tag_fix("/jobs/test/container/image", "nginx");

        assert_eq!(fix.title, "Add version tag to image");
        assert!(fix.description.contains("nginx"));
        assert!(fix.description.contains("unpinned"));
    }

    #[test]
    fn test_docker_inspect_guidance_fix() {
        let fix = UnpinnedImages::create_docker_inspect_guidance_fix("nginx:1.21");

        assert_eq!(fix.title, "Use docker inspect to find SHA256 hash");
        assert!(fix.description.contains("docker pull nginx:1.21"));
        assert!(fix.description.contains("docker inspect nginx:1.21"));

        // Test that the fix doesn't modify content (guidance only)
        let result = fix.apply_to_content("test content").unwrap();
        assert_eq!(result, Some("test content".to_string()));
    }

    #[test]
    fn test_registry_guidance_fix() {
        // Test Docker Hub detection
        let fix = UnpinnedImages::create_registry_guidance_fix("nginx");
        assert!(fix.description.contains("Docker Hub"));

        // Test GitHub Container Registry detection
        let fix = UnpinnedImages::create_registry_guidance_fix("ghcr.io/owner/repo");
        assert!(fix.description.contains("GitHub Container Registry"));

        // Test Google Container Registry detection
        let fix = UnpinnedImages::create_registry_guidance_fix("gcr.io/project/image");
        assert!(fix.description.contains("Google Container Registry"));

        // Test Quay.io detection
        let fix = UnpinnedImages::create_registry_guidance_fix("quay.io/org/image");
        assert!(fix.description.contains("Quay.io"));

        // Test generic registry
        let fix = UnpinnedImages::create_registry_guidance_fix("registry.example.com/image");
        assert!(fix.description.contains("your container registry"));
    }

    #[test]
    fn test_get_fixes_for_image_with_hash() {
        let image = DockerUses {
            registry: None,
            image: "nginx".to_string(),
            tag: Some("1.21".to_string()),
            hash: Some("sha256:abcd1234".to_string()),
        };

        let fixes = UnpinnedImages::get_fixes_for_image(&image, "/jobs/test/container/image");

        // Should have no fixes since it already has a hash
        assert_eq!(fixes.len(), 0);
    }

    #[test]
    fn test_get_fixes_for_image_with_latest_tag() {
        let image = DockerUses {
            registry: None,
            image: "nginx".to_string(),
            tag: Some("latest".to_string()),
            hash: None,
        };

        let fixes = UnpinnedImages::get_fixes_for_image(&image, "/jobs/test/container/image");

        // Should have 3 fixes: specific tag, SHA256 guidance, registry guidance
        assert_eq!(fixes.len(), 3);
        assert_eq!(fixes[0].title, "Replace 'latest' tag with specific version");
        assert_eq!(fixes[1].title, "Pin container image to SHA256 hash");
        assert_eq!(fixes[2].title, "Check container registry for SHA256 hash");
    }

    #[test]
    fn test_get_fixes_for_image_unpinned() {
        let image = DockerUses {
            registry: None,
            image: "nginx".to_string(),
            tag: None,
            hash: None,
        };

        let fixes = UnpinnedImages::get_fixes_for_image(&image, "/jobs/test/container/image");

        // Should have 3 fixes: add tag, SHA256 guidance, docker inspect guidance
        assert_eq!(fixes.len(), 3);
        assert_eq!(fixes[0].title, "Add version tag to image");
        assert_eq!(fixes[1].title, "Pin container image to SHA256 hash");
        assert_eq!(fixes[2].title, "Use docker inspect to find SHA256 hash");
    }

    #[test]
    fn test_get_fixes_for_image_with_specific_tag() {
        let image = DockerUses {
            registry: None,
            image: "nginx".to_string(),
            tag: Some("1.21".to_string()),
            hash: None,
        };

        let fixes = UnpinnedImages::get_fixes_for_image(&image, "/jobs/test/container/image");

        // Should have 3 fixes: SHA256 guidance, docker inspect guidance, registry guidance
        assert_eq!(fixes.len(), 3);
        assert_eq!(fixes[0].title, "Pin container image to SHA256 hash");
        assert_eq!(fixes[1].title, "Use docker inspect to find SHA256 hash");
        assert_eq!(fixes[2].title, "Check container registry for SHA256 hash");
    }

    #[test]
    fn test_fix_descriptions_are_informative() {
        let fixes = [
            UnpinnedImages::create_sha256_pin_guidance_fix("nginx"),
            UnpinnedImages::create_specific_tag_fix("/path", "nginx"),
            UnpinnedImages::create_add_tag_fix("/path", "nginx"),
            UnpinnedImages::create_docker_inspect_guidance_fix("nginx"),
            UnpinnedImages::create_registry_guidance_fix("nginx"),
        ];

        for fix in &fixes {
            // Each fix should have a meaningful title and description
            assert!(!fix.title.is_empty());
            assert!(!fix.description.is_empty());
            assert!(fix.description.len() > 50); // Should be reasonably detailed
        }
    }
}
