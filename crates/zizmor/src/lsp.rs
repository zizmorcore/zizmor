//! zizmor's language server.

use camino::Utf8Path;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::audit::AuditInput;
use crate::config::Config;
use crate::finding::location::Point;
use crate::finding::{Persona, Severity};
use crate::models::action::Action;
use crate::models::workflow::Workflow;
use crate::registry::{FindingRegistry, InputKey};
use crate::{AuditRegistry, AuditState};

struct LspDocumentCommon {
    uri: lsp_types::Url,
    text: String,
    version: Option<i32>,
}

#[derive(Debug)]
struct Backend {
    audit_registry: AuditRegistry,
    client: Client,
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(
        &self,
        _: lsp_types::InitializeParams,
    ) -> Result<lsp_types::InitializeResult> {
        Ok(lsp_types::InitializeResult {
            server_info: Some(lsp_types::ServerInfo {
                name: "zizmor (LSP)".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
            capabilities: lsp_types::ServerCapabilities {
                text_document_sync: Some(lsp_types::TextDocumentSyncCapability::Kind(
                    lsp_types::TextDocumentSyncKind::FULL,
                )),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: lsp_types::InitializedParams) {
        let selectors = vec![
            lsp_types::DocumentFilter {
                language: Some("yaml".into()),
                scheme: None,
                pattern: Some("**/.github/workflows/*.{yml,yaml}".into()),
            },
            lsp_types::DocumentFilter {
                language: Some("yaml".into()),
                scheme: None,
                pattern: Some("**/action.{yml,yaml}".into()),
            },
        ];

        // Register our capabilities with the client.
        // Clients like the VS Code extension should do this for us, but we
        // also explicitly request these capabilities in case the client/integration
        // neglects to.
        self.client
            .register_capability(vec![
                lsp_types::Registration {
                    id: "zizmor-didopen".into(),
                    method: "textDocument/didOpen".into(),
                    register_options: Some(
                        serde_json::to_value(lsp_types::TextDocumentRegistrationOptions {
                            document_selector: Some(selectors.clone()),
                        })
                        .unwrap(),
                    ),
                },
                lsp_types::Registration {
                    id: "zizmor-didchange".into(),
                    method: "textDocument/didChange".into(),
                    register_options: Some(
                        serde_json::to_value(lsp_types::TextDocumentChangeRegistrationOptions {
                            document_selector: Some(selectors.clone()),
                            sync_kind: 1, // FULL
                        })
                        .unwrap(),
                    ),
                },
                lsp_types::Registration {
                    id: "zizmor-didsave".into(),
                    method: "textDocument/didSave".into(),
                    register_options: Some(
                        serde_json::to_value(lsp_types::TextDocumentSaveRegistrationOptions {
                            include_text: Some(true),
                            text_document_registration_options:
                                lsp_types::TextDocumentRegistrationOptions {
                                    document_selector: Some(selectors.clone()),
                                },
                        })
                        .unwrap(),
                    ),
                },
                lsp_types::Registration {
                    id: "zizmor-didclose".into(),
                    method: "textDocument/didClose".into(),
                    register_options: Some(
                        serde_json::to_value(lsp_types::TextDocumentRegistrationOptions {
                            document_selector: Some(selectors),
                        })
                        .unwrap(),
                    ),
                },
            ])
            .await
            .expect("failed to register text document capabilities with the LSP client");

        self.client
            .log_message(lsp_types::MessageType::INFO, "server initialized!")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        tracing::debug!("graceful shutdown requested");
        Ok(())
    }

    async fn did_open(&self, params: lsp_types::DidOpenTextDocumentParams) {
        tracing::debug!("did_open: {:?}", params);
        self.audit(LspDocumentCommon {
            uri: params.text_document.uri,
            text: params.text_document.text,
            version: Some(params.text_document.version),
        })
        .await;
    }

    async fn did_change(&self, params: lsp_types::DidChangeTextDocumentParams) {
        tracing::debug!("did_change: {:?}", params);
        let mut params = params;
        let Some(change) = params.content_changes.pop() else {
            return;
        };

        self.audit(LspDocumentCommon {
            uri: params.text_document.uri,
            text: change.text,
            version: Some(params.text_document.version),
        })
        .await;
    }

    async fn did_save(&self, params: lsp_types::DidSaveTextDocumentParams) {
        tracing::debug!("did_save: {:?}", params);
        if let Some(text) = params.text {
            self.audit(LspDocumentCommon {
                uri: params.text_document.uri,
                text,
                version: None,
            })
            .await;
        }
    }
}

impl Backend {
    async fn audit_inner(&self, params: LspDocumentCommon) -> anyhow::Result<()> {
        tracing::debug!("analyzing: {:?} (version={:?})", params.uri, params.version);
        let path = Utf8Path::new(params.uri.path());
        let input = if matches!(path.file_name(), Some("action.yml" | "action.yaml")) {
            AuditInput::from(Action::from_string(
                params.text,
                InputKey::local(path, None)?,
            )?)
        } else if matches!(path.extension(), Some("yml" | "yaml")) {
            AuditInput::from(Workflow::from_string(
                params.text,
                InputKey::local(path, None)?,
            )?)
        } else {
            anyhow::bail!("asked to audit unexpected file: {path}");
        };

        let config = Config::default();
        let mut registry = FindingRegistry::new(None, None, Persona::Regular, &config);
        for (_, audit) in self.audit_registry.iter_audits() {
            registry.extend(audit.audit(&input)?);
        }

        let diagnostics = registry
            .findings()
            .iter()
            .map(|finding| {
                let primary = finding.primary_location();
                lsp_types::Diagnostic {
                    range: lsp_types::Range {
                        start: primary.concrete.location.start_point.into(),
                        end: primary.concrete.location.end_point.into(),
                    },
                    severity: Some(finding.determinations.severity.into()),
                    code: Some(lsp_types::NumberOrString::String(finding.ident.into())),
                    code_description: Some(lsp_types::CodeDescription {
                        href: lsp_types::Url::parse(finding.url)
                            .expect("finding contains an invalid URL somehow"),
                    }),
                    source: Some("zizmor".into()),
                    message: finding.desc.into(),
                    // TODO: Plumb non-primary locations here, maybe?
                    related_information: None,
                    tags: None,
                    data: None,
                }
            })
            .collect::<Vec<_>>();

        self.client
            .publish_diagnostics(params.uri, diagnostics, params.version)
            .await;

        Ok(())
    }

    async fn audit(&self, params: LspDocumentCommon) {
        if let Err(e) = self.audit_inner(params).await {
            self.client
                .log_message(lsp_types::MessageType::ERROR, format!("audit failed: {e}"))
                .await;
        }
    }
}

impl From<Severity> for lsp_types::DiagnosticSeverity {
    fn from(value: Severity) -> Self {
        // TODO: Does this mapping make sense?
        match value {
            Severity::Unknown => lsp_types::DiagnosticSeverity::HINT,
            Severity::Informational => lsp_types::DiagnosticSeverity::INFORMATION,
            Severity::Low => lsp_types::DiagnosticSeverity::WARNING,
            Severity::Medium => lsp_types::DiagnosticSeverity::WARNING,
            Severity::High => lsp_types::DiagnosticSeverity::ERROR,
        }
    }
}

impl From<Point> for lsp_types::Position {
    fn from(value: Point) -> Self {
        Self {
            line: value.row as u32,
            character: value.column as u32,
        }
    }
}

#[tokio::main]
pub(crate) async fn run() -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let config = Config::default();

    let audit_state = AuditState {
        config: &config,
        no_online_audits: false,
        cache_dir: std::env::temp_dir(),
        gh_token: None,
        gh_hostname: crate::GitHubHost::Standard("github.com".into()),
    };

    let audits = AuditRegistry::default_audits(&audit_state)?;
    let (service, socket) = LspService::new(|client| Backend {
        audit_registry: audits,
        client,
    });

    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(())
}
