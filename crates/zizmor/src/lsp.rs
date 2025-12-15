//! zizmor's language server.

use std::str::FromStr;

use camino::Utf8Path;
use thiserror::Error;
use tower_lsp_server::ls_types::{self, TextDocumentSyncKind};
use tower_lsp_server::{Client, LanguageServer, LspService, Server};

use crate::audit::AuditInput;
use crate::config::Config;
use crate::finding::location::Point;
use crate::finding::{Persona, Severity};
use crate::models::action::Action;
use crate::models::workflow::Workflow;
use crate::registry::input::{InputGroup, InputRegistry};
use crate::registry::{FindingRegistry, input::InputKey};
use crate::{AuditRegistry, AuditState};

#[derive(Debug, Error)]
#[error("LSP server error")]
pub(crate) struct Error {
    #[from]
    inner: anyhow::Error,
}

struct LspDocumentCommon {
    uri: ls_types::Uri,
    text: String,
    version: Option<i32>,
}

#[derive(Debug)]
struct Backend {
    audit_registry: AuditRegistry,
    client: Client,
}

impl LanguageServer for Backend {
    async fn initialize(
        &self,
        _: ls_types::InitializeParams,
    ) -> tower_lsp_server::jsonrpc::Result<ls_types::InitializeResult> {
        Ok(ls_types::InitializeResult {
            server_info: Some(ls_types::ServerInfo {
                name: "zizmor (LSP)".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
            capabilities: ls_types::ServerCapabilities {
                text_document_sync: Some(ls_types::TextDocumentSyncCapability::Kind(
                    ls_types::TextDocumentSyncKind::FULL,
                )),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: ls_types::InitializedParams) {
        let selectors = vec![
            ls_types::DocumentFilter {
                language: Some("yaml".into()),
                scheme: None,
                pattern: Some("**/.github/workflows/*.{yml,yaml}".into()),
            },
            ls_types::DocumentFilter {
                language: Some("yaml".into()),
                scheme: None,
                pattern: Some("**/action.{yml,yaml}".into()),
            },
            ls_types::DocumentFilter {
                language: Some("yaml".into()),
                scheme: None,
                pattern: Some("**/.github/dependabot.{yml,yaml}".into()),
            },
        ];

        // Register our capabilities with the client.
        // Clients like the VS Code extension should do this for us, but we
        // also explicitly request these capabilities in case the client/integration
        // neglects to.
        self.client
            .register_capability(vec![
                ls_types::Registration {
                    id: "zizmor-didopen".into(),
                    method: "textDocument/didOpen".into(),
                    register_options: Some(
                        serde_json::to_value(ls_types::TextDocumentRegistrationOptions {
                            document_selector: Some(selectors.clone()),
                        })
                        .expect("failed to serialize LSP document registration options"),
                    ),
                },
                ls_types::Registration {
                    id: "zizmor-didchange".into(),
                    method: "textDocument/didChange".into(),
                    register_options: Some(
                        serde_json::to_value(ls_types::TextDocumentChangeRegistrationOptions {
                            document_selector: Some(selectors.clone()),
                            sync_kind: TextDocumentSyncKind::FULL,
                        })
                        .expect("failed to serialize LSP document registration options"),
                    ),
                },
                ls_types::Registration {
                    id: "zizmor-didsave".into(),
                    method: "textDocument/didSave".into(),
                    register_options: Some(
                        serde_json::to_value(ls_types::TextDocumentSaveRegistrationOptions {
                            include_text: Some(true),
                            text_document_registration_options:
                                ls_types::TextDocumentRegistrationOptions {
                                    document_selector: Some(selectors.clone()),
                                },
                        })
                        .expect("failed to serialize LSP document registration options"),
                    ),
                },
                ls_types::Registration {
                    id: "zizmor-didclose".into(),
                    method: "textDocument/didClose".into(),
                    register_options: Some(
                        serde_json::to_value(ls_types::TextDocumentRegistrationOptions {
                            document_selector: Some(selectors),
                        })
                        .expect("failed to serialize LSP document registration options"),
                    ),
                },
            ])
            .await
            .expect("failed to register text document capabilities with the LSP client");

        self.client
            .log_message(ls_types::MessageType::INFO, "server initialized!")
            .await;
    }

    async fn shutdown(&self) -> tower_lsp_server::jsonrpc::Result<()> {
        tracing::debug!("graceful shutdown requested");
        Ok(())
    }

    async fn did_open(&self, params: ls_types::DidOpenTextDocumentParams) {
        tracing::debug!("did_open: {:?}", params);
        self.audit(LspDocumentCommon {
            uri: params.text_document.uri,
            text: params.text_document.text,
            version: Some(params.text_document.version),
        })
        .await;
    }

    async fn did_change(&self, params: ls_types::DidChangeTextDocumentParams) {
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

    async fn did_save(&self, params: ls_types::DidSaveTextDocumentParams) {
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
        let path = Utf8Path::new(params.uri.path().as_str());
        let input = if matches!(path.file_name(), Some("action.yml" | "action.yaml")) {
            AuditInput::from(Action::from_string(
                params.text,
                InputKey::local("lsp".into(), path, None),
            )?)
        } else if matches!(path.extension(), Some("yml" | "yaml")) {
            AuditInput::from(Workflow::from_string(
                params.text,
                InputKey::local("lsp".into(), path, None),
            )?)
        } else {
            anyhow::bail!("asked to audit unexpected file: {path}");
        };

        let mut group = InputGroup::new(Config::default());
        group.register_input(input)?;
        let mut input_registry = InputRegistry::new();
        input_registry.groups.insert("lsp".into(), group);

        let mut registry = FindingRegistry::new(&input_registry, None, None, Persona::Regular);

        for (input_key, input) in input_registry.iter_inputs() {
            for (ident, audit) in self.audit_registry.iter_audits() {
                registry.extend(
                    audit
                        .audit(ident, input, input_registry.get_config(input_key.group()))
                        .await?,
                );
            }
        }

        let diagnostics = registry
            .findings()
            .iter()
            .map(|finding| {
                let primary = finding.primary_location();
                ls_types::Diagnostic {
                    range: ls_types::Range {
                        start: primary.concrete.location.start_point.into(),
                        end: primary.concrete.location.end_point.into(),
                    },
                    severity: Some(finding.determinations.severity.into()),
                    code: Some(ls_types::NumberOrString::String(finding.ident.into())),
                    code_description: Some(ls_types::CodeDescription {
                        href: ls_types::Uri::from_str(finding.url)
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
                .log_message(ls_types::MessageType::ERROR, format!("audit failed: {e}"))
                .await;
        }
    }
}

impl From<Severity> for ls_types::DiagnosticSeverity {
    fn from(value: Severity) -> Self {
        // TODO: Does this mapping make sense?
        match value {
            Severity::Informational => ls_types::DiagnosticSeverity::INFORMATION,
            Severity::Low => ls_types::DiagnosticSeverity::WARNING,
            Severity::Medium => ls_types::DiagnosticSeverity::WARNING,
            Severity::High => ls_types::DiagnosticSeverity::ERROR,
        }
    }
}

impl From<Point> for ls_types::Position {
    fn from(value: Point) -> Self {
        Self {
            line: value.row as u32,
            character: value.column as u32,
        }
    }
}

pub(crate) async fn run() -> Result<(), Error> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let state = AuditState::default();

    let audits = AuditRegistry::default_audits(&state)?;
    let (service, socket) = LspService::new(|client| Backend {
        audit_registry: audits,
        client,
    });

    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(())
}
