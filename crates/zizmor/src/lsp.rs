//! zizmor's language server.

use camino::Utf8Path;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::audit::AuditInput;
use crate::config::Config;
use crate::{AuditRegistry, AuditState};

struct LspDocumentCommon<'a> {
    uri: lsp_types::Url,
    text: &'a str,
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
                text_document_sync: Some(lsp_types::TextDocumentSyncCapability::Options(
                    lsp_types::TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(lsp_types::TextDocumentSyncKind::FULL),
                        save: Some(lsp_types::TextDocumentSyncSaveOptions::SaveOptions(
                            lsp_types::SaveOptions {
                                include_text: Some(true),
                            },
                        )),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: lsp_types::InitializedParams) {
        self.client
            .register_capability(vec![lsp_types::Registration {
                id: "zizmor-cap-textdocumentregistrationoptions".into(),
                method: "textDocument/didOpen".into(),
                register_options: Some(
                    serde_json::to_value(lsp_types::TextDocumentRegistrationOptions {
                        document_selector: Some(vec![
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
                        ]),
                    })
                    .unwrap(),
                ),
            }])
            .await
            .expect("failed to register text document capabilities with the LSP client");

        self.client
            .log_message(lsp_types::MessageType::INFO, "server initialized!")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: lsp_types::DidOpenTextDocumentParams) {
        tracing::debug!("did_open: {:?}", params);
        self.analyze(LspDocumentCommon {
            uri: params.text_document.uri,
            text: &params.text_document.text,
            version: Some(params.text_document.version),
        })
        .await;
    }

    async fn did_change(&self, params: lsp_types::DidChangeTextDocumentParams) {
        tracing::debug!("did_change: {:?}", params);
        let Some(change) = params.content_changes.first() else {
            return;
        };

        self.analyze(LspDocumentCommon {
            uri: params.text_document.uri,
            text: &change.text,
            version: Some(params.text_document.version),
        })
        .await;
    }

    async fn did_save(&self, params: lsp_types::DidSaveTextDocumentParams) {
        tracing::debug!("did_save: {:?}", params);
        if let Some(text) = &params.text {
            self.analyze(LspDocumentCommon {
                uri: params.text_document.uri,
                text: &text,
                version: None,
            })
            .await;
        }
    }
}

impl Backend {
    async fn analyze<'a>(&self, params: LspDocumentCommon<'a>) {
        tracing::debug!("analyzing: {:?} (version={:?})", params.uri, params.version);
        let path = Utf8Path::new(params.uri.path());
        let input = if matches!(path.file_name(), Some("action.yml" | "action.yaml")) {
            todo!()
        } else if matches!(path.extension(), Some("yml" | "yaml")) {
            todo!()
        } else {
            return;
        };

        // self.client.publish_diagnostics(uri, diags, version)
        todo!()
    }
}

#[tokio::main]
pub(crate) async fn run() {
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

    let (service, socket) = LspService::new(|client| Backend {
        audit_registry: AuditRegistry::default_audits(&audit_state).unwrap(),
        client,
    });
    Server::new(stdin, stdout, socket).serve(service).await;
}
