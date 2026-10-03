pub(crate) use zizmor_dev::{NetworkMode, OutputMode, WorkspaceBuilder, input_under_test};

/// Create a runner using the binary built for this integration test target.
pub(crate) fn zizmor() -> zizmor_dev::Zizmor {
    zizmor_dev::Zizmor::cargo_bin()
}
