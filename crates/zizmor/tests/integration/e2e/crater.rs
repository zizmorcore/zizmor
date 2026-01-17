//! "Crater" runs of zizmor, i.e. over large external projects.
//!
//! The idea behind these tests is to detect (unintended) large changes
//! between versions of zizmor.

use crate::common::{OutputMode, zizmor};

#[cfg_attr(not(feature = "crater-tests"), ignore)]
#[test]
fn curl() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--persona=pedantic"])
            .input("curl/curl@6c8956c1cbf5cffcd2fd4571cf277e2eec280578")
            .run()?
    );
    Ok(())
}

#[cfg_attr(not(feature = "crater-tests"), ignore)]
#[test]
fn libssh2() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--persona=pedantic"])
            .input("libssh2/libssh2@cb252b5909630dd439d3f80ca9318a99da253dbe")
            .run()?
    );
    Ok(())
}
