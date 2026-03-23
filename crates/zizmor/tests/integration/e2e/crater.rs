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

#[cfg_attr(not(feature = "crater-tests"), ignore)]
#[test]
fn warehouse() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--persona=pedantic"])
            .input("pypi/warehouse@9ed30d191788fcfa9c5be56bcce9b743e758903e")
            .run()?
    );
    Ok(())
}

#[cfg_attr(not(feature = "crater-tests"), ignore)]
#[test]
fn pyca_cryptography() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--persona=pedantic"])
            .input("pyca/cryptography@43eb178ee3aae8d0060221118437b03c23570a41")
            .run()?
    );
    Ok(())
}

#[cfg_attr(not(feature = "crater-tests"), ignore)]
#[test]
fn astral_sh_uv() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .offline(false)
            .output(OutputMode::Both)
            .args(["--persona=pedantic"])
            .input("astral-sh/uv@8ed803e507f41937d55865ae88c8c806573b3b9e")
            .run()?
    );
    Ok(())
}
