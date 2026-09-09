//! Clap-based models for Docker CLI argument parsing.
//!
//! These structs model the subset of Docker's CLI that we need to extract
//! image references from `pull`, `run`, and `create` subcommands. Clap
//! handles combined short flags (`-dit`), `--flag=value` syntax, and
//! value-consuming vs boolean flag disambiguation automatically.
//!
//! Unknown subcommands or parse failures return `None` from
//! [`DockerCli::parse_image`], which is the safe false-negative behavior
//! for a security tool.

use clap::{Args, Parser, Subcommand};

/// Top-level Docker CLI model.
///
/// Handles global flags that appear before the subcommand
/// (e.g. `docker --context foo run alpine`).
#[derive(Parser, Debug)]
#[command(
    no_binary_name = true,
    disable_help_flag = true,
    disable_version_flag = true
)]
struct DockerCli {
    #[command(flatten)]
    _global: DockerGlobalFlags,

    #[command(subcommand)]
    command: DockerCommand,
}

/// Global flags that can appear before any Docker subcommand.
#[derive(Args, Debug)]
struct DockerGlobalFlags {
    // Boolean global flags
    #[arg(short = 'D', long = "debug")]
    _debug: bool,

    #[arg(long = "tls")]
    _tls: bool,

    #[arg(long = "tlsverify")]
    _tlsverify: bool,

    // Value-consuming global flags
    #[arg(long = "config")]
    _config: Option<String>,

    #[arg(short = 'c', long = "context")]
    _context: Option<String>,

    #[arg(short = 'H', long = "host")]
    _host: Option<String>,

    #[arg(short = 'l', long = "log-level")]
    _log_level: Option<String>,

    #[arg(long = "tlscacert")]
    _tlscacert: Option<String>,

    #[arg(long = "tlscert")]
    _tlscert: Option<String>,

    #[arg(long = "tlskey")]
    _tlskey: Option<String>,
}

#[derive(Subcommand, Debug)]
#[command(disable_help_subcommand = true)]
enum DockerCommand {
    Pull(PullArgs),
    Run(RunArgs),
    Create(CreateArgs),
}

/// `docker pull` arguments.
///
/// Note: `-a` here is `--all-tags` (boolean), unlike in `run`/`create`
/// where `-a` is `--attach` (value-consuming). Clap resolves this
/// per-subcommand automatically.
#[derive(Args, Debug)]
struct PullArgs {
    // Boolean flags
    #[arg(short = 'a', long = "all-tags")]
    _all_tags: bool,

    #[arg(long = "disable-content-trust")]
    _disable_content_trust: bool,

    #[arg(short = 'q', long = "quiet")]
    _quiet: bool,

    // Value-consuming flags
    #[arg(long = "platform")]
    _platform: Option<String>,

    /// The image reference (first positional argument).
    image: Option<String>,
}

/// Flags shared between `docker run` and `docker create`.
#[derive(Args, Debug)]
struct CommonRunCreateFlags {
    // Boolean flags — all must be declared so clap handles `-dit` correctly.
    #[arg(short = 'd', long = "detach")]
    _detach: bool,

    #[arg(long = "disable-content-trust")]
    _disable_content_trust: bool,

    #[arg(short = 'i', long = "interactive")]
    _interactive: bool,

    #[arg(long = "init")]
    _init: bool,

    #[arg(long = "no-healthcheck")]
    _no_healthcheck: bool,

    #[arg(long = "oom-kill-disable")]
    _oom_kill_disable: bool,

    #[arg(short = 'P', long = "publish-all")]
    _publish_all: bool,

    #[arg(long = "privileged")]
    _privileged: bool,

    #[arg(long = "read-only")]
    _read_only: bool,

    #[arg(long = "rm")]
    _rm: bool,

    #[arg(long = "sig-proxy")]
    _sig_proxy: bool,

    #[arg(short = 't', long = "tty")]
    _tty: bool,

    // Value-consuming flags (short)
    #[arg(short = 'a', long = "attach", action = clap::ArgAction::Append)]
    _attach: Vec<String>,

    #[arg(short = 'e', long = "env", action = clap::ArgAction::Append)]
    _env: Vec<String>,

    #[arg(short = 'l', long = "label", action = clap::ArgAction::Append)]
    _label: Vec<String>,

    #[arg(short = 'p', long = "publish", action = clap::ArgAction::Append)]
    _publish: Vec<String>,

    #[arg(short = 'v', long = "volume", action = clap::ArgAction::Append)]
    _volume: Vec<String>,

    #[arg(short = 'w', long = "workdir")]
    _workdir: Option<String>,

    #[arg(short = 'u', long = "user")]
    _user: Option<String>,

    #[arg(short = 'h', long = "hostname")]
    _hostname: Option<String>,

    #[arg(short = 'm', long = "memory")]
    _memory: Option<String>,

    // Value-consuming flags (long only)
    #[arg(long = "name")]
    _name: Option<String>,

    #[arg(long = "network", visible_alias = "net")]
    _network: Option<String>,

    #[arg(long = "pid")]
    _pid: Option<String>,

    #[arg(long = "ipc")]
    _ipc: Option<String>,

    #[arg(long = "platform")]
    _platform: Option<String>,

    #[arg(long = "pull")]
    _pull: Option<String>,

    #[arg(long = "restart")]
    _restart: Option<String>,

    #[arg(long = "runtime")]
    _runtime: Option<String>,

    #[arg(long = "entrypoint")]
    _entrypoint: Option<String>,

    #[arg(long = "cgroupns")]
    _cgroupns: Option<String>,

    #[arg(long = "cidfile")]
    _cidfile: Option<String>,

    #[arg(long = "cpus")]
    _cpus: Option<String>,

    #[arg(long = "cpu-shares", short = 'c')]
    _cpu_shares: Option<String>,

    #[arg(long = "cpuset-cpus")]
    _cpuset_cpus: Option<String>,

    #[arg(long = "cpuset-mems")]
    _cpuset_mems: Option<String>,

    #[arg(long = "device", action = clap::ArgAction::Append)]
    _device: Vec<String>,

    #[arg(long = "dns", action = clap::ArgAction::Append)]
    _dns: Vec<String>,

    #[arg(long = "dns-option", action = clap::ArgAction::Append)]
    _dns_option: Vec<String>,

    #[arg(long = "dns-search", action = clap::ArgAction::Append)]
    _dns_search: Vec<String>,

    #[arg(long = "env-file", action = clap::ArgAction::Append)]
    _env_file: Vec<String>,

    #[arg(long = "expose", action = clap::ArgAction::Append)]
    _expose: Vec<String>,

    #[arg(long = "group-add", action = clap::ArgAction::Append)]
    _group_add: Vec<String>,

    #[arg(long = "health-cmd")]
    _health_cmd: Option<String>,

    #[arg(long = "health-interval")]
    _health_interval: Option<String>,

    #[arg(long = "health-retries")]
    _health_retries: Option<String>,

    #[arg(long = "health-start-period")]
    _health_start_period: Option<String>,

    #[arg(long = "health-timeout")]
    _health_timeout: Option<String>,

    #[arg(long = "ip")]
    _ip: Option<String>,

    #[arg(long = "ip6")]
    _ip6: Option<String>,

    #[arg(long = "kernel-memory")]
    _kernel_memory: Option<String>,

    #[arg(long = "link", action = clap::ArgAction::Append)]
    _link: Vec<String>,

    #[arg(long = "log-driver")]
    _log_driver: Option<String>,

    #[arg(long = "log-opt", action = clap::ArgAction::Append)]
    _log_opt: Vec<String>,

    #[arg(long = "mac-address")]
    _mac_address: Option<String>,

    #[arg(long = "memory-reservation")]
    _memory_reservation: Option<String>,

    #[arg(long = "memory-swap")]
    _memory_swap: Option<String>,

    #[arg(long = "mount", action = clap::ArgAction::Append)]
    _mount: Vec<String>,

    #[arg(long = "network-alias", action = clap::ArgAction::Append)]
    _network_alias: Vec<String>,

    #[arg(long = "pids-limit")]
    _pids_limit: Option<String>,

    #[arg(long = "security-opt", action = clap::ArgAction::Append)]
    _security_opt: Vec<String>,

    #[arg(long = "shm-size")]
    _shm_size: Option<String>,

    #[arg(long = "stop-signal")]
    _stop_signal: Option<String>,

    #[arg(long = "stop-timeout")]
    _stop_timeout: Option<String>,

    #[arg(long = "storage-opt", action = clap::ArgAction::Append)]
    _storage_opt: Vec<String>,

    #[arg(long = "sysctl", action = clap::ArgAction::Append)]
    _sysctl: Vec<String>,

    #[arg(long = "tmpfs", action = clap::ArgAction::Append)]
    _tmpfs: Vec<String>,

    #[arg(long = "ulimit", action = clap::ArgAction::Append)]
    _ulimit: Vec<String>,

    #[arg(long = "uts")]
    _uts: Option<String>,

    #[arg(long = "userns")]
    _userns: Option<String>,

    #[arg(long = "volume-driver")]
    _volume_driver: Option<String>,

    #[arg(long = "volumes-from", action = clap::ArgAction::Append)]
    _volumes_from: Vec<String>,
}

/// `docker run` arguments.
#[derive(Args, Debug)]
struct RunArgs {
    #[command(flatten)]
    _common: CommonRunCreateFlags,

    /// The image reference (first positional argument).
    image: Option<String>,

    /// Trailing command and arguments after the image.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    _command: Vec<String>,
}

/// `docker create` arguments. Same shape as `run`.
#[derive(Args, Debug)]
struct CreateArgs {
    #[command(flatten)]
    _common: CommonRunCreateFlags,

    /// The image reference (first positional argument).
    image: Option<String>,

    /// Trailing command and arguments after the image.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    _command: Vec<String>,
}

impl DockerCli {
    /// Extract the image reference from Docker command arguments.
    ///
    /// `args` should be the arguments AFTER the command name (`docker`),
    /// as captured by tree-sitter. Returns `None` if the subcommand is
    /// not `pull`/`run`/`create`, or if parsing fails (safe false negative).
    pub(crate) fn parse_image(args: &[&str]) -> Option<String> {
        let cli = DockerCli::try_parse_from(args).ok()?;
        match cli.command {
            DockerCommand::Pull(pull) => pull.image,
            DockerCommand::Run(run) => run.image,
            DockerCommand::Create(create) => create.image,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Basic subcommand routing ---

    #[test]
    fn pull_extracts_image() {
        assert_eq!(
            DockerCli::parse_image(&["pull", "ubuntu"]),
            Some("ubuntu".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["pull", "ubuntu:latest"]),
            Some("ubuntu:latest".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["pull", "ubuntu:22.04"]),
            Some("ubuntu:22.04".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["pull", "ubuntu@sha256:abcdef1234567890"]),
            Some("ubuntu@sha256:abcdef1234567890".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["pull", "ghcr.io/org/image:tag"]),
            Some("ghcr.io/org/image:tag".into())
        );
    }

    #[test]
    fn run_extracts_image() {
        assert_eq!(
            DockerCli::parse_image(&["run", "ubuntu"]),
            Some("ubuntu".into())
        );
    }

    #[test]
    fn create_extracts_image() {
        assert_eq!(
            DockerCli::parse_image(&["create", "--name", "myapp", "node:20"]),
            Some("node:20".into())
        );
    }

    #[test]
    fn unknown_subcommands_return_none() {
        assert_eq!(DockerCli::parse_image(&["build", "."]), None);
        assert_eq!(DockerCli::parse_image(&["push", "myimage"]), None);
        assert_eq!(DockerCli::parse_image(&["images"]), None);
    }

    // --- Combined short flags ---

    #[test]
    fn combined_short_flags() {
        assert_eq!(
            DockerCli::parse_image(&["run", "-dit", "ubuntu:22.04"]),
            Some("ubuntu:22.04".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["run", "-it", "alpine"]),
            Some("alpine".into())
        );
    }

    // --- Value-consuming flags ---

    #[test]
    fn value_consuming_short_flags() {
        assert_eq!(
            DockerCli::parse_image(&["run", "-e", "FOO=bar", "ubuntu"]),
            Some("ubuntu".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["run", "-v", "/a:/b", "ubuntu"]),
            Some("ubuntu".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["run", "-p", "8080:80", "nginx"]),
            Some("nginx".into())
        );
    }

    #[test]
    fn value_consuming_long_flags() {
        assert_eq!(
            DockerCli::parse_image(&["run", "--name", "foo", "ubuntu"]),
            Some("ubuntu".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["run", "--network", "host", "ubuntu"]),
            Some("ubuntu".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["run", "--restart", "always", "nginx"]),
            Some("nginx".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["run", "--pid", "host", "alpine"]),
            Some("alpine".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["run", "--ipc", "host", "redis"]),
            Some("redis".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["run", "--platform", "linux/amd64", "ubuntu"]),
            Some("ubuntu".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["run", "--pull", "always", "ubuntu"]),
            Some("ubuntu".into())
        );
    }

    // --- --flag=value syntax ---

    #[test]
    fn flag_equals_value_syntax() {
        assert_eq!(
            DockerCli::parse_image(&["run", "--name=mycontainer", "--rm", "postgres:15"]),
            Some("postgres:15".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["pull", "--platform=linux/arm64", "nginx:latest"]),
            Some("nginx:latest".into())
        );
    }

    // --- Embedded short flag values ---

    #[test]
    fn embedded_short_flag_value() {
        // -eFOO=bar is a single token: -e with value FOO=bar
        assert_eq!(
            DockerCli::parse_image(&["run", "-eFOO=bar", "ubuntu"]),
            Some("ubuntu".into())
        );
    }

    // --- -a ambiguity ---

    #[test]
    fn a_flag_is_boolean_in_pull() {
        // -a is --all-tags in pull (boolean), so "ubuntu" is the image
        assert_eq!(
            DockerCli::parse_image(&["pull", "-a", "ubuntu"]),
            Some("ubuntu".into())
        );
    }

    #[test]
    fn a_flag_consumes_value_in_run() {
        // -a is --attach in run (value-consuming), so STDERR is the value,
        // ubuntu is the image
        assert_eq!(
            DockerCli::parse_image(&["run", "-a", "STDERR", "ubuntu"]),
            Some("ubuntu".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["run", "--attach", "STDOUT", "alpine"]),
            Some("alpine".into())
        );
    }

    // --- Global flags ---

    #[test]
    fn global_value_consuming_flags() {
        assert_eq!(
            DockerCli::parse_image(&["--context", "foo", "run", "alpine"]),
            Some("alpine".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["--log-level=debug", "pull", "nginx:latest"]),
            Some("nginx:latest".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["--host", "tcp://localhost:2375", "run", "-d", "redis:7"]),
            Some("redis:7".into())
        );
    }

    #[test]
    fn global_boolean_flags() {
        assert_eq!(
            DockerCli::parse_image(&["--debug", "pull", "ubuntu"]),
            Some("ubuntu".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["-D", "--tls", "run", "nginx"]),
            Some("nginx".into())
        );
        assert_eq!(
            DockerCli::parse_image(&["--tlsverify", "pull", "alpine:3.18"]),
            Some("alpine:3.18".into())
        );
    }

    // --- Complex real-world patterns ---

    #[test]
    fn run_with_many_flags() {
        assert_eq!(
            DockerCli::parse_image(&[
                "run",
                "-d",
                "--rm",
                "-v",
                "/tmp:/tmp",
                "-e",
                "FOO=bar",
                "--name",
                "mycontainer",
                "postgres:15",
            ]),
            Some("postgres:15".into())
        );
    }

    #[test]
    fn run_boolean_flags_dont_consume_next() {
        assert_eq!(
            DockerCli::parse_image(&["run", "-d", "--rm", "nginx:latest"]),
            Some("nginx:latest".into())
        );
    }

    #[test]
    fn pull_with_platform() {
        assert_eq!(
            DockerCli::parse_image(&["pull", "--platform", "linux/amd64", "ubuntu"]),
            Some("ubuntu".into())
        );
    }

    // --- Net alias ---

    #[test]
    fn net_alias_for_network() {
        assert_eq!(
            DockerCli::parse_image(&["run", "--net", "bridge", "nginx"]),
            Some("nginx".into())
        );
    }

    // --- Edge cases ---

    #[test]
    fn empty_args_returns_none() {
        assert_eq!(DockerCli::parse_image(&[]), None);
    }

    #[test]
    fn only_subcommand_no_image() {
        assert_eq!(DockerCli::parse_image(&["pull"]), None);
        assert_eq!(DockerCli::parse_image(&["run"]), None);
    }

    #[test]
    fn global_flags_mixed_with_boolean_and_value() {
        assert_eq!(
            DockerCli::parse_image(&[
                "--debug",
                "--host",
                "tcp://localhost:2375",
                "run",
                "-d",
                "redis:7",
            ]),
            Some("redis:7".into())
        );
    }

    #[test]
    fn trailing_command_after_image_in_run() {
        assert_eq!(
            DockerCli::parse_image(&["run", "-it", "ubuntu", "bash", "-c", "echo hello"]),
            Some("ubuntu".into())
        );
    }

    #[test]
    fn trailing_command_after_image_in_create() {
        assert_eq!(
            DockerCli::parse_image(&["create", "alpine", "sleep", "3600"]),
            Some("alpine".into())
        );
    }
}
