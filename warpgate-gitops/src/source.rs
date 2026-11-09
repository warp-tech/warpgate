//! Reads a provider's files from where they live: a directory on this node, or
//! a git repository. Blocking; a server calls it off the async runtime.

use std::io;
use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;

use gix::credentials::helper::Action;
use gix::credentials::protocol::Outcome;
use gix::remote::fetch::Shallow;
use gix::sec::identity::Account;
use sha2::{Digest, Sha256};
use warpgate_common::Secret;
use warpgate_db_entities::Parameters::{GitopsGitSource, GitopsSource};

use crate::read_files;

/// The files as one revision of the source has them
#[derive(Debug)]
pub struct Checkout {
    /// The commit, or for a directory a hash of its files
    pub revision: String,
    /// Paths relative to the source's root, as [`crate::validate::check_files`] takes them
    pub files: Vec<(PathBuf, String)>,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("`{0}` is not a relative path inside the repository")]
    PathOutside(String),
    #[error("no .yaml or .yml files found")]
    Empty,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("git: {0}")]
    Git(String),
}

/// `password` is the resolved credential of a git source with a username.
/// Setting `interrupt` makes a running fetch or checkout stop at its next
/// check.
pub fn checkout(
    source: &GitopsSource,
    password: Option<Secret<String>>,
    interrupt: &AtomicBool,
) -> Result<Checkout, SourceError> {
    match source {
        GitopsSource::Directory(dir) => {
            let files = read_relative(Path::new(&dir.path))?;
            Ok(Checkout {
                revision: content_hash(&files),
                files,
            })
        }
        GitopsSource::Git(git) => {
            let inner = inner_path(git.path.as_deref())?;
            let worktree = tempfile::tempdir()?;
            let revision = clone(git, &git.reference, password, worktree.path(), interrupt)?;
            Ok(Checkout {
                revision,
                files: read_relative(&worktree.path().join(inner))?,
            })
        }
    }
}

/// Files sent in a request rather than fetched: the documents of one YAML
/// stream, with a hash of it for revision
pub fn checkout_text(yaml: String) -> Checkout {
    let files = vec![(PathBuf::from("request.yaml"), yaml)];
    Checkout {
        revision: content_hash(&files),
        files,
    }
}

/// A shallow clone of `reference` into `into`, returning the commit it checked out
fn clone(
    git: &GitopsGitSource,
    reference: &str,
    password: Option<Secret<String>>,
    into: &Path,
    interrupt: &AtomicBool,
) -> Result<String, SourceError> {
    let account = git.username.clone().map(|username| Account {
        username,
        password: password
            .map(|password| password.expose_secret().clone())
            .unwrap_or_default(),
        oauth_refresh_token: None,
    });

    // Isolated: the server account's git config (URL rewrites, proxies,
    // credential helpers) has no say
    let fetch = gix::clone::PrepareFetch::new(
        git.url.as_str(),
        into,
        gix::create::Kind::WithWorktree,
        gix::create::Options::default(),
        gix::open::Options::isolated(),
    )
    .map_err(git_error)?
    // `read_files` follows symlinks, which a repository could point at
    // the server's own files; check them out as plain files instead
    .with_in_memory_config_overrides(["core.symlinks=false"])
    .with_shallow(Shallow::DepthAtRemote(NonZeroU32::MIN))
    // Answers every credential request, so nothing ever prompts
    .configure_connection(move |connection| {
        let account = account.clone();
        connection.set_credentials(move |action| {
            Ok(match (action, &account) {
                (Action::Get(context), Some(account)) => Some(Outcome {
                    identity: account.clone(),
                    next: context.into(),
                }),
                _ => None,
            })
        });
        Ok(())
    });
    let mut fetch = if is_object_id(reference) || reference.starts_with("refs/") {
        fetch.with_revision(Some(reference))
    } else {
        fetch.with_ref_name(Some(reference))
    }
    .map_err(git_error)?;

    let (mut checkout, _) = fetch
        .fetch_then_checkout(gix::progress::Discard, interrupt)
        .map_err(git_error)?;
    let (repo, _) = checkout
        .main_worktree(gix::progress::Discard, interrupt)
        .map_err(git_error)?;
    Ok(repo.head_id().map_err(git_error)?.to_string())
}

fn git_error(error: impl std::fmt::Display) -> SourceError {
    SourceError::Git(error.to_string())
}

fn is_object_id(reference: &str) -> bool {
    matches!(reference.len(), 40 | 64) && reference.bytes().all(|b| b.is_ascii_hexdigit())
}

fn inner_path(path: Option<&str>) -> Result<PathBuf, SourceError> {
    let path = PathBuf::from(path.unwrap_or_default());
    if path
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
    {
        Ok(path)
    } else {
        Err(SourceError::PathOutside(path.display().to_string()))
    }
}

fn read_relative(root: &Path) -> Result<Vec<(PathBuf, String)>, SourceError> {
    let files: Vec<_> = read_files(&[root.to_owned()])?
        .into_iter()
        .map(|(path, contents)| {
            let relative = path
                .strip_prefix(root)
                .ok()
                .filter(|relative| !relative.as_os_str().is_empty())
                .map(Path::to_owned);
            (relative.unwrap_or(path), contents)
        })
        .collect();
    if files.is_empty() {
        return Err(SourceError::Empty);
    }
    Ok(files)
}

fn content_hash(files: &[(PathBuf, String)]) -> String {
    let mut hash = Sha256::new();
    for (path, contents) in files {
        for part in [path.to_string_lossy().as_bytes(), contents.as_bytes()] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part);
        }
    }
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use warpgate_common::MaybeSecretRef;
    use warpgate_db_entities::Parameters::GitopsDirectorySource;

    use super::*;

    const ROLE: &str = "apiVersion: warpgate/v1\nkind: Role\nmetadata: {name: dba}\nspec: {}\n";
    static NEVER: AtomicBool = AtomicBool::new(false);

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn commit(repo: &Path, file: &str, contents: &str) -> String {
        let path = repo.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
        git(repo, &["add", "."]);
        git(repo, &["commit", "-qm", file]);
        git(repo, &["rev-parse", "HEAD"])
    }

    fn source(repo: &Path, reference: &str, path: Option<&str>) -> GitopsSource {
        GitopsSource::Git(GitopsGitSource {
            url: format!("file://{}", repo.display()),
            reference: reference.into(),
            username: None,
            password: MaybeSecretRef::default(),
            path: path.map(Into::into),
        })
    }

    #[test]
    fn a_directory_revision_follows_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("roles.yaml"), ROLE).unwrap();
        let source = GitopsSource::Directory(GitopsDirectorySource {
            path: dir.path().display().to_string(),
        });

        let first = checkout(&source, None, &NEVER).unwrap();
        assert_eq!(first.files, [(PathBuf::from("roles.yaml"), ROLE.into())]);
        assert_eq!(
            first.revision,
            checkout(&source, None, &NEVER).unwrap().revision
        );

        fs::write(dir.path().join("roles.yaml"), format!("{ROLE}# edited\n")).unwrap();
        assert_ne!(
            first.revision,
            checkout(&source, None, &NEVER).unwrap().revision
        );
    }

    #[test]
    fn checks_out_a_branch_or_a_commit_inside_the_path() {
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "-q"]);
        let first = commit(repo.path(), "warpgate/roles.yaml", ROLE);
        commit(repo.path(), "README.yaml", "not: a resource\n");
        let second = commit(repo.path(), "warpgate/more.yml", ROLE);

        let head = checkout(&source(repo.path(), "main", Some("warpgate")), None, &NEVER).unwrap();
        assert_eq!(head.revision, second);
        assert_eq!(
            head.files
                .iter()
                .map(|(p, _)| p.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["more.yml", "roles.yaml"]
        );

        let pinned =
            checkout(&source(repo.path(), &first, Some("warpgate")), None, &NEVER).unwrap();
        assert_eq!(pinned.revision, first);
        assert_eq!(pinned.files.len(), 1);
    }

    #[test]
    fn symlinks_are_not_followed_and_paths_stay_inside() {
        let repo = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.yaml"), "password: hunter2\n").unwrap();
        git(repo.path(), &["init", "-q"]);
        std::os::unix::fs::symlink(
            outside.path().join("secret.yaml"),
            repo.path().join("link.yaml"),
        )
        .unwrap();
        commit(repo.path(), "roles.yaml", ROLE);

        let files = checkout(&source(repo.path(), "main", None), None, &NEVER)
            .unwrap()
            .files;
        let (_, link) = files
            .iter()
            .find(|(path, _)| path == Path::new("link.yaml"))
            .unwrap();
        assert_eq!(
            link,
            &outside.path().join("secret.yaml").display().to_string()
        );

        assert!(matches!(
            checkout(&source(repo.path(), "main", Some("../x")), None, &NEVER),
            Err(SourceError::PathOutside(_))
        ));
    }
}
