//! Reads a provider's files from where they live: a directory on this node, or
//! a git repository. Blocking; a server calls it off the async runtime.

use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::{fs, io};

use data_encoding::HEXLOWER;
use gix::credentials::helper::Action;
use gix::credentials::protocol::Outcome;
use gix::remote::fetch::{Shallow, Tags};
use gix::remote::{Direction, ref_map};
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

/// `password` is a git source's resolved password or token, if it has one.
/// `held` is the result of an earlier call for the same source. If a git
/// source's reference is still at that commit, `held` is returned and
/// nothing is fetched.
/// Setting `interrupt` makes a running fetch or checkout stop at its next
/// check.
pub fn checkout(
    source: &GitopsSource,
    password: Option<Secret<String>>,
    held: Option<Arc<Checkout>>,
    interrupt: &AtomicBool,
) -> Result<Arc<Checkout>, SourceError> {
    match source {
        GitopsSource::Directory(dir) => {
            let files = read_relative(Path::new(&dir.path))?;
            Ok(Arc::new(Checkout {
                revision: content_hash(&files),
                files,
            }))
        }
        GitopsSource::Git(git) => {
            let inner = inner_path(git.path.as_deref())?;
            let account = account(git.username.as_deref(), password);
            let scratch = tempfile::tempdir()?;
            if let Some(held) = held {
                let probe = scratch.path().join("probe");
                fs::create_dir(&probe)?;
                if remote_tip(git, account.as_ref(), &probe)?.as_deref() == Some(&held.revision) {
                    return Ok(held);
                }
            }
            let worktree = scratch.path().join("worktree");
            fs::create_dir(&worktree)?;
            let revision = clone(git, account, &worktree, interrupt)?;
            Ok(Arc::new(Checkout {
                revision,
                files: read_relative(&worktree.join(inner))?,
            }))
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

/// Username sent with a token when the source has none. Hosts that take a
/// token as the password accept any username with it.
const TOKEN_USERNAME: &str = "git";

/// Credentials for the remote. `None` connects anonymously.
fn account(username: Option<&str>, password: Option<Secret<String>>) -> Option<Account> {
    if username.is_none() && password.is_none() {
        return None;
    }
    Some(Account {
        username: username.unwrap_or(TOKEN_USERNAME).to_owned(),
        password: password
            .map(|password| password.expose_secret().clone())
            .unwrap_or_default(),
        oauth_refresh_token: None,
    })
}

/// Answers every credential request, so nothing ever prompts
fn credentials(action: Action, account: Option<&Account>) -> Option<Outcome> {
    match (action, account) {
        (Action::Get(context), Some(account)) => Some(Outcome {
            identity: account.clone(),
            next: context.into(),
        }),
        _ => None,
    }
}

/// The commit that the source's reference points to on the remote, read from
/// the remote's ref list. `None` if the list doesn't identify it, and the
/// caller then clones.
fn remote_tip(
    git: &GitopsGitSource,
    account: Option<&Account>,
    scratch: &Path,
) -> Result<Option<String>, SourceError> {
    let reference = git.reference.as_str();
    // A commit never moves
    if is_object_id(reference) {
        return Ok(Some(reference.to_ascii_lowercase()));
    }

    // gix opens a connection from a repository. This empty one is isolated,
    // like the clone's.
    let repo = gix::ThreadSafeRepository::init_opts(
        scratch,
        gix::create::Kind::Bare,
        gix::create::Options::default(),
        gix::open::Options::isolated(),
    )
    .map_err(git_error)?
    .to_thread_local();
    let remote = repo
        .remote_at(git.url.as_str())
        .map_err(git_error)?
        .with_fetch_tags(Tags::None);
    let mut connection = remote.connect(Direction::Fetch).map_err(git_error)?;
    connection.set_credentials(|action| Ok(credentials(action, account)));
    let wanted = gix::refspec::parse(reference.into(), gix::refspec::parse::Operation::Fetch)
        .map_err(git_error)?
        .to_owned();
    let options = ref_map::Options {
        extra_refspecs: vec![wanted],
        ..Default::default()
    };
    let (refs, _) = connection
        .ref_map(gix::progress::Discard, options)
        .map_err(git_error)?;

    // These are the names a clone tries, in the same order. Any other match
    // gives `None`: resolving to a different ref than the clone does would
    // keep returning the held checkout after the clone's ref moved.
    let names = [
        reference.to_owned(),
        format!("refs/heads/{reference}"),
        format!("refs/tags/{reference}"),
    ];
    let tip = names.iter().find_map(|name| {
        refs.mappings.iter().find(|mapping| {
            mapping
                .remote
                .as_name()
                .is_some_and(|full| full == name.as_str())
        })
    });
    Ok(tip
        .and_then(|mapping| mapping.remote.peeled_id())
        .map(|id| id.to_hex().to_string()))
}

/// Shallow-clones the source's reference into `into`. Returns the commit
/// that was checked out.
fn clone(
    git: &GitopsGitSource,
    account: Option<Account>,
    into: &Path,
    interrupt: &AtomicBool,
) -> Result<String, SourceError> {
    // Isolated, so the server account's git config (URL rewrites, proxies,
    // credential helpers) is ignored
    let fetch = gix::clone::PrepareFetch::new(
        git.url.as_str(),
        into,
        gix::create::Kind::WithWorktree,
        gix::create::Options::default(),
        gix::open::Options::isolated(),
    )
    .map_err(git_error)?
    // `read_files` follows symlinks, and a repository could point one at
    // the server's files. Check them out as plain files.
    .with_in_memory_config_overrides(["core.symlinks=false"])
    .with_shallow(Shallow::DepthAtRemote(NonZeroU32::MIN))
    .configure_connection(move |connection| {
        let account = account.clone();
        connection.set_credentials(move |action| Ok(credentials(action, account.as_ref())));
        Ok(())
    });
    let reference = git.reference.as_str();
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

/// The revision of files that don't come from a commit
pub fn content_hash(files: &[(PathBuf, String)]) -> String {
    let mut hash = Sha256::new();
    for (path, contents) in files {
        for part in [path.to_string_lossy().as_bytes(), contents.as_bytes()] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part);
        }
    }
    HEXLOWER.encode(&hash.finalize())
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
    fn a_token_is_sent_without_a_username() {
        assert!(account(None, None).is_none());

        let named = account(Some("ci"), None).unwrap();
        assert_eq!(
            (named.username.as_str(), named.password.as_str()),
            ("ci", "")
        );

        let token = account(None, Some(Secret::new("token".to_owned()))).unwrap();
        assert_eq!(
            (token.username.as_str(), token.password.as_str()),
            (TOKEN_USERNAME, "token")
        );
    }

    #[test]
    fn a_directory_revision_follows_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("roles.yaml"), ROLE).unwrap();
        let source = GitopsSource::Directory(GitopsDirectorySource {
            path: dir.path().display().to_string(),
        });

        let first = checkout(&source, None, None, &NEVER).unwrap();
        assert_eq!(first.files, [(PathBuf::from("roles.yaml"), ROLE.into())]);
        assert_eq!(
            first.revision,
            checkout(&source, None, None, &NEVER).unwrap().revision
        );

        fs::write(dir.path().join("roles.yaml"), format!("{ROLE}# edited\n")).unwrap();
        assert_ne!(
            first.revision,
            checkout(&source, None, None, &NEVER).unwrap().revision
        );
    }

    #[test]
    fn checks_out_a_branch_or_a_commit_inside_the_path() {
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "-q"]);
        let first = commit(repo.path(), "warpgate/roles.yaml", ROLE);
        commit(repo.path(), "README.yaml", "not: a resource\n");
        let second = commit(repo.path(), "warpgate/more.yml", ROLE);

        let head = checkout(
            &source(repo.path(), "main", Some("warpgate")),
            None,
            None,
            &NEVER,
        )
        .unwrap();
        assert_eq!(head.revision, second);
        assert_eq!(
            head.files
                .iter()
                .map(|(p, _)| p.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["more.yml", "roles.yaml"]
        );

        let pinned = checkout(
            &source(repo.path(), &first, Some("warpgate")),
            None,
            None,
            &NEVER,
        )
        .unwrap();
        assert_eq!(pinned.revision, first);
        assert_eq!(pinned.files.len(), 1);
    }

    #[test]
    fn a_reference_that_has_not_moved_is_not_fetched_again() {
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "-q"]);
        commit(repo.path(), "roles.yaml", ROLE);
        git(repo.path(), &["tag", "v1"]);
        let again = |source: &GitopsSource, held: &Arc<Checkout>| {
            checkout(source, None, Some(held.clone()), &NEVER).unwrap()
        };

        let main = source(repo.path(), "main", None);
        let first = checkout(&main, None, None, &NEVER).unwrap();
        assert!(Arc::ptr_eq(&first, &again(&main, &first)));
        let tag = source(repo.path(), "v1", None);
        assert!(Arc::ptr_eq(&first, &again(&tag, &first)));
        let full = source(repo.path(), "refs/heads/main", None);
        assert!(Arc::ptr_eq(&first, &again(&full, &first)));

        let moved = commit(repo.path(), "more.yaml", ROLE);
        let second = again(&main, &first);
        assert_eq!(second.revision, moved);
        assert_eq!(second.files.len(), 2);
        assert!(Arc::ptr_eq(&first, &again(&tag, &first)));

        // A commit never moves, so the remote isn't asked
        let pinned = source(Path::new("/nowhere"), &first.revision, None);
        assert!(Arc::ptr_eq(&first, &again(&pinned, &first)));
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

        let main = checkout(&source(repo.path(), "main", None), None, None, &NEVER).unwrap();
        let (_, link) = main
            .files
            .iter()
            .find(|(path, _)| path == Path::new("link.yaml"))
            .unwrap();
        assert_eq!(
            link,
            &outside.path().join("secret.yaml").display().to_string()
        );

        assert!(matches!(
            checkout(
                &source(repo.path(), "main", Some("../x")),
                None,
                None,
                &NEVER
            ),
            Err(SourceError::PathOutside(_))
        ));
    }
}
