//! Repository content listing and metadata lookups.
//!
//! Builders on [`HFRepository`] for inspecting what's in a repo without downloading file
//! contents:
//!
//! - [`HFRepository::list_tree`] — paginated stream of [`RepoTreeEntry`] (files and directories), optionally recursive
//!   and prefix-filtered.
//! - [`HFRepository::get_paths_info`] — batched lookup of metadata for a known set of paths.
//! - [`HFRepository::get_file_metadata`] — HEAD-based metadata for one file (size, ETag, commit hash, xet hash).

use bon::bon;
use futures::stream::Stream;
use reqwest::Url;

use super::files::{extract_commit_hash, extract_etag, extract_file_size, extract_xet_hash};
use super::{FileMetadataInfo, HFRepository, RepoTreeEntry, RepoType};
use crate::client::encode_ref;
use crate::error::{HFError, HFResult};
use crate::{constants, retry};

#[bon]
impl<T: RepoType> HFRepository<T> {
    /// Stream file and directory entries in the repository tree.
    ///
    /// Returns `HFResult<impl Stream<Item = HFResult<RepoTreeEntry>>>`.
    ///
    /// Use [`HFRepository::get_paths_info`] when you already know the exact paths
    /// you want to inspect.
    ///
    /// # Parameters
    ///
    /// - `revision`: Git revision to list. Defaults to the main branch.
    /// - `path_in_repo`: repository-relative subdirectory to list. Defaults to the repo root. Leading, trailing, and
    ///   consecutive `/` separators are ignored; path segments are URL-encoded automatically.
    /// - `recursive` (default `false`): traverse subdirectories.
    /// - `expand` (default `false`): include per-file metadata such as size, LFS info, and last-commit summaries.
    /// - `limit`: cap the total number of entries yielded.
    #[builder(finish_fn = send, derive(Debug, Clone))]
    pub fn list_tree(
        &self,
        /// Git revision to list. Defaults to the main branch.
        #[builder(into)]
        revision: Option<String>,
        /// Repository-relative subdirectory to list. Defaults to the repo root.
        /// Leading, trailing, and consecutive `/` separators are ignored;
        /// path segments are URL-encoded automatically.
        #[builder(into)]
        path_in_repo: Option<String>,
        /// Traverse subdirectories.
        #[builder(default)]
        recursive: bool,
        /// Include per-file metadata such as size, LFS info, and last-commit summaries.
        #[builder(default)]
        expand: bool,
        /// Cap the total number of entries yielded.
        limit: Option<usize>,
    ) -> HFResult<impl Stream<Item = HFResult<RepoTreeEntry>> + '_> {
        let revision = revision.as_deref().unwrap_or(constants::DEFAULT_REVISION);
        let url_str = format!(
            "{}/tree/{}",
            self.hf_client
                .api_url(self.repo_type.plural(), &self.repo_path()),
            encode_ref(revision)
        );
        let mut url = Url::parse(&url_str)?;
        if let Some(path) = path_in_repo.as_deref() {
            crate::client::append_path_segments(&mut url, path)?;
        }

        let mut query: Vec<(String, String)> = Vec::new();
        if recursive {
            query.push(("recursive".into(), "true".into()));
        }
        if expand {
            query.push(("expand".into(), "true".into()));
        }

        Ok(self.hf_client.paginate(url, query, limit))
    }

    /// Get info about specific paths in a repository.
    ///
    /// Prefer this over [`HFRepository::list_tree`] when you already know the
    /// small set of paths you want to inspect.
    ///
    /// Endpoint: `POST /api/{repo_type}s/{repo_id}/paths-info/{revision}`.
    ///
    /// # Parameters
    ///
    /// - `paths` (required): paths in the repository to fetch info for.
    /// - `revision`: Git revision. Defaults to the main branch.
    #[builder(finish_fn = send, derive(Debug, Clone))]
    pub async fn get_paths_info(
        &self,
        /// Paths in the repository to fetch info for.
        paths: Vec<String>,
        /// Git revision. Defaults to the main branch.
        #[builder(into)]
        revision: Option<String>,
    ) -> HFResult<Vec<RepoTreeEntry>> {
        let revision = revision.as_deref().unwrap_or(constants::DEFAULT_REVISION);
        let url = format!(
            "{}/paths-info/{}",
            self.hf_client
                .api_url(self.repo_type.plural(), &self.repo_path()),
            encode_ref(revision)
        );

        let body = serde_json::json!({ "paths": paths });

        let headers = self.hf_client.auth_headers();
        let response = retry::retry(self.hf_client.retry_config(), || {
            self.hf_client
                .http_client()
                .post(&url)
                .headers(headers.clone())
                .json(&body)
                .send()
        })
        .await?;

        let repo_path = self.repo_path();
        let response = self
            .hf_client
            .check_response(
                response,
                Some(&repo_path),
                crate::error::NotFoundContext::Entry {
                    path: paths.join(", "),
                },
            )
            .await?;
        Ok(response.json().await?)
    }

    /// Fetch metadata for a single file via a HEAD request on its resolve URL.
    ///
    /// Returns the resolved commit hash, ETag, file size, and (if the file is Xet-backed)
    /// the Xet content hash — without downloading the file contents.
    ///
    /// Endpoint: `HEAD {endpoint}/{prefix}{repo_id}/resolve/{revision}/{filepath}`.
    ///
    /// A redirect to another host, such as the CDN `302` from `/resolve/`, is not
    /// followed: that response carries `X-Repo-Commit`, `ETag`, and `X-Linked-Size`,
    /// while the CDN `200` does not. A relative or same-host redirect, such as the
    /// `307` to `/api/resolve-cache/`, is followed so the final response can supply
    /// the size. `location` is the `Location` header when the redirect is not
    /// followed, and the final request URL otherwise.
    ///
    /// # Parameters
    ///
    /// - `filepath` (required): path of the file to inspect within the repository.
    /// - `revision`: Git revision. Defaults to the main branch.
    #[builder(finish_fn = send, derive(Debug, Clone))]
    pub async fn get_file_metadata(
        &self,
        /// Path of the file to inspect within the repository.
        #[builder(into)]
        filepath: String,
        /// Git revision. Defaults to the main branch.
        revision: Option<&str>,
    ) -> HFResult<FileMetadataInfo> {
        let filename = filepath;
        let revision = revision.unwrap_or(constants::DEFAULT_REVISION);
        let repo_path = self.repo_path();
        let url = self.hf_client.download_url(
            self.repo_type.url_prefix(),
            &repo_path,
            revision,
            &filename,
        )?;

        let response = head_file_metadata(self, &url, &filename).await?;

        let etag = extract_etag(&response).ok_or_else(|| {
            HFError::malformed_response_at(
                format!("missing ETag header for {filename}"),
                url.to_string(),
            )
        })?;
        let commit_hash = extract_commit_hash(&response).ok_or_else(|| {
            HFError::malformed_response_at(
                format!("missing X-Repo-Commit header for {filename}"),
                url.to_string(),
            )
        })?;
        let xet_hash = extract_xet_hash(&response);
        let file_size = extract_file_size(&response).unwrap_or_else(|| {
            tracing::warn!(
                file = %filename,
                "missing or invalid Content-Length/X-Linked-Size header, defaulting file size to 0"
            );
            0
        });
        let location = metadata_location(&response);

        Ok(FileMetadataInfo {
            filename,
            etag,
            commit_hash,
            xet_hash,
            file_size,
            location,
        })
    }
}

const MAX_SAME_HUB_REDIRECTS: usize = 8;

async fn head_file_metadata<T: RepoType>(
    repo: &HFRepository<T>,
    start: &str,
    filename: &str,
) -> HFResult<reqwest::Response> {
    let mut current = Url::parse(start)?;
    let headers = repo.hf_client.auth_headers();
    let repo_path = repo.repo_path();
    for _ in 0..MAX_SAME_HUB_REDIRECTS {
        let response = retry::retry(repo.hf_client.retry_config(), || {
            repo.hf_client
                .no_redirect_client()
                .head(current.clone())
                .headers(headers.clone())
                .send()
        })
        .await?;
        if response.status().is_success() {
            return Ok(response);
        }
        if let Some(next) = same_hub_redirect(&current, &response) {
            current = next;
            continue;
        }
        if response.status().is_redirection() {
            return Ok(response);
        }
        return repo
            .hf_client
            .check_response(
                response,
                Some(&repo_path),
                crate::error::NotFoundContext::Entry {
                    path: filename.to_string(),
                },
            )
            .await;
    }
    Err(HFError::malformed_response_at(
        format!("too many same-hub redirects for {filename}"),
        start,
    ))
}

fn same_hub_redirect(current: &Url, response: &reqwest::Response) -> Option<Url> {
    if !response.status().is_redirection() {
        return None;
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())?;
    if !crate::client::location_stays_on_hub(current, location) {
        return None;
    }
    current.join(location).ok()
}

fn metadata_location(response: &reqwest::Response) -> Option<String> {
    if response.status().is_redirection() {
        return response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
    }
    Some(response.url().to_string())
}

#[cfg(feature = "blocking")]
use futures::stream::StreamExt as _;

#[cfg(feature = "blocking")]
#[bon]
impl<T: RepoType> crate::blocking::HFRepositorySync<T> {
    /// Blocking counterpart of [`HFRepository::list_tree`]. Returns the collected stream as a
    /// `Vec<RepoTreeEntry>`. See the async method for parameters and behavior.
    #[builder(finish_fn = send, derive(Debug, Clone))]
    pub fn list_tree(
        &self,
        #[builder(into)] revision: Option<String>,
        #[builder(into)] path_in_repo: Option<String>,
        #[builder(default)] recursive: bool,
        #[builder(default)] expand: bool,
        limit: Option<usize>,
    ) -> HFResult<Vec<RepoTreeEntry>> {
        self.runtime.block_on(async move {
            let stream = self
                .inner
                .list_tree()
                .maybe_revision(revision)
                .maybe_path_in_repo(path_in_repo)
                .recursive(recursive)
                .expand(expand)
                .maybe_limit(limit)
                .send()?;
            futures::pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(item) = stream.next().await {
                items.push(item?);
            }
            Ok(items)
        })
    }

    /// Blocking counterpart of [`HFRepository::get_paths_info`]. See the async method for
    /// parameters and behavior.
    #[builder(finish_fn = send, derive(Debug, Clone))]
    pub fn get_paths_info(
        &self,
        paths: Vec<String>,
        #[builder(into)] revision: Option<String>,
    ) -> HFResult<Vec<RepoTreeEntry>> {
        self.runtime.block_on(
            self.inner
                .get_paths_info()
                .paths(paths)
                .maybe_revision(revision)
                .send(),
        )
    }

    /// Blocking counterpart of [`HFRepository::get_file_metadata`]. See the async method for
    /// parameters and behavior.
    #[builder(finish_fn = send, derive(Debug, Clone))]
    pub fn get_file_metadata(
        &self,
        #[builder(into)] filepath: String,
        revision: Option<&str>,
    ) -> HFResult<FileMetadataInfo> {
        self.runtime.block_on(
            self.inner
                .get_file_metadata()
                .filepath(filepath)
                .maybe_revision(revision)
                .send(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::HFClientBuilder;

    const COMMIT: &str = "0123456789012345678901234567890123456789";

    async fn serve(
        listener: tokio::net::TcpListener,
        response_for: impl Fn(&str) -> String + Send + Sync + 'static,
    ) {
        let response_for = Arc::new(response_for);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let response_for = Arc::clone(&response_for);
                tokio::spawn(async move {
                    let mut request = vec![0; 4096];
                    let Ok(read) = socket.read(&mut request).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&request[..read]);
                    let path = request.split_whitespace().nth(1).unwrap_or("");
                    let response = response_for(path);
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
    }

    async fn metadata_fixture() -> (String, Arc<AtomicUsize>) {
        let cdn = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cdn_addr = cdn.local_addr().unwrap();
        let cdn_hits = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&cdn_hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = cdn.accept().await else {
                    return;
                };
                hits.fetch_add(1, Ordering::Relaxed);
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });

        let hub = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hub_addr = hub.local_addr().unwrap();
        let cdn_url = format!("http://{cdn_addr}/model.gguf");
        serve(hub, move |path| {
            if path.ends_with("/resolve/main/README.md") {
                "HTTP/1.1 307 Temporary Redirect\r\n\
                 Location: /api/resolve-cache/models/owner/repo/README.md\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n"
                    .to_string()
            } else if path.contains("/resolve-cache/") {
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     ETag: \"readme-etag\"\r\n\
                     X-Repo-Commit: {COMMIT}\r\n\
                     Content-Length: 7576\r\n\
                     Connection: close\r\n\
                     \r\n"
                )
            } else if path.ends_with("/resolve/main/model.gguf") {
                format!(
                    "HTTP/1.1 302 Found\r\n\
                     Location: {cdn_url}\r\n\
                     X-Linked-Etag: \"gguf-etag\"\r\n\
                     X-Repo-Commit: {COMMIT}\r\n\
                     X-Linked-Size: 99\r\n\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\
                     \r\n"
                )
            } else if path.ends_with("/resolve/main/plain.txt") {
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     ETag: \"plain-etag\"\r\n\
                     X-Repo-Commit: {COMMIT}\r\n\
                     Content-Length: 4\r\n\
                     Connection: close\r\n\
                     \r\n"
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            }
        })
        .await;
        (format!("http://{hub_addr}"), cdn_hits)
    }

    #[tokio::test]
    async fn file_metadata_reads_direct_ok_and_both_redirect_shapes() {
        let (endpoint, cdn_hits) = metadata_fixture().await;
        let client = HFClientBuilder::new()
            .endpoint(endpoint.clone())
            .retry_max_attempts(1)
            .build()
            .unwrap();
        let repo = client.model("owner", "repo");

        let plain = repo
            .get_file_metadata()
            .filepath("plain.txt")
            .send()
            .await
            .unwrap();
        assert_eq!(plain.commit_hash, COMMIT);
        assert_eq!(plain.etag, "plain-etag");
        assert_eq!(plain.file_size, 4);
        assert_eq!(
            plain.location.as_deref(),
            Some(format!("{endpoint}/owner/repo/resolve/main/plain.txt").as_str())
        );

        let gguf = repo
            .get_file_metadata()
            .filepath("model.gguf")
            .send()
            .await
            .unwrap();
        assert_eq!(gguf.commit_hash, COMMIT);
        assert_eq!(gguf.etag, "gguf-etag");
        assert_eq!(gguf.file_size, 99);
        assert!(
            gguf.location
                .as_deref()
                .is_some_and(|location| location.ends_with("/model.gguf")),
            "location should be the CDN target, got {:?}",
            gguf.location
        );
        assert_eq!(cdn_hits.load(Ordering::Relaxed), 0);

        let readme = repo
            .get_file_metadata()
            .filepath("README.md")
            .send()
            .await
            .unwrap();
        assert_eq!(readme.commit_hash, COMMIT);
        assert_eq!(readme.etag, "readme-etag");
        assert_eq!(readme.file_size, 7576);
        assert_eq!(
            readme.location.as_deref(),
            Some(format!("{endpoint}/api/resolve-cache/models/owner/repo/README.md").as_str())
        );
    }
}
