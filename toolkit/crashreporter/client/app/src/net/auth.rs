/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Best-effort Felt bearer token for authenticating enterprise crash uploads.
//!
//! In Firefox Enterprise, crash reports and crash pings are uploaded to the
//! admin console, which requires the same bearer token used for other console
//! communication. Felt persists the token to disk (see
//! `toolkit/crashreporter/EnterpriseCrashToken.sys.mjs`) so out-of-process
//! uploads can read it.
//!
//! This native reader is best-effort: unlike the `crashreporterNetworkBackend`
//! background task (which is the preferred upload path), the crash reporter
//! client has no NSS / OS key store access and so cannot decrypt the refresh
//! token or refresh an expired access token. It therefore attaches the access
//! token only when it is still valid, and otherwise sends the upload
//! unauthenticated (to be retried later by an authenticated session).

use std::path::Path;

/// File name of the token store, located in the crash reports data directory.
const TOKEN_FILE_NAME: &str = "enterprise-crash-token.json";

/// Refresh skew, matching Felt's `TOKEN_EXPIRY_SKEW`
/// (`toolkit/components/felt/rust/src/utils.rs`).
const TOKEN_EXPIRY_SKEW: i64 = 5 * 60;

#[derive(serde::Deserialize)]
struct PersistedToken {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    expires_at: i64,
}

/// Read a still-valid persisted access token and return an
/// `Authorization: Bearer` header for it, or `None` if there is no token, it is
/// expired, or the file cannot be read/parsed.
pub fn enterprise_authorization_header(data_dir: Option<&Path>) -> Option<(String, String)> {
    let path = data_dir?.join(TOKEN_FILE_NAME);
    let contents = match crate::std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            log::debug!("no enterprise crash token available ({e})");
            return None;
        }
    };
    let token: PersistedToken = match serde_json::from_str(&contents) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("failed to parse enterprise crash token: {e}");
            return None;
        }
    };
    if token.access_token.is_empty() {
        return None;
    }
    let now = ::time::OffsetDateTime::from(crate::std::time::SystemTime::now()).unix_timestamp();
    if token.expires_at - TOKEN_EXPIRY_SKEW < now {
        log::info!("enterprise crash token is expired; sending upload unauthenticated");
        return None;
    }
    Some((
        "Authorization".to_owned(),
        format!("Bearer {}", token.access_token),
    ))
}

/// Convenience wrapper returning the header(s) as a `Vec` suitable for passing
/// to `RequestBuilder`.
pub fn enterprise_authorization_headers(data_dir: Option<&Path>) -> Vec<(String, String)> {
    enterprise_authorization_header(data_dir)
        .into_iter()
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::std::{
        fs::{MockFS, MockFiles},
        mock,
        time::MockCurrentTime,
    };

    const NOW: u64 = 1_000_000;

    fn now_system_time() -> ::std::time::SystemTime {
        ::std::time::SystemTime::UNIX_EPOCH + ::std::time::Duration::from_secs(NOW)
    }

    fn run_with_token(contents: Option<&str>) -> Option<(String, String)> {
        let files = MockFiles::new();
        files.add_dir("data_dir");
        if let Some(contents) = contents {
            files.add_file("data_dir/enterprise-crash-token.json", contents);
        }
        mock::builder()
            .set(MockFS, files)
            .set(MockCurrentTime, now_system_time())
            .run(|| enterprise_authorization_header(Some(Path::new("data_dir"))))
    }

    #[test]
    fn valid_token_yields_header() {
        let header = run_with_token(Some(&format!(
            r#"{{"access_token":"abc","expires_at":{},"console_url":"https://c.example.com"}}"#,
            NOW + 1000
        )))
        .expect("expected an authorization header");
        assert_eq!(header.0, "Authorization");
        assert_eq!(header.1, "Bearer abc");
    }

    #[test]
    fn expired_token_yields_none() {
        // expires_at within the skew window counts as expired.
        let header = run_with_token(Some(&format!(
            r#"{{"access_token":"abc","expires_at":{}}}"#,
            NOW + 100
        )));
        assert!(header.is_none());
    }

    #[test]
    fn empty_access_token_yields_none() {
        let header = run_with_token(Some(r#"{"access_token":"","expires_at":99999999999}"#));
        assert!(header.is_none());
    }

    #[test]
    fn missing_file_yields_none() {
        assert!(run_with_token(None).is_none());
    }

    #[test]
    fn no_data_dir_yields_none() {
        assert!(enterprise_authorization_header(None).is_none());
    }
}
