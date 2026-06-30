/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  OSKeyStore: "resource://gre/modules/OSKeyStore.sys.mjs",
});

/**
 * On-disk persistence of the Felt bearer token for Firefox Enterprise crash
 * uploads.
 *
 * Crash reports and crash pings are uploaded out-of-process (by the native
 * crashreporter client and the crashreporterNetworkBackend background task),
 * which run in fresh processes that have no in-memory Felt token. This store
 * lets those processes read (and, for the background task, refresh) the token.
 *
 * The file holds the access token, its expiry, the console URL and the refresh
 * token. The refresh token is encrypted with the OS key store so it is not
 * readable from the file alone; the rest is plaintext so the native client
 * (which has no NSS/OS key store access) can still attach a still-valid access
 * token on a best-effort basis.
 */
export const EnterpriseCrashToken = {
  /**
   * Absolute path to the token file, co-located with the other crash data
   * under UAppData/Crash Reports (created with 0700 permissions).
   *
   * @type {string}
   */
  TOKEN_FILE_PATH: PathUtils.join(
    Services.dirsvc.get("UAppData", Ci.nsIFile).path,
    "Crash Reports",
    "enterprise-crash-token.json"
  ),

  /**
   * Persist the current tokens, encrypting the refresh token at rest.
   *
   * @param {object} tokens
   * @param {string} tokens.accessToken
   * @param {string} tokens.refreshToken
   * @param {number} tokens.expiresAt    Unix timestamp in seconds (UTC).
   * @param {string} tokens.consoleUrl
   */
  async write({ accessToken, refreshToken, expiresAt, consoleUrl }) {
    const refreshTokenEnc = refreshToken
      ? await lazy.OSKeyStore.encrypt(refreshToken)
      : "";
    await IOUtils.makeDirectory(PathUtils.parent(this.TOKEN_FILE_PATH), {
      permissions: 0o700,
    });
    await IOUtils.writeJSON(this.TOKEN_FILE_PATH, {
      access_token: accessToken ?? "",
      expires_at: expiresAt ?? 0,
      console_url: consoleUrl ?? "",
      refresh_token_enc: refreshTokenEnc,
    });
  },

  /**
   * Read the persisted tokens and decrypt the refresh token.
   *
   * @returns {Promise<?object>} `{ accessToken, refreshToken, expiresAt,
   *   consoleUrl }`, or null if the file does not exist.
   */
  async read() {
    let data;
    try {
      data = await IOUtils.readJSON(this.TOKEN_FILE_PATH);
    } catch (e) {
      if (DOMException.isInstance(e) && e.name === "NotFoundError") {
        return null;
      }
      throw e;
    }
    let refreshToken = data.refresh_token_enc
      ? await lazy.OSKeyStore.decrypt(
          data.refresh_token_enc,
          "EnterpriseCrashToken"
        )
      : "";
    return {
      accessToken: data.access_token ?? "",
      refreshToken,
      expiresAt: data.expires_at ?? 0,
      consoleUrl: data.console_url ?? "",
    };
  },

  /**
   * Delete the token file. Called whenever Felt tokens are cleared.
   */
  async clear() {
    await IOUtils.remove(this.TOKEN_FILE_PATH, { ignoreAbsent: true });
  },
};
