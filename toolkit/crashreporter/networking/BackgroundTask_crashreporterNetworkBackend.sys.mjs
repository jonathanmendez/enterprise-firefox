/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import { EXIT_CODE } from "resource://gre/modules/BackgroundTasksManager.sys.mjs";

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  EnterpriseCrashToken: "resource://gre/modules/EnterpriseCrashToken.sys.mjs",
  ConsoleClient: "resource://gre/modules/enterprise/ConsoleClient.sys.mjs",
});

// Matches Felt's TOKEN_EXPIRY_SKEW (toolkit/components/felt/rust/src/utils.rs):
// refresh a little before the token actually expires.
const TOKEN_EXPIRY_SKEW = 5 * 60;

/*
 * IMPORTANT! Keep the deserialized JSON format compatible with
 * toolkit/crashreporter/client/app/src/net/http.rs
 */

async function createRequestInit(requestBuilder) {
  switch (requestBuilder.type) {
    case "MimePost": {
      const formData = new FormData();
      for (const part of requestBuilder.parts) {
        let content = part.content;
        const options = { type: part.mime_type ?? "" };
        switch (content.type) {
          case "File":
            content = await File.createFromFileName(content.value, options);
            break;
          case "String":
            content = new Blob([content.value], options);
            break;
        }
        formData.append(part.name, content, part.filename);
      }
      return {
        method: "POST",
        headers: Object.fromEntries(requestBuilder.headers ?? []),
        body: formData,
      };
    }
    case "Post": {
      const body = requestBuilder.body;
      const headers = requestBuilder.headers;
      return {
        method: "POST",
        headers: Object.fromEntries(headers),
        body: new Uint8Array(body),
      };
    }
  }

  throw new Error("invalid request builder format");
}

function tokenExpired(expiresAt) {
  return (expiresAt ?? 0) - TOKEN_EXPIRY_SKEW < Math.floor(Date.now() / 1000);
}

/**
 * In Firefox Enterprise, crash uploads are sent to the admin console and must
 * carry the same Felt bearer token as other console communication. The token
 * is persisted to disk by Felt (see EnterpriseCrashToken) because this task
 * runs in a fresh process with no in-memory token.
 *
 * Returns the persisted token state (refreshing the access token if it is
 * already expired), or null for non-enterprise builds where no token file
 * exists and uploads stay unauthenticated.
 */
async function getEnterpriseToken() {
  let state;
  try {
    state = await lazy.EnterpriseCrashToken.read();
  } catch (e) {
    console.error(`Failed to read enterprise crash token: ${e}`);
    return null;
  }
  if (!state) {
    return null;
  }
  if (tokenExpired(state.expiresAt)) {
    return (await refreshEnterpriseToken(state)) ?? state;
  }
  return state;
}

/**
 * Refresh the access token via the console's /sso/token endpoint and persist
 * the rotated tokens. Returns the updated state, or null on failure.
 *
 * Note: each upload runs in its own background task process, so two concurrent
 * uploads could both refresh and rotate the refresh token, invalidating one
 * another. We tolerate that: the losing upload fails and its report stays
 * pending for a later, re-authenticated session to retry.
 */
async function refreshEnterpriseToken(state) {
  if (!state.refreshToken || !state.consoleUrl) {
    return null;
  }
  try {
    const { access_token, refresh_token, expires_at } =
      await lazy.ConsoleClient._doTokenRefresh(
        state.consoleUrl,
        state.refreshToken
      );
    await lazy.EnterpriseCrashToken.write({
      accessToken: access_token,
      refreshToken: refresh_token,
      expiresAt: expires_at,
      consoleUrl: state.consoleUrl,
    });
    return {
      accessToken: access_token,
      refreshToken: refresh_token,
      expiresAt: expires_at,
      consoleUrl: state.consoleUrl,
    };
  } catch (e) {
    console.error(`Failed to refresh enterprise crash token: ${e}`);
    return null;
  }
}

export async function runBackgroundTask(commandLine) {
  const requestUrl = commandLine.getArgument(0);
  const requestUserAgent = commandLine.getArgument(1);
  const requestBuilderFilePath = commandLine.getArgument(2);

  const requestBuilderFile = await File.createFromFileName(
    requestBuilderFilePath
  );
  const requestBuilder = JSON.parse(await requestBuilderFile.text());

  const requestInit = await createRequestInit(requestBuilder);
  (requestInit.headers ??= {})["User-Agent"] = requestUserAgent;

  let tokenState = await getEnterpriseToken();
  if (tokenState?.accessToken) {
    requestInit.headers.Authorization = `Bearer ${tokenState.accessToken}`;
  }

  let response = await fetch(requestUrl, requestInit);

  // If the console rejected the token, refresh it once and retry.
  if (
    (response.status === 401 || response.status === 403) &&
    tokenState?.refreshToken
  ) {
    const refreshed = await refreshEnterpriseToken(tokenState);
    if (refreshed?.accessToken) {
      requestInit.headers.Authorization = `Bearer ${refreshed.accessToken}`;
      response = await fetch(requestUrl, requestInit);
    }
  }

  if (!response.ok) {
    console.error(
      `Request failed: ${response.status} ${response.statusText}\n${await response.text()}`
    );
    return 1;
  }

  await IOUtils.write(requestBuilderFilePath, await response.bytes());

  return EXIT_CODE.SUCCESS;
}
