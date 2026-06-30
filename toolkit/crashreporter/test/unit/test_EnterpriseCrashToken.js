/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

const { EnterpriseCrashToken } = ChromeUtils.importESModule(
  "resource://gre/modules/EnterpriseCrashToken.sys.mjs"
);
const { OSKeyStoreTestUtils } = ChromeUtils.importESModule(
  "resource://testing-common/OSKeyStoreTestUtils.sys.mjs"
);

add_setup(function () {
  OSKeyStoreTestUtils.setup();
});

registerCleanupFunction(async () => {
  await EnterpriseCrashToken.clear();
  await OSKeyStoreTestUtils.cleanup();
});

add_task(async function test_write_read_clear() {
  const expiresAt = Math.floor(Date.now() / 1000) + 3600;
  await EnterpriseCrashToken.write({
    accessToken: "access-abc",
    refreshToken: "refresh-xyz",
    expiresAt,
    consoleUrl: "https://console.example.com",
  });

  const read = await EnterpriseCrashToken.read();
  Assert.equal(read.accessToken, "access-abc");
  Assert.equal(read.refreshToken, "refresh-xyz");
  Assert.equal(read.expiresAt, expiresAt);
  Assert.equal(read.consoleUrl, "https://console.example.com");

  // The refresh token must not be stored in cleartext.
  const raw = await IOUtils.readUTF8(EnterpriseCrashToken.TOKEN_FILE_PATH);
  Assert.ok(!raw.includes("refresh-xyz"), "refresh token is encrypted at rest");
  Assert.ok(raw.includes("access-abc"), "access token is stored in cleartext");

  await EnterpriseCrashToken.clear();
  Assert.equal(
    await EnterpriseCrashToken.read(),
    null,
    "read returns null after clear"
  );
});

add_task(async function test_read_missing_returns_null() {
  await EnterpriseCrashToken.clear();
  Assert.equal(await EnterpriseCrashToken.read(), null);
});
