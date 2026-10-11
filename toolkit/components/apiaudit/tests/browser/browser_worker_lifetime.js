/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

// Test that blob workers which self-terminate remain visible in the worker
// descriptor list when privacy.apiaudit.hideDevTools is on, so that pages
// cannot evade inspection by spinning up an ephemeral worker.

const { require } = ChromeUtils.importESModule(
  "resource://devtools/shared/loader/Loader.sys.mjs"
);
const {
  DevToolsServer,
} = require("resource://devtools/server/devtools-server.js");
const {
  DevToolsClient,
} = require("resource://devtools/client/devtools-client.js");

const TEST_ROOT = getRootDirectory(gTestPath).replace(
  "chrome://mochitests/content",
  "https://example.com"
);
const TEST_PAGE = TEST_ROOT + "file_worker_lifetime.html";

async function spawnLocalClient() {
  if (!DevToolsServer.initialized) {
    DevToolsServer.init();
    DevToolsServer.registerAllActors();
  }
  const client = new DevToolsClient(DevToolsServer.connectPipe());
  await client.connect();
  return client;
}

add_setup(async function () {
  await SpecialPowers.pushPrefEnv({
    set: [
      ["privacy.apiaudit.enabled", true],
      ["privacy.apiaudit.hideDevTools", true],
    ],
  });
});

add_task(async function test_terminated_blob_worker_stays_visible() {
  const hideDevTools = Services.prefs.getBoolPref(
    "privacy.apiaudit.hideDevTools",
    false
  );
  info(`privacy.apiaudit.hideDevTools = ${hideDevTools}`);

  const client = await spawnLocalClient();

  const tab = await BrowserTestUtils.openNewForegroundTab({
    gBrowser,
    url: TEST_PAGE,
  });

  info("Wait for the blob worker to appear and terminate");
  let terminatedWorker = null;
  let attempts = 0;
  await TestUtils.waitForCondition(async () => {
    attempts++;
    const mainRoot = client.mainRoot;
    const { workers } = await mainRoot.listWorkers();
    info(`Attempt ${attempts}: ${workers.length} workers visible`);
    for (const w of workers) {
      info(`  Worker: url=${w.url}, traits=${JSON.stringify(w.traits)}`);
    }
    terminatedWorker = workers.find(
      w => w.url && w.url.startsWith("blob:") && w.traits?.isTerminated
    );
    return !!terminatedWorker;
  }, "Waiting for the blob worker descriptor to appear as terminated");

  ok(
    terminatedWorker,
    "The terminated blob worker descriptor is still visible"
  );
  is(
    terminatedWorker.traits.isTerminated,
    true,
    "The descriptor reports isTerminated"
  );

  await client.close();
  BrowserTestUtils.removeTab(tab);
});

add_task(async function test_blob_worker_not_retained_without_pref() {
  await SpecialPowers.pushPrefEnv({
    set: [["privacy.apiaudit.hideDevTools", false]],
  });

  const client = await spawnLocalClient();

  const tab = await BrowserTestUtils.openNewForegroundTab({
    gBrowser,
    url: TEST_PAGE,
  });

  info("Wait for the page to spawn the blob worker and for it to close");
  await TestUtils.waitForCondition(
    () => tab.linkedBrowser.contentTitle == "done",
    "Waiting for the page to finish"
  );

  let removed = false;
  await TestUtils.waitForCondition(async () => {
    const { workers } = await client.mainRoot.listWorkers();
    removed = !workers.some(
      w => w.url && w.url.startsWith("blob:") && w.traits?.isTerminated
    );
    return removed;
  }, "Waiting for no terminated blob worker descriptor to be listed");

  ok(
    removed,
    "Without the pref, the terminated blob worker descriptor is not retained"
  );

  await client.close();
  BrowserTestUtils.removeTab(tab);
  await SpecialPowers.popPrefEnv();
});
