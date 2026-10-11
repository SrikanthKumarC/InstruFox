/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

const { ApiAudit } = ChromeUtils.importESModule(
  "moz-src:///toolkit/components/apiaudit/ApiAudit.sys.mjs"
);
const { rankApi } = ChromeUtils.importESModule(
  "moz-src:///toolkit/components/apiaudit/ApiAuditRanking.sys.mjs"
);

const TEST_ROOT = getRootDirectory(gTestPath).replace(
  "chrome://mochitests/content",
  "https://example.com"
);
const TEST_PAGE = TEST_ROOT + "file_fingerprint.html";
const BLOB_WORKER_PAGE = TEST_ROOT + "file_blob_worker.html";

function mainContext(record) {
  return record.contexts.find(context => context.kind == "window");
}

async function loadAndCollect(browser, url = TEST_PAGE, options = {}) {
  BrowserTestUtils.startLoadingURIString(browser, url);
  await BrowserTestUtils.browserLoaded(browser);
  await TestUtils.waitForCondition(
    () => browser.contentTitle == "done",
    "Waiting for the page to finish probing"
  );
  let innerWindowId = browser.browsingContext.currentWindowGlobal.innerWindowId;
  let windows = await ApiAudit.collect(options);
  return windows.find(w => w.innerWindowId == innerWindowId);
}

add_setup(async function () {
  await SpecialPowers.pushPrefEnv({
    set: [["privacy.apiaudit.enabled", true]],
  });
  ApiAudit.init();
});

add_task(async function test_records_page_calls() {
  await BrowserTestUtils.withNewTab("about:blank", async browser => {
    let record = await loadAndCollect(browser);
    ok(record, "Found a record for the test page");
    is(record.origin, "https://example.com", "Origin is recorded");
    ok(record.isTop, "Test page is a top-level document");
    is(record.browserId, browser.browserId, "browserId is recorded");

    let apis = new Map(mainContext(record).apis.map(api => [api.name, api]));
    for (let name of [
      "HTMLCanvasElement.toDataURL()",
      "Navigator.hardwareConcurrency",
      "Screen.width",
      "new OfflineAudioContext()",
      "AudioBuffer.getChannelData()",
    ]) {
      ok(apis.has(name), `${name} was recorded`);
    }

    let matchMedia = apis.get("Window.matchMedia()");
    ok(
      matchMedia.args.includes('"(prefers-color-scheme: dark)"'),
      "matchMedia argument was recorded"
    );
    ok(
      matchMedia.scripts.some(s => s.startsWith(TEST_PAGE)),
      "Calling script was recorded"
    );

    let getParameter = apis.get("WebGLRenderingContext.getParameter()");
    if (getParameter) {
      ok(getParameter.args.includes("37446"), "getParameter enum recorded");
      is(
        rankApi(getParameter.name, getParameter.args).score,
        100,
        "Unmasked renderer query gets the top score"
      );
    }

    is(
      rankApi("HTMLCanvasElement.toDataURL()").category,
      "canvas",
      "toDataURL is ranked as canvas fingerprinting"
    );
    is(rankApi("Node.appendChild()").score, 0, "Unknown APIs rank as noise");
    is(
      rankApi("WorkerNavigator.hardwareConcurrency").score,
      rankApi("Navigator.hardwareConcurrency").score,
      "Worker navigator properties rank like their window counterparts"
    );

    await SpecialPowers.spawn(browser, [], () => {
      return content.navigator.oscpu;
    });
    record = (await ApiAudit.collect()).find(
      w => w.innerWindowId == record.innerWindowId
    );
    ok(
      !mainContext(record).apis.some(api => api.name == "Navigator.oscpu"),
      "Calls made by privileged code are not recorded"
    );
  });
});

add_task(async function test_disabled() {
  await SpecialPowers.pushPrefEnv({
    set: [["privacy.apiaudit.enabled", false]],
  });
  await BrowserTestUtils.withNewTab("about:blank", async browser => {
    let record = await loadAndCollect(browser);
    ok(!record?.contexts.length, "Nothing is recorded while disabled");
  });
  await SpecialPowers.popPrefEnv();
});

add_task(async function test_window_ranks_apis() {
  await BrowserTestUtils.withNewTab("about:blank", async browser => {
    await loadAndCollect(browser);
    let win = ApiAudit.openWindow(window);
    await BrowserTestUtils.waitForEvent(win, "load");
    let rows = win.document.getElementById("rows");
    await TestUtils.waitForCondition(
      () => rows.children.length,
      "Waiting for ranked rows"
    );
    let scores = [...rows.querySelectorAll("tr td:first-child")].map(td =>
      Number(td.textContent)
    );
    ok(
      scores.every(score => score >= 30),
      "Default threshold hides noise"
    );
    Assert.deepEqual(
      scores,
      scores.toSorted((a, b) => b - a),
      "Rows are sorted by score"
    );
    ok(
      [...rows.querySelectorAll(".api")].some(td =>
        td.textContent.startsWith("HTMLCanvasElement.toDataURL")
      ),
      "toDataURL is listed"
    );
    is(ApiAudit.openWindow(window), win, "Opening again focuses the window");
    await BrowserTestUtils.closeWindow(win);
  });
});

add_task(async function test_blob_workers_and_dynamic_code() {
  await BrowserTestUtils.withNewTab("about:blank", async browser => {
    let record = await loadAndCollect(browser, BLOB_WORKER_PAGE, {
      includeCode: true,
    });
    ok(record, "Found a record for the blob worker page");

    let main = mainContext(record);
    let newWorker = main.apis.find(api => api.name == "new Worker()");
    ok(newWorker, "Worker construction was recorded");
    ok(
      newWorker.args.some(arg =>
        arg.startsWith('TrustedScriptURL "blob:https://example.com/')
      ),
      "Worker blob URL inside the TrustedScriptURL was recorded"
    );
    is(
      rankApi(newWorker.name, newWorker.args).category,
      "dynamic",
      "Blob workers are ranked as hidden code"
    );
    ok(
      main.code.some(
        code =>
          code.kind == "Function" &&
          code.text.includes("APIAUDIT_FUNCTION_MARKER")
      ),
      "new Function() source on the main thread was captured"
    );

    let worker = record.contexts.find(
      context =>
        context.kind == "dedicated-worker" &&
        context.url.startsWith("blob:https://example.com/") &&
        !context.parentUrl
    );
    ok(worker, "Blob worker has its own context");
    let workerApis = worker.apis.map(api => api.name);
    for (let name of [
      "WorkerNavigator.hardwareConcurrency",
      "OffscreenCanvasRenderingContext2D.fillText()",
      "eval()",
    ]) {
      ok(workerApis.includes(name), `${name} was recorded in the worker`);
    }
    let script = worker.code.find(code => code.kind == "worker-script");
    ok(
      script?.text.includes("APIAUDIT_WORKER_MARKER"),
      "Decoded worker source was captured"
    );
    is(script.url, worker.url, "Captured source carries the blob URL");
    ok(
      worker.code.some(
        code =>
          code.kind == "eval" &&
          code.text == "self.APIAUDIT_EVAL_MARKER = 1 + 1"
      ),
      "eval() source in the worker was captured"
    );
    ok(
      worker.apis
        .find(api => api.name == "eval()")
        ?.args.includes('"self.APIAUDIT_EVAL_MARKER = 1 + 1"'),
      "eval() code is recorded as its argument"
    );
    ok(
      main.code.some(
        code =>
          code.kind == "setTimeout" &&
          code.text == "window.APIAUDIT_TIMER_MARKER = 1"
      ),
      "setTimeout() string code was captured"
    );

    let nested = record.contexts.find(
      context => context.parentUrl == worker.url
    );
    ok(nested, "Nested blob worker has its own context");
    ok(
      nested.apis.some(api => api.name == "WorkerNavigator.platform"),
      "Nested worker API calls were recorded"
    );

    let pageScripts = new Map(main.code.map(code => [code.kind, code]));
    ok(
      pageScripts.get("inline-script")?.text.includes("APIAUDIT_INLINE_MARKER"),
      "Inline <script> source was captured"
    );
    let external = main.code.find(code => code.kind == "script");
    ok(
      external?.url.endsWith("file_external.js") &&
        external.text.includes("APIAUDIT_EXTERNAL_MARKER"),
      "External <script> source was captured"
    );
    let module = main.code.find(code => code.kind == "module");
    ok(
      module?.url.endsWith("file_module.mjs") &&
        module.text.includes("APIAUDIT_MODULE_MARKER"),
      "Module script source was captured"
    );

    let windows = await ApiAudit.collect({ includeCode: true });
    let shared = windows.find(
      w => w.isWorker && w.url == TEST_ROOT + "file_shared_worker.js"
    );
    ok(shared, "Shared worker has its own entry");
    let sharedContext = shared.contexts[0];
    is(sharedContext.kind, "shared-worker", "Shared worker kind is recorded");
    ok(
      sharedContext.apis.some(
        api => api.name == "WorkerNavigator.hardwareConcurrency"
      ),
      "Shared worker API calls were recorded"
    );
    ok(
      sharedContext.code.some(code =>
        code.text.includes("APIAUDIT_SHARED_MARKER")
      ),
      "Shared worker source was captured"
    );

    let summary = await ApiAudit.collect();
    let light = summary.find(w => w.innerWindowId == record.innerWindowId);
    ok(
      light.contexts.every(c => c.code.every(code => !("text" in code))),
      "Code text is omitted unless requested"
    );
  });
});

async function openAuditWindow() {
  let win = ApiAudit.openWindow(window);
  await BrowserTestUtils.waitForEvent(win, "load");
  return win;
}

async function selectTab(doc, browser) {
  let key = `group:tab:${browser.browserId}`;
  let node = await TestUtils.waitForCondition(
    () => doc.querySelector(`#pages li[data-key="${key}"]`),
    "Waiting for the tab in the tree"
  );
  node.click();
  return key;
}

add_task(async function test_tab_grouping_and_copy_all() {
  await BrowserTestUtils.withNewTab("about:blank", async browser => {
    await loadAndCollect(browser, TEST_PAGE);
    await loadAndCollect(browser, BLOB_WORKER_PAGE);
    let win = await openAuditWindow();
    let doc = win.document;
    await selectTab(doc, browser);

    await TestUtils.waitForCondition(
      () => doc.querySelectorAll("#pages li.node-doc").length >= 2,
      "Both page loads of the tab are listed under it"
    );
    let docTitles = [...doc.querySelectorAll("#pages li.node-doc")].map(
      li => li.title
    );
    ok(docTitles.includes(TEST_PAGE), "First page load is in the tab");
    ok(docTitles.includes(BLOB_WORKER_PAGE), "Second page load is in the tab");
    ok(
      docTitles.includes("Shared & service workers"),
      "Linked shared worker is grouped with the tab"
    );
    let rows = doc.getElementById("rows");
    await TestUtils.waitForCondition(
      () =>
        [...rows.querySelectorAll("td")].some(td =>
          td.title.includes("shared-worker " + TEST_ROOT)
        ),
      "Shared worker calls are listed under the tab that created it"
    );
    ok(
      rows.querySelector('tr[data-api="HTMLCanvasElement.toDataURL()"]'),
      "Calls from the earlier page load are listed under the tab"
    );

    rows.querySelector('tr[data-api="eval()"]').click();
    await TestUtils.waitForCondition(
      () =>
        [...rows.querySelectorAll("tr.code-row pre")].some(
          pre => pre.textContent == "self.APIAUDIT_EVAL_MARKER = 1 + 1"
        ),
      "Expanding the eval() row shows the evaluated code"
    );
    rows.querySelector('tr[data-api="new Worker()"]').click();
    await TestUtils.waitForCondition(
      () =>
        [...rows.querySelectorAll("tr.code-row pre")].some(pre =>
          pre.textContent.includes("APIAUDIT_WORKER_MARKER")
        ),
      "Expanding the Worker row shows the worker source"
    );

    doc.querySelector("#views button[data-view=code]").click();
    await TestUtils.waitForCondition(
      () => doc.querySelectorAll("#code-list details").length >= 3,
      "Waiting for the code entries"
    );

    await SimpleTest.promiseClipboardChange(
      data => {
        try {
          let report = JSON.parse(data);
          return (
            report.code.some(code =>
              code.text.includes("APIAUDIT_WORKER_MARKER")
            ) &&
            report.apis.some(api => api.name == "HTMLCanvasElement.toDataURL()")
          );
        } catch {
          return false;
        }
      },
      () => doc.getElementById("copy-all").click()
    );
    ok(
      true,
      "Copy all puts the whole tab, including worker source, on the clipboard"
    );

    let summary;
    await SimpleTest.promiseClipboardChange(
      data => {
        summary = data;
        return data.startsWith("# API Audit summary");
      },
      () => doc.getElementById("copy-summary").click()
    );
    ok(
      /\| 90 \| HTMLCanvasElement\.toDataURL \| call \| 1 \|/.test(summary),
      "Summary lists ranked APIs with their call counts"
    );
    ok(
      summary.includes("### Dynamic / hidden code"),
      "Summary groups by category"
    );
    ok(
      summary.includes("dedicated-worker blob:https://example.com/"),
      "Summary lists the worker contexts"
    );
    ok(
      summary.includes("## Other APIs"),
      "Summary includes the remaining APIs"
    );
    ok(summary.includes("| eval (hidden) |"), "Summary lists captured code");
    ok(
      !summary.includes("APIAUDIT_WORKER_MARKER"),
      "Summary leaves out the code text"
    );
    await BrowserTestUtils.closeWindow(win);
  });
});

add_task(async function test_service_worker_linked_to_page() {
  await SpecialPowers.pushPrefEnv({
    set: [
      ["dom.serviceWorkers.enabled", true],
      ["dom.serviceWorkers.testing.enabled", true],
    ],
  });
  const SW_PAGE = TEST_ROOT + "file_sw_page.html";
  await BrowserTestUtils.withNewTab("about:blank", async browser => {
    let record = await loadAndCollect(browser, SW_PAGE);
    ok(record.serviceWorkerId, "Controlled page records its service worker");

    let worker;
    await TestUtils.waitForCondition(async () => {
      let windows = await ApiAudit.collect({ includeCode: true });
      worker = windows.find(
        w => w.isWorker && w.serviceWorkerId == record.serviceWorkerId
      );
      return worker;
    }, "Waiting for the service worker records");
    is(worker.url, TEST_ROOT + "file_sw.js", "Service worker URL is recorded");
    is(
      worker.serviceWorkerScope,
      TEST_ROOT,
      "Service worker scope is recorded"
    );
    let context = worker.contexts[0];
    is(context.kind, "service-worker", "Service worker kind is recorded");
    ok(
      context.apis.some(
        api => api.name == "WorkerNavigator.hardwareConcurrency"
      ),
      "Service worker API calls were recorded"
    );
    ok(
      context.code.some(code => code.text.includes("APIAUDIT_SW_MARKER")),
      "Service worker source was captured"
    );

    let win = await openAuditWindow();
    let doc = win.document;
    await selectTab(doc, browser);
    await TestUtils.waitForCondition(
      () =>
        [...doc.querySelectorAll("#rows td")].some(td =>
          td.title.includes("service-worker " + TEST_ROOT + "file_sw.js")
        ),
      "Service worker calls are listed under the page it controls"
    );
    [...doc.querySelectorAll("#pages li.node-doc")]
      .find(li => li.title == "Shared & service workers")
      .click();
    ok(
      [...doc.querySelectorAll("#pages li.node-worker")].some(li =>
        li.title.includes("service-worker " + TEST_ROOT + "file_sw.js")
      ),
      "Service worker is listed inside the tab"
    );
    ok(
      ![...doc.querySelectorAll("#pages li.node-group")].some(
        li => li.dataset.key == "group:site:example.com"
      ),
      "Linked service worker does not get a separate site entry"
    );
    await BrowserTestUtils.closeWindow(win);

    await SpecialPowers.spawn(browser, [], async () => {
      let registration = await content.navigator.serviceWorker.ready;
      await registration.unregister();
    });
  });
});

add_task(async function test_sessions() {
  await BrowserTestUtils.withNewTab("about:blank", async browser => {
    await loadAndCollect(browser);
    let innerWindowId =
      browser.browsingContext.currentWindowGlobal.innerWindowId;
    let probe = name =>
      SpecialPowers.spawn(browser, [name], n =>
        content.wrappedJSObject.probe(n)
      );
    let apiNames = async () => {
      let record = (await ApiAudit.collect()).find(
        w => w.innerWindowId == innerWindowId
      );
      return record?.contexts.flatMap(c => c.apis.map(api => api.name)) ?? [];
    };

    await ApiAudit.startSession();
    ok(ApiAudit.session.start, "Starting a session records its start time");
    ok(
      !(await apiNames()).includes("HTMLCanvasElement.toDataURL()"),
      "Calls made before the session started are gone"
    );
    await probe("oscpu");
    ok(
      (await apiNames()).includes("Navigator.oscpu"),
      "Calls made during the session are recorded"
    );

    ApiAudit.stopSession();
    ok(ApiAudit.session.stop, "Stopping records the stop time");
    await probe("platform");
    let names = await apiNames();
    ok(
      !names.includes("Navigator.platform"),
      "Nothing is recorded when stopped"
    );
    ok(names.includes("Navigator.oscpu"), "Stopping keeps the session's data");

    ApiAudit.resumeSession();
    await probe("vendor");
    names = await apiNames();
    ok(names.includes("Navigator.vendor"), "Resuming records again");
    ok(
      names.includes("Navigator.oscpu"),
      "Resuming keeps earlier session data"
    );

    await ApiAudit.clear();
    is((await apiNames()).length, 0, "Clear forgets everything");

    let win = await openAuditWindow();
    let doc = win.document;
    await TestUtils.waitForCondition(
      () =>
        doc.getElementById("session").textContent.startsWith("Recording since"),
      "The window shows the running session"
    );
    doc.getElementById("stop").click();
    ok(!ApiAudit.enabled, "The Stop button stops recording");
    await TestUtils.waitForCondition(
      () => doc.getElementById("session").textContent.startsWith("Stopped at"),
      "The window shows the stopped session"
    );
    ok(!doc.getElementById("resume").hidden, "Resume is offered when stopped");
    doc.getElementById("start").click();
    await TestUtils.waitForCondition(
      () => ApiAudit.enabled,
      "The Start button starts recording"
    );
    await probe("productSub");
    await selectTab(doc, browser);
    let rows = doc.getElementById("rows");
    await TestUtils.waitForCondition(
      () => rows.querySelector('tr[data-api="Navigator.productSub"]'),
      "Calls after Start are listed"
    );
    ok(
      !rows.querySelector('tr[data-api="Navigator.vendor"]'),
      "Calls from before Start are not listed"
    );
    await BrowserTestUtils.closeWindow(win);
  });
});

add_task(async function test_debugger_traps() {
  let defaults = Services.prefs.getDefaultBranch("");
  ok(
    !defaults.getBoolPref("devtools.debugger.pause-on-debugger-statement"),
    "DevTools does not pause on debugger statements by default"
  );
  is(
    defaults.getStringPref("devtools.toolbox.host"),
    "window",
    "DevTools opens undocked by default"
  );

  const { require } = ChromeUtils.importESModule(
    "resource://devtools/shared/loader/Loader.sys.mjs"
  );
  const { gDevTools } = require("devtools/client/framework/devtools");
  registerCleanupFunction(() => {
    Services.prefs.clearUserPref("devtools.everOpened");
    Services.prefs.clearUserPref("devtools.toolbox.selectedTool");
  });
  await BrowserTestUtils.withNewTab("about:blank", async browser => {
    let tab = gBrowser.getTabForBrowser(browser);
    let toolbox = await gDevTools.showToolboxForTab(tab, {
      toolId: "webconsole",
    });
    let record = await loadAndCollect(
      browser,
      TEST_ROOT + "file_antidebug.html"
    );
    is(browser.contentTitle, "done", "The page ran through its traps");
    ok(!toolbox.threadFront.paused, "DevTools did not pause");

    let main = mainContext(record);
    let debuggerApi = main.apis.find(api => api.name == "debugger()");
    ok(debuggerApi, "Debugger statements are recorded");
    ok(
      debuggerApi.args.some(arg => arg.startsWith('"Function ')),
      "The runtime-built trap is attributed to Function()"
    );
    is(
      rankApi(debuggerApi.name, debuggerApi.args).category,
      "antidebug",
      "Debugger statements are ranked as anti-debugging"
    );
    let flagged = main.code.filter(code => code.antiDebug).map(c => c.kind);
    ok(flagged.includes("inline-script"), "The page script is flagged");
    ok(flagged.includes("Function"), "The Function() code is flagged");
    await toolbox.destroy();
  });
});
