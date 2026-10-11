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
const TEST_PAGE = TEST_ROOT + "file_capture.html";

add_setup(async function () {
  await SpecialPowers.pushPrefEnv({
    set: [["privacy.apiaudit.enabled", true]],
  });
  ApiAudit.init();
  await ApiAudit.clear();
});

async function loadAndCollect(browser) {
  BrowserTestUtils.startLoadingURIString(browser, TEST_PAGE);
  await BrowserTestUtils.browserLoaded(browser);
  await TestUtils.waitForCondition(
    () => browser.contentTitle == "done",
    "Waiting for the page to finish probing"
  );
  let innerWindowId = browser.browsingContext.currentWindowGlobal.innerWindowId;
  let windows = await ApiAudit.collect({ includeCode: true });
  let record = windows.find(w => w.innerWindowId == innerWindowId);
  let context = record.contexts.find(c => c.kind == "window");
  return { record, context, apis: new Map(context.apis.map(a => [a.name, a])) };
}

function callsOf(apis, name) {
  let api = apis.get(name);
  ok(api, `${name} was recorded`);
  return api?.calls ?? [];
}

add_task(async function test_capture() {
  await BrowserTestUtils.withNewTab("about:blank", async browser => {
    let { context, apis } = await loadAndCollect(browser);

    ok(
      callsOf(apis, "CanvasRenderingContext2D.fillText()").some(
        c => c.args.join(", ") == '"hello", 2, 10'
      ),
      "Every argument of a call is recorded"
    );
    ok(
      callsOf(apis, "HTMLCanvasElement.getContext()").some(
        c => c.result == "[object CanvasRenderingContext2D]"
      ),
      "Return values are recorded"
    );
    ok(
      apis.get("Document.cookie=").args.includes('"apiaudit=1"'),
      "Setter values are recorded"
    );
    ok(
      callsOf(apis, "Crypto.getRandomValues()").some(c =>
        /^Uint8Array\(4\) #[0-9a-f]{8}$/.test(c.result)
      ),
      "Typed arrays are recorded with their length and a hash"
    );

    ok(
      callsOf(apis, "StorageManager.estimate()").some(c =>
        /^Promise resolved: \{.*quota: \d+/.test(c.result)
      ),
      "What a returned promise resolves with is recorded"
    );

    let languages = apis.get("Navigator.languages");
    Assert.greaterOrEqual(
      languages.count,
      3,
      "Reads of [Cached] attributes are all counted"
    );
    ok(
      languages.calls.some(c => c.result.startsWith('["')),
      "Array results are described element by element"
    );

    ok(
      callsOf(apis, "Storage.setItem()").some(
        c => c.args.join(", ") == '"apiauditKey", "stored"'
      ),
      "Named property assignments record the key and value"
    );
    ok(
      apis.get("Storage.getItem()").args.includes('"apiauditKey"'),
      "Named property reads record the key"
    );

    let offset = callsOf(apis, "Date.getTimezoneOffset()");
    ok(
      offset.some(c => /^-?\d+$/.test(c.result)),
      "Date.getTimezoneOffset() is recorded with its result"
    );
    is(
      rankApi("Date.getTimezoneOffset()").category,
      "locale",
      "Time zone probes are ranked"
    );
    ok(
      callsOf(apis, "Intl.DateTimeFormat.resolvedOptions()").some(c =>
        c.result.includes("timeZone: ")
      ),
      "Intl resolved options are recorded"
    );
    let tan = apis.get("Math.tan()");
    ok(tan?.args.includes("-1e+300"), "Math probes record their argument");
    is(
      rankApi(tan.name, tan.args).score,
      60,
      "Extreme math arguments are ranked as precision probes"
    );

    ok(
      apis.has("new WebAssembly.Module()"),
      "WebAssembly compilation is recorded"
    );
    let wasm = context.code.find(c => c.kind == "wasm");
    is(wasm?.encoding, "base64", "WebAssembly modules are captured as base64");
    is(wasm?.text, "AGFzbQEAAAA=", "The module bytes are captured");

    let handler = context.code.find(c => c.kind == "event-handler");
    is(
      handler?.text,
      "window.handlerRan = 1",
      "Inline event handler source is captured"
    );
    ok(handler.url.endsWith(" onclick"), "The handler attribute is named");
    ok(
      context.code.some(
        c => c.kind == "javascript-url" && c.text == "void(window.jsurlRan = 1)"
      ),
      "javascript: URL code is captured"
    );

    ok(
      callsOf(apis, "CSS.@media").some(
        c =>
          c.args[0].includes("min-resolution") &&
          ["matches", "no match"].includes(c.result)
      ),
      "Stylesheet media queries are recorded with their result"
    );
    ok(
      callsOf(apis, "CSS.@supports").some(
        c => c.args[0].includes("display") && c.result == "matches"
      ),
      "Stylesheet @supports conditions are recorded"
    );
    ok(
      callsOf(apis, "CSS.@font-face local()").some(
        c => c.args[0] == '"ApiAudit No Such Font"' && c.result == "not found"
      ),
      "@font-face local() lookups are recorded"
    );

    let { requests, cookies } = ApiAudit.collectNetwork();
    let post = requests.find(
      r => r.url.endsWith("?beacon") && r.method == "POST"
    );
    ok(post, "Requests made by the page are recorded");
    is(post?.requestBody?.text, "apiaudit-body", "Request bodies are recorded");
    is(post?.browserId, browser.browserId, "Requests are attributed to tabs");
    ok(
      post?.requestHeaders.some(([name]) => name.toLowerCase() == "cookie"),
      "Request headers include the cookies sent"
    );
    ok(
      cookies.some(
        c => c.name == "apiaudit" && c.value == "1" && c.action == "added"
      ),
      "Cookie changes are recorded"
    );
  });
});
