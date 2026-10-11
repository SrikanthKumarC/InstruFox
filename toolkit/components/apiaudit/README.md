# API Audit

Records every WebIDL method, getter, setter and constructor that web content
invokes, in every content process and in dedicated workers, and shows them in
a window ranked by privacy risk.

## Upstream touch points

Everything lives in this directory except:

- `dom/bindings/Codegen.py`: `CGPerSignatureCall.apiAuditCall` emits a call to
  `mozilla::apiaudit::Record*` at the top of every generated binding member,
  and `mozilla/ApiAudit.h` is added to generated binding includes.
- `dom/workers/ScriptLoader.cpp` (`WorkerScriptLoader::EvaluateScript`): one
  `RecordScriptSource` call, which captures the source of every classic and
  `importScripts()` worker script, including blob: and data: workers.
- `dom/script/ScriptLoader.cpp` (`ScriptLoader::EvaluateScript`): one
  `RecordCompiledScript` call, which captures every inline and external
  `<script>` (including blob: scripts and ones restored from the caches).
- `js/loader/ModuleLoaderBase.cpp` (`ModuleLoaderBase::CreateModuleScript`):
  one `RecordCompiledScript` call, for module scripts in windows and workers.
- `caps/nsScriptSecurityManager.cpp` (`ContentSecurityPolicyPermitsJSAction`)
  and `dom/workers/RuntimeService.cpp` (`ContentSecurityPolicyAllows`): one
  `RecordDynamicCode` call each, which captures strings compiled by `eval()`
  and `Function()` and logs WebAssembly compilation, on the main thread and in
  workers.
- `devtools/server/actors/resources/console-messages.js`
  (`ConsoleMessageWatcher`): page console calls no longer serialize their
  arguments synchronously within the call; the serialization is deferred to
  a later event loop turn, so timing `console.log`/`console.table` no
  longer reveals whether DevTools is open.
- `toolkit/components/moz.build`: adds `apiaudit` to `DIRS`.

When rebasing onto a newer mozilla-central, only those lines can conflict.

## How it works

- `ApiAudit.cpp` groups records per inner window, then per context: the
  window's main thread and each worker it started (nested workers included).
  Shared and service workers, which have no window, get their own entry; the
  window keeps the id of the service worker controlling it.
  For each API it keeps the call count, up to 24 distinct first arguments and
  up to 12 distinct calling scripts (`url:line:col`). For each context it keeps
  up to 64 distinct pieces of code (worker scripts, `eval`/`Function`
  strings), each truncated to `privacy.apiaudit.maxCodeLength` characters
  (default 524288).
  Calls made by system-principal code (browser chrome, actors,
  `SpecialPowers`) are ignored. Records of closed windows are kept for
  `privacy.apiaudit.retainSeconds` (default 600).
- `nsIApiAuditService` exposes the per-process records as JSON;
  the `ApiAudit` JS process actor gathers them from every process.
- `ApiAuditRanking.sys.mjs` scores each API from 0 (noise) to 100 and
  assigns a category; some scores depend on the recorded argument (for
  example `getParameter(37446)` is UNMASKED_RENDERER_WEBGL).
- `eval()` and `Function()` calls are recorded with their code as the
  argument; string `setTimeout()`/`setInterval()` calls are captured as code
  too.
- The "API Audit" toolbar button opens `chrome://global/content/apiaudit/apiaudit.html`.
  Its sidebar groups everything by tab (or by site when there is no tab):
  each page load in the tab, then each frame and worker. Selecting any level
  shows the APIs and code of everything below it. Expanding an `eval`,
  `Function`, `setTimeout`, `setInterval`, `Worker` or `importScripts` row
  shows the code it ran.
  Its Code view lists captured code, with blob:/data: workers and dynamic code
  flagged; "Copy all" copies the selected page's report, code included, as
  JSON. "Copy summary" copies a Markdown summary of the selection: every API
  with its call count, grouped by category, plus contexts and the list of
  captured code (without its text). Service workers are listed under the pages they control or that
  registered them, and shared workers under the pages that constructed them
  (matched on the resolved `new SharedWorker()` URL).
- Arguments that wrap a string in a DOM object (`TrustedScriptURL`,
  `TrustedScript`, `TrustedHTML`, `URL`) are recorded with that string;
  `Blob` arguments are recorded with their size and type.

## Usage

- Recording is on by default (`privacy.apiaudit.enabled`). In the window,
  Start forgets everything recorded so far, in every process, and records
  from that moment; Stop pauses recording and keeps the data; Resume
  continues the stopped session; Clear forgets the data (and, while
  recording, restarts the session from that moment).
- Raw log: `MOZ_LOG=ApiAudit:3` prints the first use of each API per window,
  `MOZ_LOG=ApiAudit:5` prints every sampled call.
- From the Browser Console:
  `ChromeUtils.importESModule("moz-src:///toolkit/components/apiaudit/ApiAudit.sys.mjs").ApiAudit.openWindow()`

## DevTools traps

Pages detect DevTools by pausing on `debugger;` statements (often in a loop or
built at runtime with `Function("debugger")`) and timing how long they took,
or by noticing that a docked toolbox shrank the viewport. While
`privacy.apiaudit.hideDevTools` is true (the default), the module changes two
DevTools defaults at startup: `devtools.debugger.pause-on-debugger-statement`
to false and `devtools.toolbox.host` to `window`. A value you set yourself, for
example with the "Pause on debugger statement" checkbox, still wins.

Captured code that contains a `debugger` statement is flagged
"anti-debugging", and each time such code is compiled a `debugger()` call
(ranked 85) is recorded with the kind and URL of that code as its argument.
The check is textual, so the word inside a string or comment also matches.

Pages also detect DevTools by timing `console.log`/`console.table`: with
DevTools open, every console call used to serialize its arguments (and
`console.table` enumerate the first argument's properties and
sub-properties) synchronously inside the call. That serialization now runs
in a later event loop turn, so the page-visible cost of a console call is
the same whether or not DevTools is attached (messages still reach the
console, one task later). The price is that mutations made in the same
task as a console call show up in the serialized message; `console.table`
on an object that changes keeps showing the state of the last task before
the message was serialized.

## Not covered

APIs that are not WebIDL members: JS built-ins (`Intl`, `Date`), CSS media
queries evaluated by stylesheets, font metrics observed through layout,
HTTP headers. Attribute reads that the JIT serves from a cached slot
(`[StoreInSlot]`/`[Cached]`) are only recorded on the first read. Event
handler attributes (`onclick="..."`), `javascript:` URLs and WebAssembly
module bytes are not captured. A shared worker started with a URL that the
page computed without passing a string, `URL` or `TrustedScriptURL` cannot
be linked and stays a separate entry.

DevTools detection not covered: the deferred console serialization still
runs on the target thread, so a page measuring event-loop lag (for example
with `setTimeout` drift) while spamming heavy console calls can still see
DevTools. Likewise the general slowdown of a page the Debugger is attached
to (JIT deopt, slower allocation) is not equalized.
