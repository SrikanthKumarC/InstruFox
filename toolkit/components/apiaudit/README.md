# API Audit

Records every WebIDL method, getter, setter and constructor that web content
invokes, with its arguments and what it returned, in every content process and
in workers; the JS builtins that reveal the time zone, locale and floating
point behavior; the conditions stylesheets evaluate; the code pages compile;
and the network requests and cookies they produce. Shows them in a window
ranked by privacy risk.

## Upstream touch points

Everything lives in this directory except:

- `dom/bindings/Codegen.py`: `CGPerSignatureCall.apiAuditCall` emits a
  recorder (`AutoRecordMethod`, `AutoRecordGetter`, `RecordSetter` or
  `RecordKey`) at the top of every generated binding member and named or
  indexed property operation, `CGSpecializedGetter` emits the getter recorder
  before the cached-slot early return, and `mozilla/ApiAudit.h` is added to
  generated binding includes.
- `js/src/jsfriendapi.{h,cpp}` and `js/src/vm/BuiltinAudit.h`:
  `js::SetBuiltinAuditHook` and the `AuditedNative` wrapper. The function
  specs of the wrapped builtins use `AuditedNative<native, name>`:
  `Date.getTimezoneOffset/toString/toTimeString/toLocale*String`
  (`js/src/builtin/Date.cpp`), every `Intl.*.resolvedOptions` and
  `Intl.supportedValuesOf` (`js/src/builtin/intl/`),
  `Temporal.Now.timeZoneId` (`js/src/builtin/temporal/TemporalNow.cpp`), the
  transcendental `Math` functions (`js/src/builtin/Math.cpp`), and
  `WebAssembly.compile/instantiate/validate/compileStreaming/
  instantiateStreaming` and the `WebAssembly.Module` constructor
  (`js/src/wasm/WasmJS.cpp`).
- `dom/fetch/FetchUtil.cpp` (`JSStreamConsumer`): copies the bytes of
  streamed WebAssembly modules to an `apiaudit::StreamCapture`.
- `dom/events/EventListenerManager.cpp` (`CompileEventHandlerInternal`) and
  `dom/jsurl/nsJSProtocolHandler.cpp` (`JSURLInputStream::EvaluateScript`):
  one `RecordCodeText` call each, for inline event handler attributes and
  `javascript:` URLs.
- `gfx/thebes/gfxUserFontSet.{h,cpp}` (`gfxUserFontSet::RecordLocalFontLookup`,
  called from `gfxUserFontEntry::LoadNextSrc`) and
  `layout/style/FontFaceSetImpl.{h,cpp}`: records `src: local()` lookups.
- `servo/components/style/stylist.rs` (`CascadeData::add_rule_list` and
  `CascadeData::add_stylesheet`) and `layout/style/GeckoBindings.{h,cpp}`
  (`Gecko_ApiAudit_*`): records the `@media`, `@supports` and `@import`
  conditions and the media lists of author stylesheets.
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
  For each API it keeps the call count, up to 24 distinct first arguments,
  up to 12 distinct calling scripts (`url:line:col`) and, from the first 128
  calls, up to 64 distinct calls: all their arguments (up to 8), their result
  and the first script that made them. For each context it keeps up to 256
  distinct pieces of code (worker scripts, `eval`/`Function` strings, inline
  event handlers, `javascript:` URLs, WebAssembly modules), each truncated to
  `privacy.apiaudit.maxCodeLength` characters (default 524288).
- Arguments are described after the call returns, so typed arrays that the
  callee fills in (`getFloatFrequencyData()`, `readPixels()`) show their new
  contents. Values are described without running page script: strings are
  cut at 200 characters and followed by their full length and a hash, typed
  arrays and `ArrayBuffer`s by their length and a hash of their bytes, arrays
  and plain objects (dictionaries) by their elements up to two levels deep,
  and other objects by their class. When a method returns a promise, the
  call is recorded once the promise settles, with what it resolved or
  rejected with (`getHighEntropyValues()`, `enumerateDevices()`,
  `StorageManager.estimate()`). A call that throws records the exception.
- Setters record the value being assigned (`Document.cookie=`). Named and
  indexed property operations record the property name, and the value for
  assignments (`localStorage.foo = ...` is recorded as `Storage.setItem()`).
- `[Cached]` and `[StoreInSlot]` attributes are recorded on every read the
  binding sees, including reads served from the slot.
- The JS builtins listed above are recorded through `js::SetBuiltinAuditHook`
  under names such as `Date.getTimezoneOffset()`, `Intl.DateTimeFormat.
  resolvedOptions()` and `Math.tan()`. The bytes of WebAssembly modules,
  whether passed as a buffer or streamed from a `Response`, are captured as
  base64 code entries of kind `wasm`.
- Author stylesheets record each `@media`, `@supports` and `@import` media
  condition and the media list of the stylesheet itself as `CSS.@media`,
  `CSS.@supports`, `CSS.@import media` and `CSS.stylesheet media`, with
  "matches" or "no match" and the stylesheet URL as the caller. User agent
  and user stylesheets are ignored. `src: local()` lookups are recorded as
  `CSS.@font-face local()` with "found" or "not found".
- `ApiAuditNetwork.sys.mjs` records, in the parent process, every HTTP request
  made for web content: URL, method, type, status, request and response
  headers (cookies included), the request body (up to 64 KiB, base64 when
  binary), the remote address and the tracking protection classification
  (`nsIClassifiedChannel` flags and matched lists). It also records every
  cookie change (`cookie-changed`), and `collectNetwork()` returns the content
  blocking log of each tab.
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
  Expanding an API row lists its distinct calls with their arguments and
  results. The Network view lists the requests, cookie changes and content
  blocking log of the selection; click a request for its headers, body and
  classification.
  Its sidebar groups everything by tab (or by site when there is no tab):
  each page load in the tab, then each frame and worker. Selecting any level
  shows the APIs and code of everything below it. Expanding an `eval`,
  `Function`, `setTimeout`, `setInterval`, `Worker` or `importScripts` row
  shows the code it ran.
  Its Code view lists captured code, with blob:/data: workers and dynamic code
  flagged; WebAssembly modules can be saved as `.wasm` files. "Copy all"
  copies the selected page's report as JSON: every API with its calls and
  results, the captured code, and the network requests, cookie changes and
  content blocking log. "Copy summary" copies a Markdown summary of the
  selection: every API with its call count and results, grouped by category,
  the contexts, the list of captured code (without its text), and the hosts
  contacted and cookies changed. Service workers are listed under the pages they control or that
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

Pages can also hide code from DevTools by running it in a blob: or data:
worker that closes itself right away, before anyone can attach to it. While
`privacy.apiaudit.hideDevTools` is true, such workers stay in the DevTools
worker list after they close, reported with the `isTerminated` trait
(`WorkerDescriptorFront.isTerminated`); their code is in the Code view. This
touches `devtools/server/actors/descriptors/worker.js`,
`devtools/server/actors/worker/worker-descriptor-actor-list.js` and
`devtools/client/fronts/descriptors/worker.js`.

## Not covered

JS builtins other than the ones listed above, such as `Function.prototype.
toString` or `Error.prototype.stack`. Builtins and binding getters that Ion
inlines or serves from a slot (`[StoreInSlot]` attributes, `[Pure]` getters
hoisted out of loops, `Math` functions) are recorded on the calls made before
the code is compiled, so their call counts are lower bounds; every calling
script is still seen. Values are described without running page script, so
DOM objects are only described by their class (their attributes are recorded
when the page reads them). Results of named and indexed property reads are
not recorded. Font metrics observed through layout show up only as the
results of the geometry getters that read them. Container queries and other
stylesheet conditions evaluated during selector matching are not recorded.
Network requests made before the first browser window opened are not
recorded. A shared worker started with a URL that the page computed without
passing a string, `URL` or `TrustedScriptURL` cannot be linked and stays a
separate entry.

DevTools detection not covered: the deferred console serialization still
runs on the target thread, so a page measuring event-loop lag (for example
with `setTimeout` drift) while spamming heavy console calls can still see
DevTools. Likewise the general slowdown of a page the Debugger is attached
to (JIT deopt, slower allocation) is not equalized.
