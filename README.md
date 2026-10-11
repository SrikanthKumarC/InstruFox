# Web Instrumentation Browser

A research browser built on the Firefox (Gecko) source tree that records what
websites do inside the browser: every Web API they call and what it returned,
the code they run (including code generated at runtime and code hidden in
blob: and data: workers), the CSS conditions they probe, and every network
request and cookie they produce. Everything is grouped per tab, frame and
worker, ranked by privacy risk, and exportable as JSON or Markdown.

It is meant for people who need to see exactly what a page does, not what it
claims to do:

- **Browser fingerprinting research**: see which canvas, WebGL, audio, font,
  locale, math-precision, screen, sensor and hardware APIs a script reads, with
  the actual arguments and values it got back.
- **Tracker and ad-tech analysis**: link API reads to the network requests
  and cookies that follow, with the tracking-protection classification of each
  request.
- **Anti-bot and anti-fraud script analysis**: capture the code those scripts
  generate at runtime (`eval`, `Function`, string timers, WebAssembly), including
  code that only exists inside short-lived workers.
- **Malicious JavaScript and obfuscation studies**: recover deobfuscated code
  as it is compiled, flag anti-debugging tricks, and keep DevTools hidden from
  pages that try to detect it.
- **Web measurement**: export a complete, structured per-page report to
  compare sites, browsers or page versions.

This is not an official Mozilla product and is not affiliated with or endorsed
by Mozilla. It uses Firefox's unofficial "Nightly" branding.

> **Privacy note:** the browser records request and response headers, request
> bodies, cookies and argument values, which can include passwords, tokens and
> other personal data. Use a separate profile for research, and review any
> report before sharing it.

## What it records

| Area | What is captured |
| --- | --- |
| Web APIs | Every WebIDL method, getter, setter and constructor that web content calls, in every content process and in dedicated, shared and service workers: call counts, arguments, results (including what promises resolve or reject with), exceptions, and the calling script `url:line:col`. |
| JS builtins | The builtins that reveal time zone, locale and floating-point behavior: `Date` time zone methods, every `Intl.*.resolvedOptions()`, `Intl.supportedValuesOf()`, `Temporal.Now.timeZoneId()`, and the transcendental `Math` functions. |
| Code | Inline and external `<script>`, module scripts, worker and `importScripts()` sources (blob: and data: included), `eval()` / `Function()` strings, string `setTimeout()` / `setInterval()`, inline event handlers, `javascript:` URLs, and WebAssembly module bytes (savable as `.wasm`). |
| CSS | `@media`, `@supports` and `@import` conditions in author stylesheets with whether they matched, and `src: local()` font lookups with whether the font was found. |
| Network | Every request made for web content: URL, method, type, status, request and response headers, request body, remote address, and tracking-protection classification. Also every cookie change and each tab's content blocking log. |
| Anti-debugging | Code containing `debugger` statements is flagged and every compilation of it is recorded. |

Each API gets a score from 0 (noise) to 100 and a category: canvas, WebGL /
WebGPU, audio, fonts, device and browser properties, time zone and locale, math
precision, screen geometry, media devices, sensors, network / WebRTC leaks,
storage and identifiers, permission probing, crypto, timing side channels, CSS
media queries, clipboard, navigation, workers, dynamic code and anti-debugging.
Some scores depend on the argument; for example `getParameter(37446)` is
`UNMASKED_RENDERER_WEBGL` and ranks high.

### Hiding DevTools from pages

Many scripts change their behavior, or stop running, when they detect that
DevTools is open. While `privacy.apiaudit.hideDevTools` is on (the default):

- pausing on `debugger;` statements is off by default and the toolbox opens in
  a separate window, so debugger-timing and viewport-size checks see nothing;
- console calls serialize their arguments one event loop turn later, so timing
  `console.log` / `console.table` no longer reveals DevTools;
- blob: and data: workers that close themselves stay listed in DevTools as
  terminated, so a page can't hide code by running it in a worker that exits
  immediately.

## Install (Linux x86_64)

Download `web-instrumentation-browser-<version>-linux-x86_64.tar.xz` from the
[Releases](../../releases) page, then:

```sh
tar -xJf web-instrumentation-browser-*-linux-x86_64.tar.xz
./firefox/firefox --profile "$(mktemp -d)"
```

The `--profile` flag starts it with a fresh, throwaway profile so it doesn't
touch your regular Firefox profile. It needs the same system libraries as
Firefox (GTK 3). Only Linux x86_64 builds are published for now.

## Using it

1. Click the **API Audit** toolbar button. If it isn't shown, add it with
   *Customize Toolbar*, or open the window from the Browser Console:
   ```js
   ChromeUtils.importESModule("moz-src:///toolkit/components/apiaudit/ApiAudit.sys.mjs").ApiAudit.openWindow()
   ```
2. Press **Start** to clear previous data and record from now on, then load the
   page you want to study. **Stop** pauses and keeps the data, **Resume**
   continues, **Clear** forgets everything.
3. The sidebar groups records by tab, page load, frame and worker. Select any
   level to see everything below it.
   - **APIs** lists every API ranked by risk; expand a row to see its distinct
     calls with arguments, results and calling scripts.
   - **Code** lists all captured code; blob:/data: workers, dynamic code and
     anti-debugging code are flagged.
   - **Network** lists requests, cookie changes and the content blocking log;
     click a request for its headers, body and classification.
4. Export with **Copy all** (full JSON report of the selected page) or
   **Copy summary** (Markdown overview grouped by category, with contexts,
   captured code and hosts contacted).

### Preferences

Set these in `about:config`:

| Pref | Default | Meaning |
| --- | --- | --- |
| `privacy.apiaudit.enabled` | `true` | Record at all. |
| `privacy.apiaudit.hideDevTools` | `true` | Apply the DevTools-hiding measures above. |
| `privacy.apiaudit.maxCodeLength` | `524288` | Characters kept per captured code entry. |
| `privacy.apiaudit.retainSeconds` | `600` | How long records of closed windows are kept. |

For a raw log, start the browser with `MOZ_LOG=ApiAudit:3` (first use of each
API per window) or `MOZ_LOG=ApiAudit:5` (every sampled call).

## Limitations

- Call counts are lower bounds for builtins and getters that the JIT inlines
  or serves from a cached slot; every calling script is still seen.
- JS builtins other than the ones listed above (for example
  `Function.prototype.toString` or `Error.prototype.stack`) are not recorded.
- Values are described without running page script, so DOM objects appear
  only as their class name.
- Container queries and other conditions evaluated during selector matching
  are not recorded.
- A page that measures event-loop lag while making heavy console calls, or
  that notices the general slowdown of an attached debugger, can still detect
  DevTools.

The full technical description, including every place the Gecko source was
changed, is in
[toolkit/components/apiaudit/README.md](toolkit/components/apiaudit/README.md).

## Building from source

This repository is a fork of
[mozilla-firefox/firefox](https://github.com/mozilla-firefox/firefox); the
instrumentation is in the commits on top of upstream `main`. Building works
the same as for Firefox:

```sh
./mach bootstrap   # once, choose "Firefox for Desktop"
./mach build
./mach run
./mach package     # produces obj-*/dist/firefox-*.tar.xz
```

See the
[Firefox build documentation](https://firefox-source-docs.mozilla.org/setup/index.html)
for requirements. Tests for the instrumentation:

```sh
./mach test toolkit/components/apiaudit/tests/browser/ --headless
```

## License

The source is licensed under the
[Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/), like Firefox.
Firefox and the Firefox logos are trademarks of the Mozilla Foundation; this
project doesn't use them and isn't endorsed by Mozilla.
