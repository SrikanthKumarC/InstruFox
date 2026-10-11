/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const { ApiAudit } = ChromeUtils.importESModule(
  "moz-src:///toolkit/components/apiaudit/ApiAudit.sys.mjs"
);
const { CATEGORIES, rankApi, pageRisk, isHiddenSourceUrl } =
  ChromeUtils.importESModule(
    "moz-src:///toolkit/components/apiaudit/ApiAuditRanking.sys.mjs"
  );
const { Downloads } = ChromeUtils.importESModule(
  "resource://gre/modules/Downloads.sys.mjs"
);

const POLL_INTERVAL_MS = 2000;
const ALL = "all";

// Maps API names to the kinds of captured code they produce, so that
// expanding such an API row shows the code itself.
const CODE_KINDS_FOR_API = [
  [/^debugger\(\)$/, null],
  [/^eval\(\)$/, ["eval"]],
  [/^Function\(\)$/, ["Function"]],
  [/\.setTimeout\(\)$/, ["setTimeout"]],
  [/\.setInterval\(\)$/, ["setInterval"]],
  [/^(?:new )?WebAssembly\.\w+\(\)$/, ["wasm"]],
  [/^new (?:Shared)?Worker\(\)$/, ["worker-script"]],
  [/^ServiceWorkerContainer\.register\(\)$/, ["worker-script"]],
  [/\.importScripts\(\)$/, ["importScripts"]],
];

// Kinds of captured code that bypass normal script inspection.
const HIDDEN_CODE_KINDS = [
  "eval",
  "Function",
  "setTimeout",
  "setInterval",
  "javascript-url",
  "wasm",
];

const state = {
  windows: new Map(),
  network: { requests: [], cookies: [], contentBlocking: [] },
  openRequests: new Set(),
  selected: ALL,
  openNodes: new Set(),
  view: "apis",
  sortKey: "score",
  category: null,
  expanded: new Set(),
  openCode: new Set(),
  codeText: new Map(),
  codeRequested: new Set(),
  root: null,
  nodes: new Map(),
  renderedCodeKeys: "",
};

const $ = id => document.getElementById(id);

function el(tag, props = {}, ...children) {
  let node = document.createElement(tag);
  for (let [key, value] of Object.entries(props)) {
    if (key == "className") {
      node.className = value;
    } else if (key == "dataset") {
      Object.assign(node.dataset, value);
    } else {
      node.setAttribute(key, value);
    }
  }
  for (let child of children) {
    if (child != null) {
      node.append(child);
    }
  }
  return node;
}

const siteCache = new Map();
function siteOf(urlOrOrigin) {
  if (!urlOrOrigin) {
    return "";
  }
  let cached = siteCache.get(urlOrOrigin);
  if (cached !== undefined) {
    return cached;
  }
  let site;
  try {
    let uri = Services.io.newURI(
      urlOrOrigin.replace(/^blob:/i, "").replace(/:\d+:\d+$/, "")
    );
    try {
      site = Services.eTLD.getBaseDomain(uri);
    } catch {
      site = uri.host || uri.spec;
    }
  } catch {
    site = urlOrOrigin;
  }
  siteCache.set(urlOrOrigin, site);
  return site;
}

function riskClass(score) {
  if (score >= 80) {
    return "risk-critical";
  }
  if (score >= 50) {
    return "risk-high";
  }
  if (score >= 25) {
    return "risk-medium";
  }
  return "risk-low";
}

function pageKey(win) {
  if (win.isTop || !win.topInnerWindowId) {
    return String(win.innerWindowId);
  }
  return String(win.topInnerWindowId);
}

function topUrlOf(win) {
  if (win.topUrl) {
    return win.topUrl;
  }
  let top = state.windows.get(win.topInnerWindowId);
  return top?.url ?? win.url;
}

function contextLabel(win, context) {
  if (context.kind == "window") {
    return `${win.isTop ? "top" : "frame"} ${win.origin || win.url || "(unknown)"}`;
  }
  let label = `${context.kind} ${context.url}`;
  if (context.name) {
    label += ` "${context.name}"`;
  }
  if (context.parentUrl) {
    label += ` (spawned by ${context.parentUrl})`;
  }
  if (win.isWorker && win.serviceWorkerScope) {
    label += ` (scope ${win.serviceWorkerScope})`;
  }
  return label;
}

// Returns the CSS class flagging a context or script: hidden source
// (blob:/data:) or third-party relative to the top-level site.
function flagClass(url, topSite) {
  if (isHiddenSourceUrl(url)) {
    return "hidden-src";
  }
  return url && siteOf(url) != topSite ? "tp" : "";
}

// A view is {win, contexts}: some or all of the contexts of one window.
function allContexts(win) {
  return { win, contexts: win.contexts };
}

function aggregate(views) {
  let apis = new Map();
  for (let { win, contexts } of views) {
    let topSite = siteOf(topUrlOf(win));
    for (let context of contexts) {
      let label = contextLabel(win, context);
      let labelClass =
        context.kind == "window"
          ? flagClass(win.origin, topSite)
          : flagClass(context.url, topSite) || "worker";
      for (let api of context.apis) {
        let entry = apis.get(api.name);
        if (!entry) {
          entry = {
            name: api.name,
            count: 0,
            inWorker: false,
            inHiddenWorker: false,
            firstSeen: api.firstSeen,
            contexts: new Map(),
            args: new Set(),
            scripts: new Map(),
            calls: new Map(),
          };
          apis.set(api.name, entry);
        }
        entry.count += api.count;
        entry.firstSeen = Math.min(entry.firstSeen, api.firstSeen);
        entry.contexts.set(label, labelClass);
        if (context.kind != "window") {
          entry.inWorker = true;
          entry.inHiddenWorker ||= isHiddenSourceUrl(context.url);
        }
        for (let arg of api.args) {
          entry.args.add(arg);
        }
        for (let script of api.scripts) {
          entry.scripts.set(script, flagClass(script, topSite));
        }
        for (let call of api.calls ?? []) {
          let key = JSON.stringify([call.args, call.result]);
          let existing = entry.calls.get(key);
          if (existing) {
            existing.count += call.count;
          } else {
            entry.calls.set(key, { ...call });
          }
        }
      }
    }
  }
  return [...apis.values()].map(entry => {
    let calls = [...entry.calls.values()];
    return {
      ...entry,
      calls,
      results: [...new Set(calls.map(c => c.result).filter(Boolean))],
      ...rankApi(entry.name, [...entry.args]),
    };
  });
}

function codeKey(win, context, code) {
  return [
    win.innerWindowId,
    context.serial,
    code.kind,
    code.hash,
    code.length,
  ].join(":");
}

function codeEntries(views) {
  let entries = [];
  let seen = new Set();
  for (let { win, contexts } of views) {
    let topSite = siteOf(topUrlOf(win));
    for (let context of contexts) {
      for (let code of context.code) {
        let key = codeKey(win, context, code);
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        let hidden =
          isHiddenSourceUrl(code.url) ||
          isHiddenSourceUrl(context.url) ||
          code.antiDebug ||
          HIDDEN_CODE_KINDS.includes(code.kind);
        entries.push({
          key,
          win,
          context,
          code,
          hidden,
          label: contextLabel(win, context),
          labelClass: flagClass(context.url || win.origin, topSite),
        });
      }
    }
  }
  entries.sort(
    (a, b) => b.hidden - a.hidden || a.code.firstSeen - b.code.firstSeen
  );
  return entries;
}

// Extracts the string from a recorded argument such as
// '"x.js"', 'TrustedScriptURL "x.js"' or 'URL "https://..."'.
function argString(arg) {
  let start = arg.indexOf('"');
  let end = arg.lastIndexOf('"');
  if (start == -1 || end <= start) {
    return null;
  }
  return arg.slice(start + 1, end).replace(/\.\.\.$/, "");
}

// Returns the absolute URLs passed to aApiName from any context of aWin.
function resolvedArgUrls(win, apiName) {
  let urls = [];
  for (let context of win.contexts) {
    let base = context.kind == "window" ? win.url : context.url;
    for (let api of context.apis) {
      if (api.name != apiName) {
        continue;
      }
      for (let arg of api.args) {
        try {
          urls.push(new URL(argString(arg), base).href);
        } catch {}
      }
    }
  }
  return urls;
}

// Whether a shared or service worker belongs to one of aWindows: the
// service worker controls it, or it registered the service worker or
// connected to the shared worker.
function isLinked(worker, windows) {
  let isServiceWorker = worker.contexts.some(c => c.kind == "service-worker");
  let apiName = isServiceWorker
    ? "ServiceWorkerContainer.register()"
    : "new SharedWorker()";
  return windows.some(
    win =>
      (isServiceWorker &&
        worker.serviceWorkerId &&
        win.serviceWorkerId == worker.serviceWorkerId) ||
      resolvedArgUrls(win, apiName).includes(worker.url)
  );
}

function isClosed(win) {
  return !!(win.destroyedAt || win.gone);
}

function firstSeenOf(windows) {
  let times = windows.flatMap(w => w.contexts.map(c => c.firstSeen));
  return times.length ? Math.min(...times) : 0;
}

function makeNode(key, type, title, subtitle, views, children = []) {
  let ranked = aggregate(views);
  let code = codeEntries(views);
  let workers = views.reduce(
    (n, v) => n + v.contexts.filter(c => c.kind != "window").length,
    0
  );
  return {
    key,
    type,
    title,
    subtitle,
    views,
    children,
    ranked,
    code,
    workers,
    hiddenCode: code.filter(c => c.hidden).length,
    risk: pageRisk(ranked),
    closed: false,
  };
}

function contextNodes(windows) {
  let nodes = [];
  for (let win of windows) {
    for (let context of win.contexts) {
      let node = makeNode(
        `ctx:${win.innerWindowId}:${context.serial}`,
        context.kind == "window" ? "frame" : "worker",
        contextLabel(win, context),
        context.kind == "window" ? win.url : "",
        [{ win, contexts: [context] }]
      );
      node.closed = isClosed(win);
      node.hidden = isHiddenSourceUrl(context.url);
      nodes.push(node);
    }
  }
  return nodes;
}

// Groups every record by tab, then by page load, then by frame and worker.
// Shared and service workers are attached to the tabs of the pages they are
// linked to, or else to the tabs showing the same site.
function buildTree() {
  let windows = [...state.windows.values()].filter(w => w.contexts.length);
  let docs = new Map();
  for (let win of windows.filter(w => !w.isWorker)) {
    let key = pageKey(win);
    if (!docs.has(key)) {
      docs.set(key, { key, windows: [] });
    }
    docs.get(key).windows.push(win);
  }

  let groups = new Map();
  let groupFor = key => {
    if (!groups.has(key)) {
      groups.set(key, { key, docs: [], workers: [] });
    }
    return groups.get(key);
  };
  for (let doc of docs.values()) {
    doc.top =
      doc.windows.find(w => String(w.innerWindowId) == doc.key) ??
      doc.windows[0];
    doc.firstSeen = firstSeenOf(doc.windows);
    doc.groupKey = doc.top.browserId
      ? `tab:${doc.top.browserId}`
      : `site:${siteOf(topUrlOf(doc.top)) || doc.top.url}`;
    groupFor(doc.groupKey).docs.push(doc);
  }
  for (let worker of windows.filter(w => w.isWorker)) {
    let keys = new Set(
      [...docs.values()]
        .filter(doc => isLinked(worker, doc.windows))
        .map(doc => doc.groupKey)
    );
    if (!keys.size) {
      let site = siteOf(worker.url);
      for (let group of groups.values()) {
        if (group.docs.some(doc => siteOf(topUrlOf(doc.top)) == site)) {
          keys.add(group.key);
        }
      }
      if (!keys.size) {
        keys.add(`site:${site}`);
      }
    }
    for (let key of keys) {
      groupFor(key).workers.push(worker);
    }
  }

  let groupNodes = [];
  for (let group of groups.values()) {
    group.docs.sort((a, b) => b.firstSeen - a.firstSeen);
    let latest = group.docs[0]?.top;
    let docNodes = group.docs.map(doc => {
      let url = topUrlOf(doc.top);
      let node = makeNode(
        `doc:${doc.key}`,
        "doc",
        url,
        new Date(doc.firstSeen).toLocaleTimeString(),
        doc.windows.map(allContexts),
        contextNodes(doc.windows)
      );
      node.closed = isClosed(doc.top);
      return node;
    });
    if (group.workers.length) {
      docNodes.push(
        makeNode(
          `shared:${group.key}`,
          "doc",
          "Shared & service workers",
          "",
          group.workers.map(allContexts),
          contextNodes(group.workers)
        )
      );
    }
    let site = latest
      ? siteOf(topUrlOf(latest))
      : siteOf(group.workers[0]?.url);
    let isTab = group.key.startsWith("tab:");
    let title =
      (isTab && group.docs.find(d => d.top.tab?.title)?.top.tab.title) ||
      site ||
      "(unknown)";
    let views = [
      ...group.docs.flatMap(doc => doc.windows.map(allContexts)),
      ...group.workers.map(allContexts),
    ];
    let node = makeNode(
      `group:${group.key}`,
      "group",
      title,
      [
        isTab ? "tab" : "site",
        latest?.tab?.url ?? (latest ? topUrlOf(latest) : site),
      ].join(" · "),
      views,
      docNodes
    );
    node.closed = group.docs.every(doc => isClosed(doc.top));
    node.loads = group.docs.length;
    groupNodes.push(node);
  }
  groupNodes.sort(
    (a, b) =>
      a.closed - b.closed ||
      b.risk.score - a.risk.score ||
      a.title.localeCompare(b.title)
  );

  let root = makeNode(
    ALL,
    "all",
    "All tabs",
    `${groupNodes.length} tabs and sites`,
    windows.map(allContexts),
    groupNodes
  );
  let nodes = new Map();
  let index = (node, parent) => {
    node.parent = parent;
    nodes.set(node.key, node);
    node.children.forEach(child => index(child, node));
  };
  index(root, null);
  state.root = root;
  state.nodes = nodes;
}

function selectedNode() {
  return state.nodes.get(state.selected) ?? state.root;
}

function select(node) {
  state.selected = node.key;
  state.category = null;
  for (let n = node; n; n = n.parent) {
    state.openNodes.add(n.key);
  }
  render();
}

function renderTree() {
  let items = [];
  let walk = (node, depth) => {
    let open = node.type == "all" || state.openNodes.has(node.key);
    let extras = [];
    if (node.type == "group" && node.loads > 1) {
      extras.push(`${node.loads} page loads`);
    }
    if (node.workers && node.type != "worker") {
      extras.push(`${node.workers} worker${node.workers == 1 ? "" : "s"}`);
    }
    if (node.hiddenCode) {
      extras.push(`${node.hiddenCode} hidden code`);
    }
    let twisty = "";
    if (node.children.length) {
      twisty = open ? "\u25BE" : "\u25B8";
    }
    let toggle = el(
      "span",
      { className: node.children.length ? "twisty" : "twisty leaf" },
      twisty
    );
    let li = el(
      "li",
      {
        className: [
          `node-${node.type}`,
          node.key == state.selected ? "selected" : "",
          node.closed ? "closed" : "",
        ].join(" "),
        title: node.type == "frame" ? node.subtitle : node.title,
        dataset: { key: node.key },
      },
      toggle,
      el(
        "span",
        { className: `badge ${riskClass(node.risk.score)}` },
        String(node.risk.score)
      ),
      el(
        "span",
        {
          className: `page-title ${node.hidden ? "hidden-src" : ""}`,
        },
        node.title
      ),
      el(
        "span",
        { className: "page-url" },
        [node.subtitle, ...extras].filter(Boolean).join(" · ")
      )
    );
    // The window's CSP blocks style attributes, so indent through CSSOM.
    li.style.paddingInlineStart = `${8 + depth * 14}px`;
    toggle.addEventListener("click", event => {
      event.stopPropagation();
      if (state.openNodes.has(node.key)) {
        state.openNodes.delete(node.key);
      } else {
        state.openNodes.add(node.key);
      }
      renderTree();
    });
    li.addEventListener("click", () => select(node));
    items.push(li);
    if (open) {
      node.children.forEach(child => walk(child, depth + 1));
    }
  };
  walk(state.root, 0);
  $("pages").replaceChildren(...items);
}

function matchesFilter(values, text) {
  if (!text) {
    return true;
  }
  return values.join("\n").toLowerCase().includes(text);
}

function sortRows(rows) {
  let key = state.sortKey;
  rows.sort((a, b) => {
    switch (key) {
      case "name":
        return a.name.localeCompare(b.name);
      case "category":
        return (
          a.categoryLabel.localeCompare(b.categoryLabel) || b.score - a.score
        );
      case "count":
        return b.count - a.count;
      default:
        return b.score - a.score || b.count - a.count;
    }
  });
}

// aEntries is an iterable of [value, className].
function listCell(entries, expanded) {
  let td = el("td");
  let items = [...entries];
  let shown = expanded ? items : items.slice(0, 1);
  shown.forEach(([value, className], i) => {
    if (i) {
      td.append(expanded ? "\n" : ", ");
    }
    td.append(el("span", { className: className ?? "" }, value));
  });
  if (!expanded && items.length > 1) {
    td.append(` +${items.length - 1}`);
  }
  td.title = items.map(([value]) => value).join("\n");
  return td;
}

// Returns a filter selecting the captured code related to an API row, or
// null if the API has no related code.
function codeFilterForApi(name) {
  for (let [regex, kinds] of CODE_KINDS_FOR_API) {
    if (regex.test(name)) {
      return kinds
        ? entry => kinds.includes(entry.code.kind)
        : entry => entry.code.antiDebug;
    }
  }
  return null;
}

// Renders one captured piece of code: a header and, once its text has been
// loaded, the full source with a copy button.
function codeBlock(entry, { collapsible, onChange }) {
  let { code } = entry;
  let loaded = state.codeText.get(entry.key);
  let unit = code.encoding == "base64" ? "bytes" : "chars";
  let size = `${code.length.toLocaleString()} ${unit}${code.truncated ? " (truncated)" : ""}`;
  let header = [
    el("span", { className: "code-kind" }, code.kind),
    code.antiDebug
      ? el("span", { className: "anti-debug" }, "anti-debugging")
      : null,
    el(
      "span",
      { className: isHiddenSourceUrl(code.url) ? "hidden-src" : "" },
      code.url || "(no URL)"
    ),
    el(
      "span",
      { className: "code-meta" },
      `${size} · run ${code.count}× · ${new Date(code.firstSeen).toLocaleTimeString()}`
    ),
    el("span", { className: `code-context ${entry.labelClass}` }, entry.label),
  ];
  let body = el("div", { className: "code-body" });
  if (!loaded) {
    body.append(
      state.codeRequested.has(entry.key)
        ? "The code is no longer available."
        : "Loading..."
    );
  } else {
    let isBinary = code.encoding == "base64";
    let copy = el("button", {}, isBinary ? "Copy base64" : "Copy code");
    copy.addEventListener("click", event => {
      event.stopPropagation();
      copyToClipboard(loaded.text, `${code.kind} source`);
    });
    let actions = el("div", { className: "code-actions" }, copy);
    if (isBinary) {
      let save = el("button", {}, "Save .wasm");
      save.addEventListener("click", event => {
        event.stopPropagation();
        saveBinary(loaded.text, `apiaudit-${code.hash >>> 0}.wasm`);
      });
      actions.append(save);
    }
    actions.append(
      el(
        "span",
        { className: "code-meta" },
        isBinary
          ? `WebAssembly module, base64-encoded · SHA-256 of the base64 ${loaded.sha256}`
          : `SHA-256 ${loaded.sha256}`
      )
    );
    body.append(actions, el("pre", {}, loaded.text));
  }

  if (!collapsible) {
    return el(
      "div",
      { className: `code-entry ${entry.hidden ? "hidden" : ""}` },
      el("div", { className: "code-header" }, ...header),
      body
    );
  }
  let details = el("details", { className: entry.hidden ? "hidden" : "" });
  details.open = state.openCode.has(entry.key);
  details.append(el("summary", {}, ...header));
  if (details.open) {
    details.append(body);
  }
  details.addEventListener("toggle", async () => {
    if (details.open == state.openCode.has(entry.key)) {
      return;
    }
    if (details.open) {
      state.openCode.add(entry.key);
      await ensureCodeText([entry]);
    } else {
      state.openCode.delete(entry.key);
    }
    onChange();
  });
  return details;
}

async function ensureCodeText(entries) {
  let missing = entries.filter(
    entry =>
      !state.codeText.has(entry.key) && !state.codeRequested.has(entry.key)
  );
  if (missing.length) {
    missing.forEach(entry => state.codeRequested.add(entry.key));
    await loadCodeText();
  }
}

function needsCodeText(entries) {
  return entries.some(
    entry =>
      !state.codeText.has(entry.key) && !state.codeRequested.has(entry.key)
  );
}

function renderTable(node) {
  let minScore = Number($("min-score").value);
  let text = $("filter").value.trim().toLowerCase();
  let rows = node.ranked.filter(
    api =>
      api.score >= minScore &&
      (!state.category || api.category == state.category) &&
      matchesFilter(
        [
          api.name,
          api.categoryLabel,
          api.reason,
          ...api.contexts.keys(),
          ...api.args,
          ...api.results,
          ...api.scripts.keys(),
        ],
        text
      )
  );
  sortRows(rows);

  for (let th of document.querySelectorAll("th[data-sort]")) {
    th.classList.toggle("sorted", th.dataset.sort == state.sortKey);
  }

  let missingCode = [];
  $("rows").replaceChildren(
    ...rows.flatMap(api => {
      let expanded = state.expanded.has(api.name);
      let codeFilter = codeFilterForApi(api.name);
      let kind = api.kind;
      if (api.inHiddenWorker) {
        kind += " · blob/data worker";
      } else if (api.inWorker) {
        kind += " · worker";
      }
      let tr = el(
        "tr",
        {
          className: [expanded ? "expanded" : "", codeFilter ? "has-code" : ""]
            .join(" ")
            .trim(),
          dataset: { api: api.name },
        },
        el(
          "td",
          { className: "num" },
          el(
            "span",
            { className: `badge ${riskClass(api.score)}` },
            String(api.score)
          )
        ),
        el(
          "td",
          {},
          api.categoryLabel,
          api.reason ? el("span", { className: "reason" }, api.reason) : null
        ),
        el(
          "td",
          { className: "api" },
          api.key.replace(/=$/, ""),
          el(
            "span",
            { className: api.inHiddenWorker ? "kind hidden-src" : "kind" },
            kind
          )
        ),
        el("td", { className: "num" }, api.count.toLocaleString()),
        listCell(api.contexts, expanded),
        listCell(
          [...api.args].map(a => [a, ""]),
          expanded
        ),
        listCell(
          api.results.map(r => [r, ""]),
          expanded
        ),
        listCell(api.scripts, expanded)
      );
      tr.addEventListener("click", () => {
        if (expanded) {
          state.expanded.delete(api.name);
        } else {
          state.expanded.add(api.name);
        }
        renderTable(selectedNode());
      });
      if (!expanded || (!codeFilter && !api.calls.length)) {
        return [tr];
      }

      let cell = el("td", { colspan: "8" });
      if (api.calls.length) {
        cell.append(callsTable(api.calls));
      }
      if (codeFilter) {
        let entries = node.code.filter(codeFilter);
        missingCode.push(...entries);
        if (!entries.length) {
          cell.append("No code was captured for this call.");
        }
        for (let entry of entries) {
          cell.append(codeBlock(entry, { collapsible: false }));
        }
      }
      return [tr, el("tr", { className: "code-row" }, cell)];
    })
  );

  if (needsCodeText(missingCode)) {
    ensureCodeText(missingCode).then(() => renderTable(selectedNode()));
  }

  let hidden = node.ranked.length - rows.length;
  $("status").textContent =
    `${rows.length} APIs shown, ${hidden} hidden by filters. ` +
    `Expand a row to see each distinct call with its arguments and result, ` +
    `and the code that eval, Function, setTimeout, Worker and WebAssembly ran. ` +
    `Purple: third-party. Orange: blob:/data: code.`;
}

// Lists the distinct sampled calls of an API: all their arguments, what they
// returned (or what the returned promise settled with) and who called.
function callsTable(calls) {
  let rows = calls.map(call =>
    el(
      "tr",
      {},
      el("td", {}, call.args.join(", ")),
      el("td", {}, call.result),
      el("td", { className: "num" }, call.count.toLocaleString()),
      el("td", {}, call.script)
    )
  );
  return el(
    "table",
    { className: "calls" },
    el(
      "thead",
      {},
      el(
        "tr",
        {},
        el("th", {}, "Arguments"),
        el("th", {}, "Result"),
        el("th", { className: "num" }, "Calls"),
        el("th", {}, "Caller")
      )
    ),
    el("tbody", {}, ...rows)
  );
}

// Single-bit nsIWebProgressListener STATE_* flags used in content blocking
// logs, by name.
const BLOCKING_STATES = Object.entries(Ci.nsIWebProgressListener)
  .filter(
    ([name, value]) =>
      /^STATE_(?:BLOCKED|LOADED|COOKIES|REPLACED|ALLOWED|PURGED)_/.test(name) &&
      Number.isInteger(value) &&
      value > 0 &&
      (value & (value - 1)) == 0
  )
  .map(([name, value]) => [name.slice("STATE_".length).toLowerCase(), value]);

function blockingStateNames(stateBits) {
  return BLOCKING_STATES.filter(([, bit]) => stateBits & bit).map(
    ([name]) => name
  );
}

function headerValue(headers, name) {
  name = name.toLowerCase();
  return headers.find(([n]) => n.toLowerCase() == name)?.[1] ?? null;
}

// Returns the requests, cookie changes and content blocking logs that belong
// to a tree node: its tabs, its windows, and the workers of its sites.
function networkFor(node) {
  let { requests, cookies, contentBlocking } = state.network;
  if (node.type == "all") {
    return { requests, cookies, contentBlocking };
  }
  let wins = node.views.map(v => v.win);
  let browserIds = new Set(wins.map(w => w.browserId).filter(Boolean));
  let windowIds = new Set(
    wins.filter(w => !w.isWorker).map(w => w.innerWindowId)
  );
  let documentUrls = new Set(wins.filter(w => !w.isWorker).map(w => w.url));
  let workerSites = new Set(
    wins.filter(w => w.isWorker).map(w => siteOf(w.url))
  );
  let fromWorkerSite = r =>
    !r.browserId && workerSites.has(siteOf(r.triggeringOrigin));
  let matchRequest =
    node.type == "group"
      ? r => browserIds.has(r.browserId) || fromWorkerSite(r)
      : r =>
          windowIds.has(r.innerWindowId) ||
          (["document", "subdocument"].includes(r.type) &&
            browserIds.has(r.browserId) &&
            documentUrls.has(r.url)) ||
          fromWorkerSite(r);
  return {
    requests: requests.filter(matchRequest),
    cookies: cookies.filter(c => browserIds.has(c.browserId)),
    contentBlocking: contentBlocking.filter(l => browserIds.has(l.browserId)),
  };
}

function isThirdPartyRequest(request) {
  let top = request.topUrl ?? request.triggeringOrigin;
  return !!top && siteOf(request.url) != siteOf(top);
}

function classificationLabel(request) {
  let c = request.classification;
  if (!c) {
    return "";
  }
  let flags = c.thirdParty.length ? c.thirdParty : c.flags;
  return [
    ...flags,
    ...(c.thirdPartyTracker ? ["third-party tracker"] : []),
  ].join(", ");
}

function bodySize(request) {
  let body = request.requestBody;
  if (!body) {
    return "";
  }
  if (body.unreadable) {
    return "?";
  }
  return `${body.length.toLocaleString()} B`;
}

function headersBlock(title, headers) {
  return el(
    "div",
    { className: "request-section" },
    el("h4", {}, title),
    el(
      "pre",
      {},
      headers.length
        ? headers.map(([name, value]) => `${name}: ${value}`).join("\n")
        : "(none)"
    )
  );
}

function requestDetails(request) {
  let parts = [
    el(
      "div",
      { className: "request-section" },
      el("h4", {}, "Request"),
      el(
        "pre",
        {},
        [
          `URL: ${request.url}`,
          `Referrer: ${request.referrer ?? "(none)"}`,
          `Initiator origin: ${request.triggeringOrigin ?? "(none)"}`,
          `Top-level page: ${request.topUrl ?? "(none)"}`,
          `Remote address: ${request.remoteAddress ?? "(unknown)"}`,
          `From cache: ${request.fromCache}`,
        ].join("\n")
      )
    ),
    headersBlock("Request headers", request.requestHeaders),
  ];
  let body = request.requestBody;
  if (body) {
    parts.push(
      el(
        "div",
        { className: "request-section" },
        el(
          "h4",
          {},
          `Request body${body.encoding ? ` (${body.encoding})` : ""}` +
            `${body.truncated ? " (truncated)" : ""}`
        ),
        el(
          "pre",
          {},
          body.unreadable ? "(the body could not be read)" : body.text
        )
      )
    );
  }
  parts.push(headersBlock("Response headers", request.responseHeaders));
  if (request.classification) {
    let c = request.classification;
    parts.push(
      el(
        "div",
        { className: "request-section" },
        el("h4", {}, "Tracking protection classification"),
        el(
          "pre",
          {},
          [
            `Flags: ${c.flags.join(", ") || "(none)"}`,
            `As first party: ${c.firstParty.join(", ") || "(none)"}`,
            `As third party: ${c.thirdParty.join(", ") || "(none)"}`,
            `Third-party tracker: ${c.thirdPartyTracker}`,
            `Matched list: ${c.matchedList ?? "(none)"}`,
            `Matched tracking lists: ${c.matchedTrackingLists.join(", ") || "(none)"}`,
          ].join("\n")
        )
      )
    );
  }
  return el("div", { className: "request-details" }, ...parts);
}

function renderNetwork(node) {
  let text = $("filter").value.trim().toLowerCase();
  let { requests, cookies, contentBlocking } = networkFor(node);
  let shownRequests = requests.filter(r =>
    matchesFilter(
      [
        r.url,
        r.method,
        r.type,
        classificationLabel(r),
        r.requestBody?.text ?? "",
        ...r.requestHeaders.flat(),
        ...r.responseHeaders.flat(),
      ],
      text
    )
  );
  $("request-rows").replaceChildren(
    ...shownRequests.flatMap(request => {
      let key = `${request.id}:${request.time}`;
      let open = state.openRequests.has(key);
      let cookieHeader = headerValue(request.requestHeaders, "cookie");
      let tr = el(
        "tr",
        { className: open ? "expanded" : "" },
        el("td", {}, new Date(request.time).toLocaleTimeString()),
        el("td", {}, request.method),
        el("td", {}, request.type),
        el("td", { className: "num" }, String(request.status ?? "")),
        el(
          "td",
          {
            className: isThirdPartyRequest(request) ? "tp" : "",
            title: request.url,
          },
          request.url
        ),
        el("td", { className: "classified" }, classificationLabel(request)),
        el("td", { className: "num" }, bodySize(request)),
        el(
          "td",
          { title: cookieHeader ?? "" },
          cookieHeader ? plural(cookieHeader.split(";").length, "cookie") : ""
        )
      );
      tr.addEventListener("click", () => {
        if (open) {
          state.openRequests.delete(key);
        } else {
          state.openRequests.add(key);
        }
        renderNetwork(selectedNode());
      });
      if (!open) {
        return [tr];
      }
      return [
        tr,
        el(
          "tr",
          { className: "code-row" },
          el("td", { colspan: "8" }, requestDetails(request))
        ),
      ];
    })
  );

  $("cookie-rows").replaceChildren(
    ...cookies
      .filter(c =>
        matchesFilter([c.host, c.name, c.value, c.action].map(String), text)
      )
      .map(c =>
        el(
          "tr",
          {},
          el("td", {}, new Date(c.time).toLocaleTimeString()),
          el("td", {}, c.action),
          el("td", { className: c.thirdParty ? "tp" : "" }, c.host ?? ""),
          el("td", {}, c.name ?? ""),
          el("td", { title: c.value ?? "" }, c.value ?? ""),
          el(
            "td",
            {},
            c.expiry ? new Date(c.expiry).toLocaleString() : "session"
          ),
          el(
            "td",
            {},
            [
              c.secure ? "secure" : "",
              c.httpOnly ? "httpOnly" : "",
              c.sameSite ? `sameSite=${c.sameSite}` : "",
              c.partitioned ? "partitioned" : "",
              c.partitionKey ? `partition ${c.partitionKey}` : "",
              c.thirdParty ? "third-party" : "",
            ]
              .filter(Boolean)
              .join(" ")
          )
        )
      )
  );

  $("blocking-log").replaceChildren(
    ...contentBlocking.map(({ url, log }) =>
      el(
        "div",
        { className: "request-section" },
        el("h4", {}, url ?? "(unknown page)"),
        el(
          "pre",
          {},
          Object.entries(log)
            .map(
              ([origin, events]) =>
                `${origin}: ` +
                events
                  .map(([bits, blocked, count]) =>
                    [
                      blocked ? "blocked" : "allowed",
                      ...blockingStateNames(bits),
                      count > 1 ? `x${count}` : "",
                    ]
                      .filter(Boolean)
                      .join(" ")
                  )
                  .join("; ")
            )
            .join("\n")
        )
      )
    )
  );

  let summary = networkSummary({ requests, cookies });
  $("network-summary").textContent =
    `${plural(requests.length, "request")} · ` +
    `${plural(summary.thirdPartyHosts.size, "third-party host")} · ` +
    `${plural(summary.trackers.size, "host")} classified by tracking protection · ` +
    `${plural(summary.withBody, "request")} with a body · ` +
    `${plural(cookies.length, "cookie change")}`;
  $("status").textContent =
    `${shownRequests.length} of ${requests.length} requests shown. ` +
    `Click a request for its headers, body and classification. ` +
    `Purple: third-party.`;
}

function networkSummary({ requests, cookies }) {
  let thirdPartyHosts = new Set();
  let trackers = new Map();
  let hosts = new Map();
  let withBody = 0;
  for (let request of requests) {
    let host;
    try {
      host = new URL(request.url).host;
    } catch {
      host = request.url;
    }
    let entry = hosts.get(host) ?? {
      host,
      requests: 0,
      thirdParty: false,
      withBody: 0,
      cookiesSent: 0,
      setCookies: 0,
      classification: new Set(),
      types: new Set(),
    };
    entry.requests++;
    entry.types.add(request.type);
    if (isThirdPartyRequest(request)) {
      entry.thirdParty = true;
      thirdPartyHosts.add(host);
    }
    if (request.requestBody) {
      entry.withBody++;
      withBody++;
    }
    if (headerValue(request.requestHeaders, "cookie")) {
      entry.cookiesSent++;
    }
    if (headerValue(request.responseHeaders, "set-cookie")) {
      entry.setCookies++;
    }
    let label = classificationLabel(request);
    if (label) {
      entry.classification.add(label);
      trackers.set(host, label);
    }
    hosts.set(host, entry);
  }
  let cookieHosts = new Set(cookies.map(c => c.host).filter(Boolean));
  return { hosts, thirdPartyHosts, trackers, withBody, cookieHosts };
}

function saveBinary(base64, name) {
  Downloads.getPreferredDownloadsDirectory().then(async dir => {
    let path = PathUtils.join(dir, name);
    await IOUtils.write(
      path,
      Uint8Array.from(atob(base64), c => c.charCodeAt(0))
    );
    $("status").textContent = `Saved to ${path}`;
  });
}

async function sha256(text) {
  let digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// Fetches the code text of every context and caches it by codeKey.
async function loadCodeText() {
  let windows = await ApiAudit.collect({ includeCode: true });
  for (let win of windows) {
    for (let context of win.contexts) {
      for (let code of context.code) {
        let key = codeKey(win, context, code);
        if (!state.codeText.has(key)) {
          state.codeText.set(key, {
            text: code.text,
            sha256: code.text ? await sha256(code.text) : "",
          });
        }
      }
    }
  }
}

function copyToClipboard(text, what) {
  Cc["@mozilla.org/widget/clipboardhelper;1"]
    .getService(Ci.nsIClipboardHelper)
    .copyString(text);
  $("status").textContent =
    `Copied ${what} (${text.length.toLocaleString()} characters) to the clipboard.`;
}

function renderCode(node) {
  let text = $("filter").value.trim().toLowerCase();
  let entries = node.code.filter(entry =>
    matchesFilter(
      [
        entry.code.kind,
        entry.code.url,
        entry.label,
        state.codeText.get(entry.key)?.text ?? "",
      ],
      text
    )
  );
  state.renderedCodeKeys = node.code.map(entry => entry.key).join();
  $("code-list").replaceChildren(
    ...entries.map(entry =>
      codeBlock(entry, {
        collapsible: true,
        onChange: () => renderCode(selectedNode()),
      })
    )
  );
  $("status").textContent =
    `${entries.length} code entries. Orange: blob:/data: workers and ` +
    `eval/Function/timer strings, which bypass normal script inspection.`;
}

function renderSummary(page) {
  let frames = page.views.filter(v =>
    v.contexts.some(c => c.kind == "window")
  ).length;
  let high = page.risk.categories.map(c => CATEGORIES[c]).join(", ");
  $("page-summary").textContent =
    `${page.title} · Risk ${page.risk.score} · ${page.ranked.length} distinct APIs · ` +
    `${frames} window${frames == 1 ? "" : "s"} · ${page.workers} worker${page.workers == 1 ? "" : "s"}` +
    (high ? ` · high-signal: ${high}` : "");

  let byCategory = new Map();
  for (let api of page.ranked) {
    if (api.score == 0) {
      continue;
    }
    let entry = byCategory.get(api.category) ?? { max: 0, count: 0 };
    entry.max = Math.max(entry.max, api.score);
    entry.count++;
    byCategory.set(api.category, entry);
  }
  let chips = [...byCategory.entries()].sort((a, b) => b[1].max - a[1].max);
  $("categories").replaceChildren(
    ...chips.map(([category, { max, count }]) => {
      let chip = el(
        "span",
        { className: `chip ${state.category == category ? "active" : ""}` },
        el("span", { className: `badge ${riskClass(max)}` }, String(max)),
        ` ${CATEGORIES[category]} (${count})`
      );
      chip.addEventListener("click", () => {
        state.category = state.category == category ? null : category;
        state.view = "apis";
        render();
      });
      return chip;
    })
  );
}

function renderView(page) {
  for (let button of document.querySelectorAll("#views button")) {
    button.classList.toggle("active", button.dataset.view == state.view);
  }
  $("view-code").textContent = `Code (${page.code.length})`;
  $("view-network").textContent =
    `Network (${networkFor(page).requests.length})`;
  $("apis-view").hidden = state.view != "apis";
  $("code-view").hidden = state.view != "code";
  $("network-view").hidden = state.view != "network";
  if (state.view == "apis") {
    renderTable(page);
  } else if (state.view == "network") {
    renderNetwork(page);
  } else {
    renderCode(page);
  }
}

function render({ fromPoll = false } = {}) {
  renderSessionControls();
  buildTree();
  renderTree();
  let page = selectedNode();
  state.selected = page.key;
  renderSummary(page);
  if (fromPoll) {
    // Keep text selections and scroll positions in code while polling.
    let codeKeys = page.code.map(entry => entry.key).join();
    if (
      (state.view == "code" && codeKeys == state.renderedCodeKeys) ||
      (state.view == "network" && state.openRequests.size) ||
      !window.getSelection().isCollapsed
    ) {
      return;
    }
  }
  renderView(page);
}

async function refresh({ fromPoll = false } = {}) {
  let windows;
  try {
    windows = await ApiAudit.collect();
    state.network = ApiAudit.collectNetwork();
  } catch (e) {
    $("status").textContent = `Failed to collect records: ${e}`;
    return;
  }
  let seen = new Set();
  for (let win of windows) {
    seen.add(win.innerWindowId);
    state.windows.set(win.innerWindowId, win);
  }
  for (let [id, win] of state.windows) {
    if (!seen.has(id)) {
      win.gone = true;
    }
  }
  render({ fromPoll });
}

// Builds a report of the selected page, including the captured code.
async function buildReport() {
  await refresh();
  await loadCodeText();
  let page = selectedNode();
  return {
    exportedAt: new Date().toISOString(),
    session: {
      recording: ApiAudit.enabled,
      start: ApiAudit.session.start
        ? new Date(ApiAudit.session.start).toISOString()
        : null,
      stop: ApiAudit.session.stop
        ? new Date(ApiAudit.session.stop).toISOString()
        : null,
    },
    page: {
      title: page.title,
      type: page.type,
      details: page.subtitle,
      risk: page.risk,
      workers: page.workers,
    },
    apis: page.ranked
      .toSorted((a, b) => b.score - a.score || b.count - a.count)
      .map(api => ({
        name: api.name,
        score: api.score,
        category: api.category,
        reason: api.reason,
        count: api.count,
        contexts: [...api.contexts.keys()],
        args: [...api.args],
        results: api.results,
        scripts: [...api.scripts.keys()],
        calls: api.calls,
      })),
    network: networkFor(page),
    code: page.code.map(entry => ({
      kind: entry.code.kind,
      encoding: entry.code.encoding ?? "text",
      url: entry.code.url,
      context: entry.label,
      hidden: entry.hidden,
      length: entry.code.length,
      truncated: entry.code.truncated,
      count: entry.code.count,
      firstSeen: new Date(entry.code.firstSeen).toISOString(),
      sha256: state.codeText.get(entry.key)?.sha256 ?? "",
      text: state.codeText.get(entry.key)?.text ?? "",
    })),
    windows: [...new Set(page.views.map(v => v.win))].map(win => ({
      innerWindowId: win.innerWindowId,
      url: win.url,
      origin: win.origin,
      isTop: win.isTop,
      isWorker: win.isWorker,
      serviceWorkerId: win.serviceWorkerId,
      serviceWorkerScope: win.serviceWorkerScope,
      serviceWorkerUrl: win.serviceWorkerUrl,
      contexts: win.contexts.map(context => ({
        kind: context.kind,
        url: context.url,
        name: context.name,
        parentUrl: context.parentUrl,
      })),
    })),
  };
}

async function exportJSON() {
  let report = await buildReport();
  let dir = await Downloads.getPreferredDownloadsDirectory();
  let path = PathUtils.join(dir, `apiaudit-${Date.now()}.json`);
  await IOUtils.writeJSON(path, report);
  $("status").textContent = `Exported to ${path}`;
}

async function copyAll() {
  let report = await buildReport();
  copyToClipboard(
    JSON.stringify(report, null, 2),
    `the report for "${report.page.title}"`
  );
}

function sessionDescription() {
  let { start, stop } = ApiAudit.session;
  let time = t => new Date(t).toLocaleString();
  if (ApiAudit.enabled) {
    return start
      ? `recording since ${time(start)} (${formatDuration(Date.now() - start)})`
      : "recording since the browser started";
  }
  if (stop && start) {
    return `${time(start)} to ${time(stop)} (${formatDuration(stop - start)})`;
  }
  return stop ? `stopped at ${time(stop)}` : "stopped";
}

// Escapes a value for a Markdown table cell and shortens it.
function cell(value, max = 120) {
  let text = String(value).replace(/\s+/g, " ");
  if (text.length > max) {
    text = text.slice(0, max - 3) + "...";
  }
  return text.replace(/\|/g, "\\|");
}

function plural(count, word) {
  return `${count.toLocaleString()} ${word}${count == 1 ? "" : "s"}`;
}

// Builds a Markdown summary of the selected node: every API with its call
// count, grouped by privacy category, plus the contexts and captured code.
function buildSummary(node) {
  let apis = node.ranked.toSorted(
    (a, b) => b.score - a.score || b.count - a.count
  );
  let totalCalls = apis.reduce((n, api) => n + api.count, 0);
  let contexts = node.views.flatMap(({ win, contexts: list }) =>
    list.map(context => ({ win, context }))
  );
  let frames = contexts.filter(c => c.context.kind == "window").length;
  let lines = [];
  lines.push(`# API Audit summary: ${node.title}`, "");
  if (node.subtitle) {
    lines.push(`- Selection: ${node.type} (${node.subtitle})`);
  }
  lines.push(
    `- Session: ${sessionDescription()}`,
    `- Generated: ${new Date().toLocaleString()}`,
    `- Risk score: ${node.risk.score}/100`,
    `- ${plural(apis.length, "distinct API")}, ${plural(totalCalls, "call")}`,
    `- ${plural(frames, "frame")}, ${plural(node.workers, "worker")}, ` +
      `${plural(node.code.length, "captured code entry")} ` +
      `(${node.hiddenCode} hidden)`
  );
  if (node.risk.categories.length) {
    lines.push(
      `- High-signal categories: ${node.risk.categories
        .map(c => CATEGORIES[c])
        .join(", ")}`
    );
  }

  lines.push("", "## Contexts", "");
  for (let { win, context } of contexts) {
    let topSite = siteOf(topUrlOf(win));
    let url = context.kind == "window" ? win.origin || win.url : context.url;
    let flags = [];
    if (isHiddenSourceUrl(url)) {
      flags.push("blob/data");
    } else if (url && siteOf(url) != topSite) {
      flags.push("third-party");
    }
    if (isClosed(win)) {
      flags.push("closed");
    }
    let calls = context.apis.reduce((n, api) => n + api.count, 0);
    lines.push(
      `- ${contextLabel(win, context)}${flags.length ? ` [${flags.join(", ")}]` : ""}: ` +
        `${plural(context.apis.length, "API")}, ${plural(calls, "call")}`
    );
  }

  let byCategory = new Map();
  for (let api of apis.filter(a => a.score > 0)) {
    if (!byCategory.has(api.category)) {
      byCategory.set(api.category, []);
    }
    byCategory.get(api.category).push(api);
  }
  lines.push("", "## Privacy-relevant APIs");
  if (!byCategory.size) {
    lines.push("", "None.");
  }
  for (let [category, list] of byCategory) {
    let calls = list.reduce((n, api) => n + api.count, 0);
    lines.push(
      "",
      `### ${CATEGORIES[category]} (max score ${list[0].score}, ` +
        `${plural(list.length, "API")}, ${plural(calls, "call")})`,
      "",
      "| Score | API | Kind | Calls | Contexts | Arguments | Results | Callers |",
      "| ---: | --- | --- | ---: | --- | --- | --- | --- |"
    );
    for (let api of list) {
      let args = [...api.args];
      let results = api.results;
      let scripts = [...api.scripts.keys()];
      let where = [...api.contexts.keys()];
      lines.push(
        `| ${api.score} | ${cell(api.key.replace(/=$/, ""))}` +
          `${api.reason ? ` (${cell(api.reason)})` : ""} | ${api.kind} | ` +
          `${api.count.toLocaleString()} | ` +
          `${cell(where.slice(0, 2).join("; "))}` +
          `${where.length > 2 ? ` +${where.length - 2}` : ""} | ` +
          `${cell(args.slice(0, 3).join(", "), 160)}` +
          `${args.length > 3 ? ` +${args.length - 3}` : ""} | ` +
          `${cell(results.slice(0, 3).join(", "), 160)}` +
          `${results.length > 3 ? ` +${results.length - 3}` : ""} | ` +
          `${cell(scripts.slice(0, 2).join("; "))}` +
          `${scripts.length > 2 ? ` +${scripts.length - 2}` : ""} |`
      );
    }
  }

  let noise = apis.filter(a => a.score == 0);
  if (noise.length) {
    let calls = noise.reduce((n, api) => n + api.count, 0);
    lines.push(
      "",
      `## Other APIs (${plural(noise.length, "API")}, ${plural(calls, "call")})`,
      "",
      "| API | Kind | Calls |",
      "| --- | --- | ---: |"
    );
    for (let api of noise.toSorted((a, b) => b.count - a.count)) {
      lines.push(
        `| ${cell(api.key.replace(/=$/, ""))} | ${api.kind} | ${api.count.toLocaleString()} |`
      );
    }
  }

  if (node.code.length) {
    lines.push(
      "",
      "## Captured code",
      "",
      "| Kind | Source | Size | Runs | Context |",
      "| --- | --- | ---: | ---: | --- |"
    );
    for (let { code, label, hidden } of node.code) {
      lines.push(
        `| ${code.kind}${hidden ? " (hidden)" : ""}` +
          `${code.antiDebug ? " (anti-debugging)" : ""} | ${cell(code.url || "(no URL)")} | ` +
          `${code.length.toLocaleString()}${code.truncated ? " (truncated)" : ""} | ` +
          `${code.count.toLocaleString()} | ${cell(label)} |`
      );
    }
    lines.push("", "Use Copy all for the full code text.");
  }

  let network = networkFor(node);
  if (network.requests.length || network.cookies.length) {
    let summary = networkSummary(network);
    lines.push(
      "",
      "## Network",
      "",
      `- ${plural(network.requests.length, "request")} to ` +
        `${plural(summary.hosts.size, "host")} ` +
        `(${summary.thirdPartyHosts.size} third-party), ` +
        `${plural(summary.withBody, "request")} with a body`,
      `- ${plural(summary.trackers.size, "host")} classified by Firefox ` +
        `tracking protection`,
      `- ${plural(network.cookies.length, "cookie change")} on ` +
        `${plural(summary.cookieHosts.size, "host")}`,
      "",
      "| Host | Requests | Party | Types | With body | Cookies sent | Set-Cookie | Tracking protection |",
      "| --- | ---: | --- | --- | ---: | ---: | ---: | --- |"
    );
    for (let entry of [...summary.hosts.values()].sort(
      (a, b) => b.thirdParty - a.thirdParty || b.requests - a.requests
    )) {
      lines.push(
        `| ${cell(entry.host)} | ${entry.requests} | ` +
          `${entry.thirdParty ? "third" : "first"} | ` +
          `${cell([...entry.types].join(", "))} | ${entry.withBody} | ` +
          `${entry.cookiesSent} | ${entry.setCookies} | ` +
          `${cell([...entry.classification].join("; "))} |`
      );
    }
    if (network.cookies.length) {
      lines.push(
        "",
        "### Cookie changes",
        "",
        "| Action | Host | Name | Value | Expiry | Third-party |",
        "| --- | --- | --- | --- | --- | --- |"
      );
      for (let c of network.cookies) {
        lines.push(
          `| ${c.action} | ${cell(c.host ?? "")} | ${cell(c.name ?? "")} | ` +
            `${cell(c.value ?? "", 60)} | ` +
            `${c.expiry ? new Date(c.expiry).toISOString() : "session"} | ` +
            `${c.thirdParty ? "yes" : "no"} |`
        );
      }
    }
    lines.push("", "Use Copy all for every request's headers and body.");
  }
  return lines.join("\n") + "\n";
}

async function copySummary() {
  await refresh();
  let node = selectedNode();
  copyToClipboard(buildSummary(node), `the summary of "${node.title}"`);
}

function resetLocalState() {
  state.windows.clear();
  state.network = { requests: [], cookies: [], contentBlocking: [] };
  state.openRequests.clear();
  state.expanded.clear();
  state.openCode.clear();
  state.codeText.clear();
  state.codeRequested.clear();
}

function formatDuration(ms) {
  let seconds = Math.max(0, Math.round(ms / 1000));
  let minutes = Math.floor(seconds / 60);
  let hours = Math.floor(minutes / 60);
  if (hours) {
    return `${hours}h ${minutes % 60}m`;
  }
  if (minutes) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
}

function renderSessionControls() {
  let recording = ApiAudit.enabled;
  let { start, stop } = ApiAudit.session;
  $("stop").disabled = !recording;
  $("resume").hidden = recording;
  $("start").textContent = recording ? "Restart" : "Start";
  let label = $("session");
  label.classList.toggle("recording", recording);
  if (recording) {
    label.textContent = start
      ? `Recording since ${new Date(start).toLocaleTimeString()} (${formatDuration(Date.now() - start)})`
      : "Recording since the browser started";
  } else if (stop) {
    label.textContent =
      `Stopped at ${new Date(stop).toLocaleTimeString()}` +
      (start ? ` after ${formatDuration(stop - start)}` : "");
  } else {
    label.textContent = "Stopped";
  }
}

let pollTimer = null;
function schedulePoll() {
  clearInterval(pollTimer);
  if ($("live").checked) {
    pollTimer = setInterval(() => {
      if (!document.hidden) {
        refresh({ fromPoll: true });
      }
    }, POLL_INTERVAL_MS);
  }
}

function init() {
  $("start").addEventListener("click", async () => {
    await ApiAudit.startSession();
    resetLocalState();
    refresh();
  });
  $("stop").addEventListener("click", () => {
    ApiAudit.stopSession();
    refresh();
  });
  $("resume").addEventListener("click", () => {
    ApiAudit.resumeSession();
    refresh();
  });
  $("live").addEventListener("change", schedulePoll);
  $("refresh").addEventListener("click", () => refresh());
  $("copy-all").addEventListener("click", copyAll);
  $("copy-summary").addEventListener("click", copySummary);
  $("export").addEventListener("click", exportJSON);
  $("clear").addEventListener("click", async () => {
    await ApiAudit.clear();
    resetLocalState();
    refresh();
  });
  $("filter").addEventListener("input", () => renderView(selectedNode()));
  $("min-score").addEventListener("input", () => {
    $("min-score-value").textContent = $("min-score").value;
    renderView(selectedNode());
  });
  for (let th of document.querySelectorAll("th[data-sort]")) {
    th.addEventListener("click", () => {
      state.sortKey = th.dataset.sort;
      renderTable(selectedNode());
    });
  }
  for (let button of document.querySelectorAll("#views button")) {
    button.addEventListener("click", () => {
      state.view = button.dataset.view;
      renderView(selectedNode());
    });
  }
  refresh();
  schedulePoll();
}

init();
