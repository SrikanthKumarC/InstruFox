/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const lazy = {};
ChromeUtils.defineESModuleGetters(lazy, {
  // Only reached from the browser-window-delayed-startup category.
  CustomizableUI:
    // eslint-disable-next-line mozilla/no-browser-refs-in-toolkit
    "moz-src:///browser/components/customizableui/CustomizableUI.sys.mjs",
});

const ACTOR_NAME = "ApiAudit";
const WIDGET_ID = "apiaudit-button";
const WINDOW_URL = "chrome://global/content/apiaudit/apiaudit.html";
const WINDOW_TYPE = "privacy:apiaudit";
const ENABLED_PREF = "privacy.apiaudit.enabled";
const HIDE_DEVTOOLS_PREF = "privacy.apiaudit.hideDevTools";

// Default prefs that stop pages from noticing DevTools: no pausing on
// `debugger;` traps, and an undocked toolbox, so that opening it does not
// shrink the page's viewport.
const HIDE_DEVTOOLS_DEFAULTS = {
  "devtools.debugger.pause-on-debugger-statement": false,
  "devtools.toolbox.host": "window",
};

export const ApiAudit = {
  _initialized: false,

  init() {
    if (this._initialized) {
      return;
    }
    this._initialized = true;

    if (Services.prefs.getBoolPref(HIDE_DEVTOOLS_PREF, true)) {
      this.applyHideDevToolsDefaults();
    }

    ChromeUtils.registerProcessActor(ACTOR_NAME, {
      parent: {
        esModuleURI:
          "moz-src:///toolkit/components/apiaudit/ApiAuditParent.sys.mjs",
      },
      child: {
        esModuleURI:
          "moz-src:///toolkit/components/apiaudit/ApiAuditChild.sys.mjs",
      },
      includeParent: true,
      safeForUntrustedWebProcess: true,
    });

    lazy.CustomizableUI.createWidget({
      id: WIDGET_ID,
      type: "button",
      label: "API Audit",
      tooltiptext:
        "Show the Web APIs used by open pages, ranked by privacy risk",
      defaultArea: lazy.CustomizableUI.AREA_NAVBAR,
      onCreated(node) {
        node.style.listStyleImage =
          'url("chrome://browser/skin/fingerprint.svg")';
      },
      onCommand: event => this.openWindow(event.target.ownerGlobal),
    });
  },

  applyHideDevToolsDefaults() {
    let defaults = Services.prefs.getDefaultBranch("");
    for (let [name, value] of Object.entries(HIDE_DEVTOOLS_DEFAULTS)) {
      if (typeof value == "boolean") {
        defaults.setBoolPref(name, value);
      } else {
        defaults.setStringPref(name, value);
      }
    }
  },

  /**
   * Category consumer for "browser-window-delayed-startup".
   */
  onBrowserWindow() {
    this.init();
  },

  get enabled() {
    return Services.prefs.getBoolPref(ENABLED_PREF, true);
  },

  set enabled(value) {
    Services.prefs.setBoolPref(ENABLED_PREF, value);
  },

  openWindow(opener = null) {
    let existing = Services.wm.getMostRecentWindow(WINDOW_TYPE);
    if (existing) {
      existing.focus();
      return existing;
    }
    return Services.ww.openWindow(
      opener,
      WINDOW_URL,
      "_blank",
      "chrome,resizable,centerscreen,width=1100,height=700",
      null
    );
  },

  async _queryAllProcesses(message, data) {
    return Promise.all(
      ChromeUtils.getAllDOMProcesses().map(async process => {
        try {
          let result = await process
            .getActor(ACTOR_NAME)
            .sendQuery(message, data);
          return { process, result };
        } catch (e) {
          return null;
        }
      })
    );
  },

  _tabsByBrowserId() {
    let tabs = new Map();
    for (let win of Services.wm.getEnumerator("navigator:browser")) {
      for (let browser of win.gBrowser?.browsers ?? []) {
        tabs.set(browser.browserId, {
          title: browser.contentTitle,
          url: browser.currentURI?.spec,
        });
      }
    }
    return tabs;
  },

  /**
   * Returns the records of every window in every process, annotated with the
   * process, the tab and the top-level document URL where known.
   *
   * @param {object} [options]
   * @param {boolean} [options.includeCode] Include the text of captured code.
   */
  async collect({ includeCode = false } = {}) {
    let tabs = this._tabsByBrowserId();
    let windows = [];
    for (let entry of await this._queryAllProcesses("ApiAudit:GetRecords", {
      includeCode,
    })) {
      if (!entry?.result) {
        continue;
      }
      let { process, result } = entry;
      let parsed;
      try {
        parsed = JSON.parse(result);
      } catch (e) {
        console.error("ApiAudit: invalid records from", process.remoteType, e);
        continue;
      }
      for (let win of parsed.windows ?? []) {
        win.pid = process.osPid;
        win.remoteType = process.remoteType ?? "parent";
        win.tab = tabs.get(win.browserId) ?? null;
        if (win.isTop) {
          win.topUrl = win.url;
        } else if (win.topInnerWindowId) {
          let top = WindowGlobalParent.getByInnerWindowId(win.topInnerWindowId);
          win.topUrl = top?.documentURI?.spec ?? null;
        }
        windows.push(win);
      }
    }
    return windows;
  },

  async clear() {
    await this._queryAllProcesses("ApiAudit:Clear");
    if (this.enabled) {
      this.session = { start: Date.now(), stop: null };
    }
  },

  /**
   * The current recording session: when it was started and, if recording is
   * stopped, when it was stopped. start is null when recording has been on
   * since the browser started.
   */
  session: { start: null, stop: null },

  /**
   * Forgets everything recorded so far and records from now on.
   */
  async startSession() {
    await this.clear();
    this.session = { start: Date.now(), stop: null };
    this.enabled = true;
  },

  stopSession() {
    this.enabled = false;
    this.session = { ...this.session, stop: Date.now() };
  },

  /**
   * Continues the stopped session without forgetting what it recorded.
   */
  resumeSession() {
    this.enabled = true;
    this.session = { ...this.session, stop: null };
  },
};
