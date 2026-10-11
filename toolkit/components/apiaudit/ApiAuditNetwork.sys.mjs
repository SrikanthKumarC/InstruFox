/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Records, in the parent process, what web content sends and receives over
 * the network: every HTTP request with its headers and body, the response
 * headers, the classification of the request by Firefox's tracking
 * protection lists, and every cookie change.
 */

const lazy = {};
ChromeUtils.defineESModuleGetters(lazy, {
  NetUtil: "resource://gre/modules/NetUtil.sys.mjs",
});

const ENABLED_PREF = "privacy.apiaudit.enabled";
const MAX_REQUESTS = 20000;
const MAX_COOKIE_CHANGES = 10000;
const MAX_HEADER_LENGTH = 4096;
const MAX_BODY_LENGTH = 64 * 1024;
const MAX_COOKIE_VALUE_LENGTH = 1024;

const RESPONSE_TOPICS = [
  "http-on-examine-response",
  "http-on-examine-cached-response",
  "http-on-examine-merged-response",
];
const COOKIE_TOPICS = ["cookie-changed", "private-cookie-changed"];

const COOKIE_ACTIONS = {
  [Ci.nsICookieNotification.COOKIE_DELETED]: "deleted",
  [Ci.nsICookieNotification.COOKIE_ADDED]: "added",
  [Ci.nsICookieNotification.COOKIE_CHANGED]: "changed",
  [Ci.nsICookieNotification.ALL_COOKIES_CLEARED]: "all-cleared",
  [Ci.nsICookieNotification.COOKIES_BATCH_DELETED]: "batch-deleted",
};

const SAME_SITE = ["none", "lax", "strict", "unset"];

// Single-bit CLASSIFIED_* flags of nsIClassifiedChannel, by name.
const CLASSIFICATION_FLAGS = Object.entries(Ci.nsIClassifiedChannel)
  .filter(
    ([name, value]) =>
      name.startsWith("CLASSIFIED_") &&
      !name.startsWith("CLASSIFIED_ANY_") &&
      Number.isInteger(value) &&
      value > 0 &&
      (value & (value - 1)) == 0
  )
  .map(([name, value]) => [
    name.slice("CLASSIFIED_".length).toLowerCase(),
    value,
  ]);

const CONTENT_POLICY_TYPES = Object.fromEntries(
  Object.entries(Ci.nsIContentPolicy)
    .filter(([name]) => name.startsWith("TYPE_") && !name.includes("INTERNAL"))
    .map(([name, value]) => [value, name.slice("TYPE_".length).toLowerCase()])
);

function truncate(value, max) {
  value = String(value ?? "");
  return value.length > max ? value.slice(0, max) + "..." : value;
}

function flagNames(flags) {
  return CLASSIFICATION_FLAGS.filter(([, bit]) => flags & bit).map(
    ([name]) => name
  );
}

function readHeaders(channel, visit) {
  let headers = [];
  try {
    channel[visit]({
      visitHeader(name, value) {
        headers.push([name, truncate(value, MAX_HEADER_LENGTH)]);
      },
    });
  } catch (e) {
    // The channel has no headers of that kind yet.
  }
  return headers;
}

/**
 * Reads the request body without consuming it, if the upload stream can be
 * rewound. Binary bodies are returned base64-encoded.
 *
 * @param {nsIHttpChannel} channel
 * @returns {?object} The body, or null if the request has none.
 */
function readBody(channel) {
  if (!(channel instanceof Ci.nsIUploadChannel) || !channel.uploadStream) {
    return null;
  }
  let stream = channel.uploadStream;
  if (!(stream instanceof Ci.nsISeekableStream)) {
    return { length: null, unreadable: true };
  }
  let position = stream.tell();
  try {
    stream.seek(Ci.nsISeekableStream.NS_SEEK_SET, 0);
    let length = stream.available();
    let text = lazy.NetUtil.readInputStreamToString(
      stream,
      Math.min(length, MAX_BODY_LENGTH)
    );
    let body = { length, truncated: length > MAX_BODY_LENGTH };
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x08\x0e-\x1f]/.test(text)) {
      body.encoding = "base64";
      body.text = btoa(text);
    } else {
      try {
        body.text = new TextDecoder("utf-8", { fatal: true }).decode(
          Uint8Array.from(text, c => c.charCodeAt(0))
        );
      } catch (e) {
        body.text = text;
      }
    }
    return body;
  } catch (e) {
    return { length: null, unreadable: true };
  } finally {
    try {
      stream.seek(Ci.nsISeekableStream.NS_SEEK_SET, position);
    } catch (e) {}
  }
}

/**
 * Returns the browser and window a channel was opened for, or null if it was
 * not opened for web content.
 *
 * @param {nsIHttpChannel} channel
 * @returns {?object}
 */
function contentContextOf(channel) {
  let loadInfo = channel.loadInfo;
  if (!loadInfo) {
    return null;
  }
  let bcId = loadInfo.browsingContextID || loadInfo.associatedBrowsingContextID;
  let bc = bcId ? BrowsingContext.get(bcId) : null;
  let triggering = loadInfo.triggeringPrincipal;
  let loading = loadInfo.loadingPrincipal;
  if (bc) {
    if (!bc.isContent) {
      return null;
    }
  } else if (
    !triggering ||
    triggering.isSystemPrincipal ||
    triggering.isExpandedPrincipal ||
    !triggering.isContentPrincipal
  ) {
    // Requests without a browsing context are only kept when web content
    // (a shared or service worker) made them.
    return null;
  }
  if (loading?.isSystemPrincipal && !bc) {
    return null;
  }
  return {
    browserId: bc?.browserId ?? 0,
    innerWindowId: loadInfo.innerWindowID,
    topUrl: bc?.top?.currentWindowGlobal?.documentURI?.spec ?? null,
    triggeringOrigin: triggering?.isContentPrincipal ? triggering.origin : null,
  };
}

export const ApiAuditNetwork = {
  _started: false,
  _requests: [],
  _byChannelId: new Map(),
  _cookies: [],

  get enabled() {
    return Services.prefs.getBoolPref(ENABLED_PREF, true);
  },

  start() {
    if (this._started) {
      return;
    }
    this._started = true;
    Services.obs.addObserver(this, "http-on-modify-request");
    for (let topic of [...RESPONSE_TOPICS, ...COOKIE_TOPICS]) {
      Services.obs.addObserver(this, topic);
    }
    Services.obs.addObserver(this, "xpcom-shutdown");
  },

  stop() {
    if (!this._started) {
      return;
    }
    this._started = false;
    Services.obs.removeObserver(this, "http-on-modify-request");
    for (let topic of [...RESPONSE_TOPICS, ...COOKIE_TOPICS]) {
      Services.obs.removeObserver(this, topic);
    }
    Services.obs.removeObserver(this, "xpcom-shutdown");
  },

  clear() {
    this._requests = [];
    this._byChannelId.clear();
    this._cookies = [];
  },

  observe(subject, topic) {
    if (topic == "xpcom-shutdown") {
      this.stop();
      return;
    }
    if (!this.enabled) {
      return;
    }
    try {
      if (topic == "http-on-modify-request") {
        this._onRequest(subject.QueryInterface(Ci.nsIHttpChannel));
      } else if (RESPONSE_TOPICS.includes(topic)) {
        this._onResponse(
          subject.QueryInterface(Ci.nsIHttpChannel),
          topic != "http-on-examine-response"
        );
      } else if (COOKIE_TOPICS.includes(topic)) {
        this._onCookie(subject.QueryInterface(Ci.nsICookieNotification));
      }
    } catch (e) {
      console.error("ApiAuditNetwork:", e);
    }
  },

  _onRequest(channel) {
    let context = contentContextOf(channel);
    if (!context) {
      return;
    }
    let loadInfo = channel.loadInfo;
    let entry = {
      id: channel.channelId,
      time: Date.now(),
      url: truncate(channel.URI.spec, MAX_HEADER_LENGTH),
      method: channel.requestMethod,
      type: CONTENT_POLICY_TYPES[loadInfo.externalContentPolicyType] ?? "other",
      ...context,
      thirdParty: loadInfo.isThirdPartyContextToTopWindow,
      referrer: channel.referrerInfo?.computedReferrerSpec ?? null,
      requestHeaders: readHeaders(channel, "visitRequestHeaders"),
      requestBody: readBody(channel),
      status: null,
      responseHeaders: [],
      fromCache: false,
      remoteAddress: null,
      classification: null,
    };
    this._requests.push(entry);
    this._byChannelId.set(entry.id, entry);
    if (this._requests.length > MAX_REQUESTS) {
      let dropped = this._requests.shift();
      this._byChannelId.delete(dropped.id);
    }
  },

  _onResponse(channel, fromCache) {
    let entry = this._byChannelId.get(channel.channelId);
    if (!entry) {
      return;
    }
    this._byChannelId.delete(entry.id);
    // Cookies and other headers added after http-on-modify-request.
    entry.requestHeaders = readHeaders(channel, "visitRequestHeaders");
    entry.responseHeaders = readHeaders(
      channel,
      "visitOriginalResponseHeaders"
    );
    try {
      entry.status = channel.responseStatus;
    } catch (e) {}
    entry.fromCache = fromCache;
    try {
      entry.remoteAddress = channel.QueryInterface(
        Ci.nsIHttpChannelInternal
      ).remoteAddress;
    } catch (e) {}
    if (channel instanceof Ci.nsIClassifiedChannel) {
      entry.classification = {
        flags: flagNames(channel.classificationFlags),
        firstParty: flagNames(channel.firstPartyClassificationFlags),
        thirdParty: flagNames(channel.thirdPartyClassificationFlags),
        thirdPartyTracker: channel.isThirdPartyTrackingResource(),
        matchedList: channel.matchedList || null,
        matchedTrackingLists: channel.matchedTrackingLists,
      };
    }
  },

  _onCookie(notification) {
    let action = COOKIE_ACTIONS[notification.action] ?? "unknown";
    let cookie = notification.cookie;
    let bc = notification.browsingContext;
    if (bc && !bc.isContent) {
      return;
    }
    let entry = {
      time: Date.now(),
      action,
      browserId: bc?.browserId ?? 0,
      baseDomain: notification.baseDomain,
      thirdParty: notification.isThirdParty,
    };
    if (cookie) {
      Object.assign(entry, {
        name: cookie.name,
        value: truncate(cookie.value, MAX_COOKIE_VALUE_LENGTH),
        host: cookie.host,
        path: cookie.path,
        expiry: cookie.isSession ? null : cookie.expiry,
        secure: cookie.isSecure,
        httpOnly: cookie.isHttpOnly,
        sameSite: SAME_SITE[cookie.sameSite] ?? cookie.sameSite,
        partitioned: cookie.isPartitioned,
        partitionKey: cookie.originAttributes?.partitionKey || null,
      });
    }
    this._cookies.push(entry);
    if (this._cookies.length > MAX_COOKIE_CHANGES) {
      this._cookies.shift();
    }
  },

  /**
   * Returns the content blocking log of every tab: the trackers,
   * fingerprinters and cryptominers Firefox detected or blocked.
   */
  _contentBlockingLogs() {
    let logs = [];
    for (let win of Services.wm.getEnumerator("navigator:browser")) {
      for (let browser of win.gBrowser?.browsers ?? []) {
        let wgp = browser.browsingContext?.currentWindowGlobal;
        if (!wgp) {
          continue;
        }
        let log;
        try {
          log = JSON.parse(wgp.contentBlockingLog || "{}");
        } catch (e) {
          continue;
        }
        if (!Object.keys(log).length) {
          continue;
        }
        logs.push({
          browserId: browser.browserId,
          url: wgp.documentURI?.spec ?? null,
          log,
        });
      }
    }
    return logs;
  },

  /**
   * Returns everything recorded so far.
   */
  collect() {
    return {
      requests: this._requests,
      cookies: this._cookies,
      contentBlocking: this._contentBlockingLogs(),
    };
  },
};
