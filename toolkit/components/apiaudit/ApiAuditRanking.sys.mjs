/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Privacy ranking of Web APIs. Scores go from 0 (noise) to 100 (almost
 * certainly used to identify the user). Recorded names have the form
 * "Iface.attr" (getter), "Iface.attr=" (setter), "Iface.method()" and
 * "new Iface()"; rules match against the normalized "Iface.member" form, where
 * constructors are "Iface.constructor".
 */

export const CATEGORIES = {
  canvas: "Canvas fingerprinting",
  webgl: "WebGL / WebGPU fingerprinting",
  audio: "Audio fingerprinting",
  fonts: "Font enumeration",
  hardware: "Device & browser properties",
  screen: "Screen & window geometry",
  media: "Media devices & codecs",
  sensors: "Sensors & location",
  network: "Network / WebRTC leaks",
  storage: "Storage & identifiers",
  permissions: "Permission probing",
  crypto: "Crypto & hashing",
  timing: "Timing side channels",
  css: "Media queries & styles",
  clipboard: "Clipboard & input",
  navigation: "Navigation & referrer",
  workers: "Workers & background",
  dynamic: "Dynamic / hidden code",
  antidebug: "Anti-debugging",
  other: "Uncategorized",
};

const WEBGL = "(?:WebGL2?RenderingContext|WebGLRenderingContextBase)";
const CANVAS2D =
  "(?:CanvasRenderingContext2D|OffscreenCanvasRenderingContext2D)";

// [regex source, category, score]
const RULES = [
  // Canvas
  ["(?:HTMLCanvasElement)\\.(?:toDataURL|toBlob|mozGetAsFile)", "canvas", 90],
  ["OffscreenCanvas\\.convertToBlob", "canvas", 90],
  [`${CANVAS2D}\\.getImageData`, "canvas", 90],
  [`${CANVAS2D}\\.(?:isPointInPath|isPointInStroke)`, "canvas", 65],
  [`${CANVAS2D}\\.measureText`, "fonts", 60],
  ["TextMetrics\\..*", "fonts", 55],
  [`${CANVAS2D}\\.(?:fillText|strokeText)`, "canvas", 45],
  [`${CANVAS2D}\\.font=`, "fonts", 40],
  [`${CANVAS2D}\\.globalCompositeOperation=?`, "canvas", 35],
  [
    `${CANVAS2D}\\.(?:fillStyle|strokeStyle|shadowBlur|shadowColor)=`,
    "canvas",
    25,
  ],
  ["HTMLCanvasElement\\.getContext", "canvas", 30],
  ["OffscreenCanvas\\.(?:getContext|constructor)", "canvas", 40],

  // WebGL / WebGPU
  [`${WEBGL}\\.readPixels`, "webgl", 90],
  [`${WEBGL}\\.getShaderPrecisionFormat`, "webgl", 85],
  [`${WEBGL}\\.getSupportedExtensions`, "webgl", 80],
  [`${WEBGL}\\.getParameter`, "webgl", 75],
  [`${WEBGL}\\.getExtension`, "webgl", 70],
  [`${WEBGL}\\.getContextAttributes`, "webgl", 60],
  ["WebGLShaderPrecisionFormat\\..*", "webgl", 70],
  ["GPUAdapter\\.(?:info|requestAdapterInfo)", "webgl", 90],
  ["GPUAdapter\\.(?:features|limits|isFallbackAdapter)", "webgl", 75],
  ["GPU\\.requestAdapter", "webgl", 65],
  ["GPUAdapterInfo\\..*", "webgl", 85],

  // Audio
  ["OfflineAudioContext\\.constructor", "audio", 85],
  ["AudioBuffer\\.(?:getChannelData|copyFromChannel)", "audio", 80],
  [
    "AnalyserNode\\.(?:getFloatFrequencyData|getByteFrequencyData|getFloatTimeDomainData|getByteTimeDomainData)",
    "audio",
    80,
  ],
  ["OfflineAudioContext\\.startRendering", "audio", 80],
  [
    "(?:BaseAudioContext|AudioContext|OfflineAudioContext)\\.createDynamicsCompressor",
    "audio",
    70,
  ],
  ["DynamicsCompressorNode\\..*", "audio", 60],
  [
    "(?:AudioContext|BaseAudioContext)\\.(?:baseLatency|outputLatency|sampleRate)",
    "audio",
    60,
  ],
  ["AudioDestinationNode\\.maxChannelCount", "audio", 65],
  [
    "(?:BaseAudioContext|AudioContext|OfflineAudioContext)\\.createOscillator",
    "audio",
    45,
  ],
  ["AudioContext\\.constructor", "audio", 35],
  ["OscillatorNode\\.(?:type|frequency|detune)=?", "audio", 40],

  // Fonts
  ["Window\\.queryLocalFonts", "fonts", 95],
  ["FontFaceSet\\.check", "fonts", 75],
  ["FontFaceSet\\.load", "fonts", 40],
  ["Document\\.fonts", "fonts", 35],
  ["FontFace\\.constructor", "fonts", 35],
  ["Range\\.(?:getClientRects|getBoundingClientRect)", "fonts", 40],
  ["Element\\.(?:getBoundingClientRect|getClientRects)", "fonts", 25],
  ["HTMLElement\\.(?:offsetWidth|offsetHeight)", "fonts", 15],

  // Device & browser properties
  ["NavigatorUAData\\.getHighEntropyValues", "hardware", 90],
  ["Navigator\\.(?:getBattery)", "hardware", 85],
  ["BatteryManager\\..*", "hardware", 85],
  ["Navigator\\.(?:requestMIDIAccess)", "hardware", 80],
  ["Keyboard\\.getLayoutMap", "hardware", 85],
  ["Navigator\\.(?:hardwareConcurrency|deviceMemory)", "hardware", 75],
  ["Navigator\\.(?:oscpu|cpuClass|platform|buildID)", "hardware", 70],
  ["Navigator\\.(?:plugins|mimeTypes)", "hardware", 65],
  ["(?:PluginArray|MimeTypeArray|Plugin|MimeType)\\..*", "hardware", 65],
  [
    "Navigator\\.(?:webdriver|maxTouchPoints|vendor|vendorSub|productSub|pdfViewerEnabled)",
    "hardware",
    60,
  ],
  ["Navigator\\.(?:userAgentData|keyboard)", "hardware", 60],
  ["Navigator\\.(?:getGamepads)", "hardware", 70],
  ["Gamepad\\..*", "hardware", 55],
  ["Navigator\\.vibrate", "hardware", 25],
  [
    "Navigator\\.(?:userAgent|appVersion|appName|appCodeName|product)",
    "hardware",
    50,
  ],
  ["Navigator\\.(?:language|languages)", "hardware", 50],
  [
    "Navigator\\.(?:doNotTrack|globalPrivacyControl|cookieEnabled|onLine)",
    "hardware",
    35,
  ],
  ["Navigator\\.(?:connection)", "network", 70],
  ["NetworkInformation\\..*", "network", 70],

  // Screen & window geometry
  [
    "Screen\\.(?:width|height|availWidth|availHeight|availLeft|availTop|colorDepth|pixelDepth|left|top)",
    "screen",
    65,
  ],
  ["Screen\\..*", "screen", 50],
  ["ScreenOrientation\\..*", "screen", 50],
  ["Window\\.devicePixelRatio", "screen", 60],
  [
    "Window\\.(?:outerWidth|outerHeight|screenX|screenY|screenLeft|screenTop|mozInnerScreenX|mozInnerScreenY)",
    "screen",
    60,
  ],
  ["Window\\.screen", "screen", 30],
  ["Window\\.(?:innerWidth|innerHeight)", "screen", 25],
  [
    "Window\\.(?:scrollbars|menubar|personalbar|statusbar|toolbar|locationbar)",
    "screen",
    40,
  ],
  ["BarProp\\.visible", "screen", 40],
  ["VisualViewport\\..*", "screen", 25],

  // Media devices & codecs
  ["MediaDevices\\.enumerateDevices", "media", 85],
  ["MediaDevices\\.(?:getUserMedia|getDisplayMedia)", "media", 90],
  ["MediaDevices\\.getSupportedConstraints", "media", 60],
  ["SpeechSynthesis\\.getVoices", "media", 75],
  ["SpeechSynthesisVoice\\..*", "media", 60],
  ["MediaCapabilities\\.(?:decodingInfo|encodingInfo)", "media", 60],
  ["HTMLMediaElement\\.canPlayType", "media", 55],
  ["MediaSource\\.isTypeSupported", "media", 55],
  ["MediaRecorder\\.isTypeSupported", "media", 55],
  ["Navigator\\.(?:requestMediaKeySystemAccess)", "media", 65],
  ["Navigator\\.mediaDevices", "media", 40],

  // Sensors & location
  ["Geolocation\\.(?:getCurrentPosition|watchPosition)", "sensors", 95],
  [
    "(?:DeviceOrientationEvent|DeviceMotionEvent|DeviceMotionEventAcceleration|DeviceMotionEventRotationRate)\\..*",
    "sensors",
    75,
  ],
  [
    "Window\\.(?:ondeviceorientation|ondevicemotion|ondeviceorientationabsolute)=?",
    "sensors",
    75,
  ],
  [
    "(?:Accelerometer|Gyroscope|Magnetometer|AmbientLightSensor|LinearAccelerationSensor|GravitySensor|AbsoluteOrientationSensor|RelativeOrientationSensor)\\..*",
    "sensors",
    80,
  ],
  ["XRSystem\\.(?:isSessionSupported|supportsSession)", "sensors", 65],
  ["Navigator\\.xr", "sensors", 55],

  // Network / WebRTC
  ["RTCIceCandidate\\..*", "network", 90],
  [
    "RTCPeerConnection\\.(?:createOffer|setLocalDescription|localDescription)",
    "network",
    80,
  ],
  ["RTCPeerConnection\\.(?:onicecandidate|createDataChannel)=?", "network", 75],
  ["RTCPeerConnection\\.constructor", "network", 75],
  ["RTCPeerConnection\\..*", "network", 55],
  [
    "RTCRtpSender\\.getCapabilities|RTCRtpReceiver\\.getCapabilities",
    "network",
    75,
  ],
  ["Navigator\\.sendBeacon", "network", 55],
  ["WebSocket\\.constructor", "network", 25],
  ["WebTransport\\.constructor", "network", 30],
  ["XMLHttpRequest\\.(?:open|send)", "network", 25],
  ["EventSource\\.constructor", "network", 25],
  [
    "(?:Window|WorkerGlobalScope|DedicatedWorkerGlobalScope|SharedWorkerGlobalScope|ServiceWorkerGlobalScope)\\.fetch",
    "network",
    20,
  ],

  // Storage & identifiers
  ["Document\\.cookie=", "storage", 70],
  ["Document\\.cookie", "storage", 60],
  ["CookieStore\\..*", "storage", 60],
  ["StorageManager\\.(?:estimate|persisted|persist)", "storage", 75],
  ["Navigator\\.storage", "storage", 40],
  ["IDBFactory\\.databases", "storage", 65],
  ["IDBFactory\\.open", "storage", 50],
  ["Window\\.(?:localStorage|indexedDB)", "storage", 50],
  ["Window\\.sessionStorage", "storage", 35],
  ["Storage\\.(?:setItem|removeItem)", "storage", 55],
  ["Storage\\.(?:getItem|key|length)", "storage", 45],
  ["CacheStorage\\..*", "storage", 40],
  [
    "Document\\.(?:hasStorageAccess|requestStorageAccess|requestStorageAccessUnderSite)",
    "storage",
    60,
  ],
  ["BroadcastChannel\\.constructor", "storage", 40],
  ["Window\\.name=?", "storage", 45],
  [
    "FileSystemDirectoryHandle\\..*|StorageManager\\.getDirectory",
    "storage",
    55,
  ],

  // Permission probing
  ["Permissions\\.query", "permissions", 65],
  ["Notification\\.permission", "permissions", 55],
  ["Notification\\.requestPermission", "permissions", 50],
  ["PermissionStatus\\.state", "permissions", 50],

  // Crypto & hashing
  [
    "SubtleCrypto\\.(?:digest|sign|verify|deriveBits|deriveKey|exportKey)",
    "crypto",
    40,
  ],
  ["SubtleCrypto\\..*", "crypto", 25],
  ["Crypto\\.randomUUID", "crypto", 45],
  ["Crypto\\.getRandomValues", "crypto", 25],

  // Timing
  [
    "Performance\\.(?:getEntries|getEntriesByType|getEntriesByName)",
    "timing",
    55,
  ],
  ["PerformanceResourceTiming\\..*", "timing", 45],
  ["PerformanceNavigationTiming\\..*|PerformanceTiming\\..*", "timing", 40],
  ["Performance\\.(?:timing|navigation|timeOrigin)", "timing", 40],
  ["Performance\\.now", "timing", 15],
  ["Window\\.requestAnimationFrame", "timing", 5],

  // Media queries & styles
  ["Window\\.matchMedia", "css", 50],
  ["MediaQueryList\\.(?:matches|media)", "css", 35],
  ["Window\\.getComputedStyle", "css", 15],
  ["CSS\\.supports", "css", 40],

  // Clipboard & input
  ["Clipboard\\.(?:read|readText)", "clipboard", 90],
  ["Clipboard\\.(?:write|writeText)", "clipboard", 40],
  ["Navigator\\.clipboard", "clipboard", 30],
  ["Selection\\.toString", "clipboard", 30],
  ["Document\\.hasFocus", "clipboard", 15],

  // Navigation & referrer
  ["Document\\.referrer", "navigation", 40],
  ["History\\.length", "navigation", 40],
  ["History\\.(?:pushState|replaceState|state)", "navigation", 25],
  ["Document\\.(?:lastModified|domain)", "navigation", 25],
  ["Window\\.opener", "navigation", 25],
  ["Window\\.(?:top|parent|frameElement)", "navigation", 10],
  ["Location\\.(?:href|search|hash)", "navigation", 10],

  // Anti-debugging: code containing a `debugger;` statement, recorded as
  // "debugger()" with the kind and URL of that code as its argument.
  ["debugger", "antidebug", 85],

  // Dynamic / hidden code
  ["eval|Function", "dynamic", 55],
  ["WebAssembly\\.compile", "dynamic", 50],
  ["URL\\.createObjectURL", "dynamic", 35],

  // Workers & background
  ["ServiceWorkerContainer\\.register", "workers", 45],
  ["Worker\\.constructor|SharedWorker\\.constructor", "workers", 30],
  ["Navigator\\.serviceWorker", "workers", 25],
  ["CredentialsContainer\\.(?:get|create)", "permissions", 55],
];

/**
 * Returns true if a context or script URL hides its code from the network
 * panel and from simple source inspection.
 *
 * @param {string} url A script or worker URL.
 * @returns {boolean}
 */
export function isHiddenSourceUrl(url) {
  return /^(?:blob|data):/i.test(url ?? "");
}

const COMPILED = RULES.map(([source, category, score]) => ({
  regex: new RegExp(`^(?:${source})$`),
  category,
  score,
}));

const WEBGL_UNMASKED = new Set(["37445", "37446"]);
const SENSOR_EVENTS =
  /^"(?:devicemotion|deviceorientation|deviceorientationabsolute|gamepadconnected|gamepaddisconnected|devicechange|voiceschanged)"$/;
const FINGERPRINT_MEDIA_FEATURES =
  /prefers-|color-gamut|dynamic-range|forced-colors|inverted-colors|monochrome|resolution|device-pixel-ratio|pointer|hover|-moz-|device-width|device-height|color-index|display-mode|video-/;

/**
 * Splits a recorded API name into its parts.
 *
 * @param {string} name A recorded name, e.g. "Navigator.userAgent".
 * @returns {{iface: string, member: string, kind: string, key: string}}
 */
export function parseApiName(name) {
  let kind = "get";
  let rest = name;
  if (rest.startsWith("new ")) {
    rest = rest.slice(4).replace(/\(\)$/, "");
    return {
      iface: rest,
      member: "constructor",
      kind: "new",
      key: `${rest}.constructor`,
    };
  }
  if (rest.endsWith("()")) {
    kind = "call";
    rest = rest.slice(0, -2);
  } else if (rest.endsWith("=")) {
    kind = "set";
    rest = rest.slice(0, -1);
  }
  let dot = rest.indexOf(".");
  let iface = dot == -1 ? rest : rest.slice(0, dot);
  let member = dot == -1 ? "" : rest.slice(dot + 1);
  return { iface, member, kind, key: kind == "set" ? `${rest}=` : rest };
}

function argBoost(parsed, args) {
  let { iface, member } = parsed;
  if (/^WebGL2?RenderingContext$/.test(iface)) {
    if (member == "getParameter" && args.some(a => WEBGL_UNMASKED.has(a))) {
      return {
        category: "webgl",
        score: 100,
        reason: "UNMASKED_VENDOR/RENDERER_WEBGL",
      };
    }
    if (
      member == "getExtension" &&
      args.some(a => a.includes("WEBGL_debug_renderer_info"))
    ) {
      return {
        category: "webgl",
        score: 95,
        reason: "WEBGL_debug_renderer_info",
      };
    }
  }
  if (iface == "Window" && member == "matchMedia") {
    if (args.some(a => FINGERPRINT_MEDIA_FEATURES.test(a))) {
      return {
        category: "css",
        score: 70,
        reason: "fingerprintable media feature",
      };
    }
  }
  if (iface == "EventTarget" && member == "addEventListener") {
    if (args.some(a => SENSOR_EVENTS.test(a))) {
      return {
        category: "sensors",
        score: 75,
        reason: "sensor/device event listener",
      };
    }
  }
  if (
    member == "constructor" &&
    /^(?:Worker|SharedWorker)$/.test(iface) &&
    args.some(a => /(?:^|\s)"(?:blob|data):/i.test(a))
  ) {
    return {
      category: "dynamic",
      score: 70,
      reason: "worker started from a blob: or data: URL",
    };
  }
  if (
    (member == "setTimeout" || member == "setInterval") &&
    args.some(a => a.startsWith('"'))
  ) {
    return {
      category: "dynamic",
      score: 55,
      reason: "string argument compiled as code",
    };
  }
  if (iface == "Document" && member == "createElement") {
    if (args.some(a => /^"(?:canvas|audio|video)"$/i.test(a))) {
      return { category: "canvas", score: 30, reason: "creates probe element" };
    }
  }
  return null;
}

/**
 * Ranks a recorded API.
 *
 * @param {string} name A recorded name, e.g. "WebGLRenderingContext.getParameter()".
 * @param {string[]} args Recorded first arguments, used for argument-specific scores.
 * @returns {object} The parsed name plus score, category, categoryLabel and reason.
 */
export function rankApi(name, args = []) {
  let parsed = parseApiName(name);
  // Workers expose the same fingerprinting surface under different names.
  let iface = parsed.iface.replace(/^Worker(Navigator|Location)$/, "$1");
  if (iface != parsed.iface) {
    let ranked = rankApi(name.replace(parsed.iface, iface), args);
    return { ...ranked, iface: parsed.iface, key: parsed.key };
  }
  let best = { category: "other", score: 0, reason: "" };
  for (let rule of COMPILED) {
    if (
      rule.regex.test(parsed.key) ||
      rule.regex.test(`${parsed.iface}.${parsed.member}`)
    ) {
      best = { category: rule.category, score: rule.score, reason: "" };
      break;
    }
  }
  let boost = argBoost(parsed, args);
  if (boost && boost.score > best.score) {
    best = boost;
  }
  return {
    ...parsed,
    ...best,
    categoryLabel: CATEGORIES[best.category],
  };
}

/**
 * Summarizes ranked APIs into a page-level risk.
 *
 * @param {object[]} rankedApis Results of rankApi.
 * @returns {{score: number, categories: string[]}} A 0-100 score and the
 *   distinct high-signal categories.
 */
export function pageRisk(rankedApis) {
  let byCategory = new Map();
  for (let api of rankedApis) {
    if (api.score < 50) {
      continue;
    }
    byCategory.set(
      api.category,
      Math.max(byCategory.get(api.category) ?? 0, api.score)
    );
  }
  let scores = [...byCategory.values()].sort((a, b) => b - a);
  let score = 0;
  let weight = 1;
  for (let s of scores) {
    score += s * weight;
    weight *= 0.5;
  }
  return {
    score: Math.min(100, Math.round(score / 2)),
    categories: [...byCategory.keys()],
  };
}
