/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/ApiAudit.h"
#include "mozilla/ApiAuditScripts.h"
#include "mozilla/ApiAuditService.h"

#include "js/Array.h"
#include "js/ArrayBuffer.h"
#include "js/CallAndConstruct.h"
#include "js/CharacterEncoding.h"
#include "js/ColumnNumber.h"
#include "js/Conversions.h"
#include "js/ErrorReport.h"
#include "js/Exception.h"
#include "js/Object.h"
#include "js/Promise.h"
#include "js/PropertyAndElement.h"
#include "js/PropertyDescriptor.h"
#include "js/Proxy.h"
#include "js/String.h"
#include "js/experimental/TypedData.h"
#include "jsapi.h"
#include "jsfriendapi.h"
#include "mozilla/Base64.h"
#include "mozilla/BasePrincipal.h"
#include "mozilla/ClearOnShutdown.h"
#include "mozilla/CycleCollectedJSContext.h"
#include "mozilla/HashFunctions.h"
#include "mozilla/JSONStringWriteFuncs.h"
#include "mozilla/JSONWriter.h"
#include "mozilla/Logging.h"
#include "mozilla/Preferences.h"
#include "mozilla/Services.h"
#include "mozilla/StaticMutex.h"
#include "mozilla/StaticPtr.h"
#include "mozilla/TextUtils.h"
#include "mozilla/UniquePtr.h"
#include "mozilla/dom/Blob.h"
#include "mozilla/dom/BlobBinding.h"
#include "mozilla/dom/BrowsingContext.h"
#include "mozilla/dom/DOMException.h"
#include "mozilla/dom/DOMExceptionBinding.h"
#include "mozilla/dom/Document.h"
#include "mozilla/dom/ServiceWorkerDescriptor.h"
#include "mozilla/dom/TrustedHTML.h"
#include "mozilla/dom/TrustedScript.h"
#include "mozilla/dom/TrustedScriptURL.h"
#include "mozilla/dom/TrustedTypesBinding.h"
#include "mozilla/dom/URL.h"
#include "mozilla/dom/URLBinding.h"
#include "mozilla/dom/WindowContext.h"
#include "mozilla/dom/WorkerCommon.h"
#include "mozilla/dom/WorkerPrivate.h"
#include "nsClassHashtable.h"
#include "nsGlobalWindowInner.h"
#include "nsHashKeys.h"
#include "nsIObserver.h"
#include "nsIObserverService.h"
#include "nsISupportsPrimitives.h"
#include "nsIURI.h"
#include "nsJSUtils.h"
#include "nsPIDOMWindowInlines.h"
#include "nsTArray.h"
#include "nsTHashMap.h"
#include "nsThreadUtils.h"
#include "prtime.h"
#include "xpcpublic.h"

namespace mozilla::apiaudit {

static LazyLogModule sLog("ApiAudit");

#define PREF_ENABLED "privacy.apiaudit.enabled"
#define PREF_RETAIN_SECONDS "privacy.apiaudit.retainSeconds"
#define PREF_MAX_CODE_LENGTH "privacy.apiaudit.maxCodeLength"

static constexpr uint32_t kMaxSamplesPerApi = 128;
static constexpr uint32_t kMaxDistinctArgs = 24;
static constexpr uint32_t kMaxDistinctScripts = 12;
static constexpr uint32_t kMaxDistinctCalls = 64;
static constexpr uint32_t kMaxArgLength = 200;
static constexpr uint32_t kMaxValueLength = 1024;
static constexpr uint32_t kMaxDescribedElements = 32;
static constexpr uint32_t kMaxDescribeDepth = 2;
static constexpr uint32_t kMaxScriptLength = 400;
static constexpr uint32_t kMaxCodeRecordsPerContext = 256;
static constexpr uint32_t kMaxCodeBytesPerContext = 32 * 1024 * 1024;
static constexpr uint32_t kDefaultMaxCodeLength = 512 * 1024;
static constexpr uint32_t kMaxPendingPromises = 4096;

// Window keys of workers that have no owning window (shared and service
// workers and their nested workers) have this bit set. Keys stay below 2^53
// so that they survive the JSON round trip to JS.
static constexpr uint64_t kWorkerWindowKeyBit = uint64_t(1) << 51;
static constexpr uint64_t kWorkerWindowKeyMask = kWorkerWindowKeyBit - 1;

Atomic<State, Relaxed> gState(State::Uninitialized);
static Atomic<uint32_t, Relaxed> sMaxCodeLength(kDefaultMaxCodeLength);
static Atomic<uint64_t> sNextWorkerSerial(0);
static Atomic<bool> sShutdown(false);

// One distinct way an API was called: its arguments, what it returned and
// the first script that called it that way.
struct CallRecord {
  nsTArray<nsCString> mArgs;
  nsCString mResult;
  nsCString mScript;
  uint64_t mCount = 0;
};

struct ApiStats {
  uint64_t mCount = 0;
  uint32_t mSamples = 0;
  PRTime mFirstSeen = 0;
  nsTArray<nsCString> mArgs;
  nsTArray<nsCString> mScripts;
  nsTArray<CallRecord> mCalls;
};

struct CodeRecord {
  const char* mKind = nullptr;
  nsCString mURL;
  nsCString mText;
  uint32_t mLength = 0;
  HashNumber mHash = 0;
  bool mTruncated = false;
  // The code contains a debugger statement, a common anti-analysis trap.
  bool mAntiDebug = false;
  // mText holds base64-encoded bytes (WebAssembly modules).
  bool mBase64 = false;
  uint64_t mCount = 0;
  PRTime mFirstSeen = 0;
};

// The main thread of a window, or one worker.
struct ContextRecord {
  uint64_t mSerial = 0;
  const char* mKind = "window";
  nsCString mURL;
  nsCString mName;
  nsCString mParentURL;
  PRTime mFirstSeen = 0;
  nsClassHashtable<nsDepCharHashKey, ApiStats> mApis;
  nsTArray<CodeRecord> mCode;
  size_t mCodeBytes = 0;
};

struct WindowRecord {
  bool mHasMetadata = false;
  bool mIsTop = false;
  bool mIsWorker = false;
  uint64_t mTopInnerWindowId = 0;
  uint64_t mBrowserId = 0;
  nsCString mURL;
  nsCString mOrigin;
  // For windows: the service worker controlling them. For service worker
  // entries: the service worker itself. Ids match across processes.
  uint64_t mServiceWorkerId = 0;
  nsCString mServiceWorkerScope;
  nsCString mServiceWorkerURL;
  PRTime mDestroyedAt = 0;
  PRTime mLastSeen = 0;
  nsTArray<UniquePtr<ContextRecord>> mContexts;
};

// Identifies where a call is made from. Computed without holding sMutex.
struct ContextKey {
  uint64_t mWindowKey = 0;
  uint64_t mSerial = 0;
  nsGlobalWindowInner* mWindow = nullptr;
  dom::WorkerPrivate* mWorker = nullptr;
};

struct CallSample {
  JSContext* mCx = nullptr;
  ContextKey mKey;
  const char* mName = nullptr;
  nsCString mCaller;
  nsTArray<nsCString> mArgs;
};

// A call that returned a promise, waiting for the promise to settle.
struct PendingPromise {
  uint64_t mWindowKey = 0;
  uint64_t mSerial = 0;
  const char* mName = nullptr;
  nsTArray<nsCString> mArgs;
  nsCString mScript;
};

static StaticMutex sMutex;
static StaticAutoPtr<nsClassHashtable<nsUint64HashKey, WindowRecord>> sWindows
    MOZ_GUARDED_BY(sMutex);
static StaticAutoPtr<nsClassHashtable<nsUint64HashKey, PendingPromise>>
    sPendingPromises MOZ_GUARDED_BY(sMutex);
static uint64_t sNextPromiseId MOZ_GUARDED_BY(sMutex) = 0;

static void BuiltinCalled(JSContext* aCx, const char* aName,
                          const JS::CallArgs& aArgs, bool aOk);

static void PrefChanged(const char*, void*) {
  gState = Preferences::GetBool(PREF_ENABLED, true) ? State::Enabled
                                                    : State::Disabled;
  sMaxCodeLength =
      Preferences::GetUint(PREF_MAX_CODE_LENGTH, kDefaultMaxCodeLength);
}

static void PurgeDestroyedLocked() MOZ_REQUIRES(sMutex) {
  if (!sWindows) {
    return;
  }
  PRTime cutoff =
      PR_Now() -
      PRTime(Preferences::GetUint(PREF_RETAIN_SECONDS, 600)) * PR_USEC_PER_SEC;
  for (auto iter = sWindows->Iter(); !iter.Done(); iter.Next()) {
    const WindowRecord& record = *iter.Data();
    PRTime destroyedAt =
        record.mIsWorker ? record.mLastSeen : record.mDestroyedAt;
    if (destroyedAt && destroyedAt < cutoff) {
      iter.Remove();
    }
  }
}

class WindowObserver final : public nsIObserver {
 public:
  NS_DECL_ISUPPORTS

  NS_IMETHOD Observe(nsISupports* aSubject, const char* aTopic,
                     const char16_t*) override {
    if (!strcmp(aTopic, "xpcom-shutdown")) {
      if (nsCOMPtr<nsIObserverService> obs = services::GetObserverService()) {
        obs->RemoveObserver(this, "inner-window-destroyed");
        obs->RemoveObserver(this, "xpcom-shutdown");
      }
      sShutdown = true;
      gState = State::Disabled;
      js::SetBuiltinAuditHook(nullptr);
      StaticMutexAutoLock lock(sMutex);
      sWindows = nullptr;
      sPendingPromises = nullptr;
      return NS_OK;
    }

    nsCOMPtr<nsISupportsPRUint64> wrapper = do_QueryInterface(aSubject);
    uint64_t id = 0;
    if (!wrapper || NS_FAILED(wrapper->GetData(&id))) {
      return NS_OK;
    }
    StaticMutexAutoLock lock(sMutex);
    if (!sWindows) {
      return NS_OK;
    }
    if (WindowRecord* record = sWindows->Get(id)) {
      record->mDestroyedAt = PR_Now();
    }
    PurgeDestroyedLocked();
    return NS_OK;
  }

 private:
  ~WindowObserver() = default;
};

NS_IMPL_ISUPPORTS(WindowObserver, nsIObserver)

// Called until the main thread has read the prefs. Worker threads record
// with the default (enabled) state in the meantime, so that a process that
// only runs a service worker is not missed.
bool InitSlow() {
  if (sShutdown) {
    return false;
  }
  {
    StaticMutexAutoLock lock(sMutex);
    if (!sWindows) {
      sWindows = new nsClassHashtable<nsUint64HashKey, WindowRecord>();
      sPendingPromises =
          new nsClassHashtable<nsUint64HashKey, PendingPromise>();
      js::SetBuiltinAuditHook(BuiltinCalled);
    }
  }
  if (!NS_IsMainThread()) {
    static Atomic<bool> sDispatched(false);
    if (!sDispatched.exchange(true)) {
      NS_DispatchToMainThread(
          NS_NewRunnableFunction("apiaudit::InitSlow", [] { InitSlow(); }));
    }
    return true;
  }
  static bool sMainThreadInitialized = false;
  if (sMainThreadInitialized) {
    return gState == State::Enabled;
  }
  sMainThreadInitialized = true;
  Preferences::RegisterCallbackAndCall(PrefChanged, PREF_ENABLED ""_ns);
  Preferences::RegisterCallback(PrefChanged, PREF_MAX_CODE_LENGTH ""_ns);
  if (nsCOMPtr<nsIObserverService> obs = services::GetObserverService()) {
    RefPtr<WindowObserver> observer = new WindowObserver();
    obs->AddObserver(observer, "inner-window-destroyed", false);
    obs->AddObserver(observer, "xpcom-shutdown", false);
  }
  if (gState == State::Uninitialized) {
    gState = State::Disabled;
  }
  return gState == State::Enabled;
}

static const char* WorkerKindName(dom::WorkerPrivate* aWorker) {
  if (aWorker->IsServiceWorker()) {
    return "service-worker";
  }
  if (aWorker->IsSharedWorker()) {
    return "shared-worker";
  }
  return "dedicated-worker";
}

// Returns a serial number unique to the worker running on this thread.
// Worker threads are recycled, so the cached serial is only reused when both
// the WorkerPrivate and its script URL buffer are unchanged.
static uint64_t WorkerSerial(dom::WorkerPrivate* aWorker) {
  static thread_local dom::WorkerPrivate* tWorker = nullptr;
  static thread_local const char16_t* tScriptURL = nullptr;
  static thread_local uint64_t tSerial = 0;
  const char16_t* scriptURL = aWorker->ScriptURL().BeginReading();
  if (tWorker != aWorker || tScriptURL != scriptURL) {
    tWorker = aWorker;
    tScriptURL = scriptURL;
    tSerial = ++sNextWorkerSerial;
  }
  return tSerial;
}

static bool GetContextKey(JSContext* aCx, ContextKey& aKey) {
  if (CycleCollectedJSContext* ccjscx = CycleCollectedJSContext::Get();
      !ccjscx || ccjscx->IsSystemCaller()) {
    return false;
  }
  if (NS_IsMainThread()) {
    aKey.mWindow = xpc::CurrentWindowOrNull(aCx);
    aKey.mWindowKey = aKey.mWindow ? aKey.mWindow->WindowID() : 0;
    return aKey.mWindowKey != 0;
  }
  aKey.mWorker = dom::GetCurrentThreadWorkerPrivate();
  if (!aKey.mWorker) {
    return false;
  }
  aKey.mSerial = WorkerSerial(aKey.mWorker);
  dom::WorkerPrivate* top = aKey.mWorker;
  while (top->GetParent()) {
    top = top->GetParent();
  }
  if (top->IsDedicatedWorker() && top->WindowID()) {
    aKey.mWindowKey = top->WindowID();
  } else {
    // The top-level worker's address plus its script URL identify it from
    // any of its nested workers' threads.
    HashNumber hash = AddToHash(HashString(top->ScriptURL()), top);
    aKey.mWindowKey =
        kWorkerWindowKeyBit |
        ((uint64_t(hash) << 16 ^ uintptr_t(top)) & kWorkerWindowKeyMask);
  }
  return true;
}

static void FillWindowMetadata(nsGlobalWindowInner* aWin,
                               WindowRecord& aRecord) {
  nsIURI* uri = aWin->GetDocumentURI();
  if (!uri) {
    return;
  }
  aRecord.mHasMetadata = true;
  uri->GetSpec(aRecord.mURL);
  if (nsIPrincipal* principal = aWin->GetPrincipal()) {
    principal->GetWebExposedOriginSerialization(aRecord.mOrigin);
  }
  if (dom::WindowContext* wc = aWin->GetWindowContext()) {
    dom::WindowContext* top = wc->TopWindowContext();
    aRecord.mTopInnerWindowId = top ? top->InnerWindowId() : 0;
    aRecord.mIsTop = top == wc;
  }
  if (dom::BrowsingContext* bc = aWin->GetBrowsingContext()) {
    aRecord.mBrowserId = bc->BrowserId();
  }
  if (Maybe<dom::ServiceWorkerDescriptor> controller = aWin->GetController()) {
    aRecord.mServiceWorkerId = controller->Id();
    aRecord.mServiceWorkerScope = controller->Scope();
    aRecord.mServiceWorkerURL = controller->ScriptURL();
  }
}

static void WorkerScriptURL(dom::WorkerPrivate* aWorker, nsACString& aURL) {
  // The resolved script URI of a service worker is its client's URL.
  if (aWorker->IsServiceWorker()) {
    aURL = aWorker->GetServiceWorkerDescriptor().ScriptURL();
  } else if (nsIURI* uri = aWorker->GetResolvedScriptURI()) {
    uri->GetSpec(aURL);
  } else {
    CopyUTF16toUTF8(aWorker->ScriptURL(), aURL);
  }
}

static ContextRecord* GetOrCreateContextLocked(const ContextKey& aKey)
    MOZ_REQUIRES(sMutex) {
  if (!sWindows) {
    return nullptr;
  }
  WindowRecord* record = sWindows->GetOrInsertNew(aKey.mWindowKey);
  if (aKey.mWindowKey & kWorkerWindowKeyBit) {
    record->mLastSeen = PR_Now();
  }
  if (aKey.mWindow && !record->mHasMetadata) {
    FillWindowMetadata(aKey.mWindow, *record);
  }
  for (auto& context : record->mContexts) {
    if (context->mSerial == aKey.mSerial) {
      return context.get();
    }
  }

  auto* context =
      record->mContexts.AppendElement(MakeUnique<ContextRecord>())->get();
  context->mSerial = aKey.mSerial;
  context->mFirstSeen = PR_Now();
  if (dom::WorkerPrivate* worker = aKey.mWorker) {
    context->mKind = WorkerKindName(worker);
    WorkerScriptURL(worker, context->mURL);
    CopyUTF16toUTF8(worker->WorkerName(), context->mName);
    if (dom::WorkerPrivate* parent = worker->GetParent()) {
      WorkerScriptURL(parent, context->mParentURL);
    }
    if (aKey.mWindowKey & kWorkerWindowKeyBit && !record->mHasMetadata) {
      record->mHasMetadata = true;
      record->mIsWorker = true;
      record->mIsTop = true;
      record->mURL = context->mURL;
      CopyUTF16toUTF8(worker->GetLocationInfo().mOrigin, record->mOrigin);
      if (worker->IsServiceWorker()) {
        const dom::ServiceWorkerDescriptor& descriptor =
            worker->GetServiceWorkerDescriptor();
        record->mServiceWorkerId = descriptor.Id();
        record->mServiceWorkerScope = descriptor.Scope();
        record->mServiceWorkerURL = descriptor.ScriptURL();
      }
    }
  }
  MOZ_LOG(sLog, LogLevel::Info,
          ("window=%" PRIu64 " new context %s %s", aKey.mWindowKey,
           context->mKind, context->mURL.get()));
  return context;
}

static ContextRecord* GetContextLocked(uint64_t aWindowKey, uint64_t aSerial)
    MOZ_REQUIRES(sMutex) {
  if (!sWindows) {
    return nullptr;
  }
  WindowRecord* record = sWindows->Get(aWindowKey);
  if (!record) {
    return nullptr;
  }
  for (auto& context : record->mContexts) {
    if (context->mSerial == aSerial) {
      return context.get();
    }
  }
  return nullptr;
}

static ContextRecord* GetContextLocked(const ContextKey& aKey)
    MOZ_REQUIRES(sMutex) {
  return GetContextLocked(aKey.mWindowKey, aKey.mSerial);
}

static HashNumber HashLinearString(JSLinearString* aStr) {
  JS::AutoCheckCannotGC nogc;
  size_t length = JS::GetLinearStringLength(aStr);
  if (JS::LinearStringHasLatin1Chars(aStr)) {
    const JS::Latin1Char* chars = JS::GetLatin1LinearStringChars(nogc, aStr);
    HashNumber hash = 0;
    for (size_t i = 0; i < length; i++) {
      hash = AddToHash(hash, char16_t(chars[i]));
    }
    return hash;
  }
  return HashString(JS::GetTwoByteLinearStringChars(nogc, aStr), length);
}

// Converts at most aMaxLength UTF-16 code units of aStr to UTF-8.
static bool StringToUTF8(JSContext* aCx, JS::Handle<JSString*> aStr,
                         uint32_t aMaxLength, nsACString& aOut,
                         bool* aTruncated) {
  JS::Rooted<JSString*> str(aCx, aStr);
  size_t length = JS::GetStringLength(str);
  *aTruncated = length > aMaxLength;
  if (*aTruncated) {
    str = JS_NewDependentString(aCx, str, 0, aMaxLength);
  }
  nsAutoJSCString chars;
  if (!str || !chars.init(aCx, str)) {
    JS_ClearPendingException(aCx);
    return false;
  }
  aOut.Assign(chars);
  return true;
}

static void AppendQuoted(const nsAString& aValue, nsACString& aOut) {
  aOut.Append('"');
  AppendUTF16toUTF8(Substring(aValue, 0, kMaxArgLength), aOut);
  if (aValue.Length() > kMaxArgLength) {
    aOut.AppendPrintf("...\" (%zu chars)", aValue.Length());
    return;
  }
  aOut.Append('"');
}

// Strings longer than kMaxArgLength are cut, and followed by their length and
// a hash of the whole string so that long outputs (toDataURL()) can still be
// compared.
static void AppendString(JSContext* aCx, JS::Handle<JSString*> aStr,
                         nsACString& aOut) {
  nsAutoCString chars;
  bool truncated = false;
  if (!StringToUTF8(aCx, aStr, kMaxArgLength, chars, &truncated)) {
    aOut.AppendLiteral("<string>");
    return;
  }
  aOut.Append('"');
  aOut.Append(chars);
  if (!truncated) {
    aOut.Append('"');
    return;
  }
  aOut.AppendLiteral("...\"");
  JSLinearString* linear = JS_EnsureLinearString(aCx, aStr);
  if (!linear) {
    JS_ClearPendingException(aCx);
    return;
  }
  aOut.AppendPrintf(" (%zu chars #%08x)", JS::GetStringLength(aStr),
                    HashLinearString(linear));
}

static void AppendBytesSummary(const char* aClassName, size_t aLength,
                               const uint8_t* aData, size_t aByteLength,
                               nsACString& aOut) {
  aOut.AppendPrintf("%s(%zu) #%08x", aClassName, aLength,
                    aData ? HashBytes(aData, aByteLength) : 0);
}

// Describes the DOM objects that wrap a URL or code string, such as the
// TrustedScriptURL passed to new Worker() on pages that enforce Trusted
// Types, without running any page script.
static bool DescribeDOMObject(JSContext* aCx, JS::Handle<JSObject*> aObj,
                              nsACString& aOut) {
  JS::Rooted<JSObject*> obj(aCx, aObj);
  {
    dom::TrustedScriptURL* trusted = nullptr;
    if (NS_SUCCEEDED(UNWRAP_OBJECT(TrustedScriptURL, &obj, trusted))) {
      aOut.AppendLiteral("TrustedScriptURL ");
      AppendQuoted(trusted->mData, aOut);
      return true;
    }
  }
  {
    dom::TrustedScript* trusted = nullptr;
    if (NS_SUCCEEDED(UNWRAP_OBJECT(TrustedScript, &obj, trusted))) {
      aOut.AppendLiteral("TrustedScript ");
      AppendQuoted(trusted->mData, aOut);
      return true;
    }
  }
  {
    dom::TrustedHTML* trusted = nullptr;
    if (NS_SUCCEEDED(UNWRAP_OBJECT(TrustedHTML, &obj, trusted))) {
      aOut.AppendLiteral("TrustedHTML ");
      AppendQuoted(trusted->mData, aOut);
      return true;
    }
  }
  {
    dom::URL* url = nullptr;
    if (NS_SUCCEEDED(UNWRAP_OBJECT(URL, &obj, url))) {
      nsAutoCString href;
      url->GetHref(href);
      aOut.AppendLiteral("URL ");
      AppendQuoted(NS_ConvertUTF8toUTF16(href), aOut);
      return true;
    }
  }
  {
    dom::Blob* blob = nullptr;
    if (NS_SUCCEEDED(UNWRAP_OBJECT(Blob, &obj, blob))) {
      IgnoredErrorResult rv;
      uint64_t size = blob->GetSize(rv);
      nsAutoString type;
      blob->GetType(type);
      aOut.AppendPrintf("[Blob %" PRIu64 " bytes %s]", size,
                        NS_ConvertUTF16toUTF8(type).get());
      return true;
    }
  }
  {
    dom::DOMException* exception = nullptr;
    if (NS_SUCCEEDED(UNWRAP_OBJECT(DOMException, &obj, exception))) {
      nsAutoString name;
      nsAutoString message;
      exception->GetName(name);
      exception->GetMessageMoz(message);
      aOut.AppendPrintf("%s: ", NS_ConvertUTF16toUTF8(name).get());
      AppendQuoted(message, aOut);
      return true;
    }
  }
  return false;
}

static void DescribeValue(JSContext* aCx, JS::Handle<JS::Value> aValue,
                          nsACString& aOut, uint32_t aDepth);

static void DescribeArrayElements(JSContext* aCx, JS::Handle<JSObject*> aObj,
                                  nsACString& aOut, uint32_t aDepth) {
  uint32_t length = 0;
  if (!JS::GetArrayLength(aCx, aObj, &length)) {
    JS_ClearPendingException(aCx);
    aOut.AppendLiteral("[Array]");
    return;
  }
  if (aDepth >= kMaxDescribeDepth) {
    aOut.AppendPrintf("[Array(%u)]", length);
    return;
  }
  aOut.Append('[');
  for (uint32_t i = 0; i < length; i++) {
    if (i) {
      aOut.AppendLiteral(", ");
    }
    if (i >= kMaxDescribedElements || aOut.Length() > kMaxValueLength) {
      aOut.AppendPrintf("... %u more", length - i);
      break;
    }
    JS::Rooted<JS::PropertyKey> id(aCx, JS::PropertyKey::Int(int32_t(i)));
    JS::Rooted<Maybe<JS::PropertyDescriptor>> desc(aCx);
    if (!JS_GetOwnPropertyDescriptorById(aCx, aObj, id, &desc)) {
      JS_ClearPendingException(aCx);
      aOut.Append('?');
      continue;
    }
    if (desc.isNothing() || !desc->isDataDescriptor()) {
      aOut.Append('?');
      continue;
    }
    JS::Rooted<JS::Value> element(aCx, desc->value());
    DescribeValue(aCx, element, aOut, aDepth + 1);
  }
  aOut.Append(']');
}

static void DescribePlainObject(JSContext* aCx, JS::Handle<JSObject*> aObj,
                                nsACString& aOut, uint32_t aDepth) {
  if (aDepth >= kMaxDescribeDepth) {
    aOut.AppendLiteral("{...}");
    return;
  }
  JS::Rooted<JS::IdVector> ids(aCx, JS::IdVector(aCx));
  if (!JS_Enumerate(aCx, aObj, &ids)) {
    JS_ClearPendingException(aCx);
    aOut.AppendLiteral("{?}");
    return;
  }
  aOut.Append('{');
  for (size_t i = 0; i < ids.length(); i++) {
    if (i) {
      aOut.AppendLiteral(", ");
    }
    if (i >= kMaxDescribedElements || aOut.Length() > kMaxValueLength) {
      aOut.AppendPrintf("... %zu more", ids.length() - i);
      break;
    }
    JS::Rooted<JS::PropertyKey> id(aCx, ids[i]);
    JS::Rooted<JS::Value> key(aCx);
    if (!JS_IdToValue(aCx, id, &key)) {
      JS_ClearPendingException(aCx);
      continue;
    }
    if (key.isString()) {
      JS::Rooted<JSString*> keyStr(aCx, key.toString());
      nsAutoCString keyChars;
      bool truncated = false;
      if (StringToUTF8(aCx, keyStr, kMaxArgLength, keyChars, &truncated)) {
        aOut.Append(keyChars);
      }
    } else if (key.isInt32()) {
      aOut.AppendInt(key.toInt32());
    } else {
      aOut.AppendLiteral("<symbol>");
    }
    aOut.AppendLiteral(": ");
    JS::Rooted<Maybe<JS::PropertyDescriptor>> desc(aCx);
    if (!JS_GetOwnPropertyDescriptorById(aCx, aObj, id, &desc)) {
      JS_ClearPendingException(aCx);
      aOut.Append('?');
      continue;
    }
    if (desc.isNothing() || !desc->isDataDescriptor()) {
      aOut.Append('?');
      continue;
    }
    JS::Rooted<JS::Value> value(aCx, desc->value());
    DescribeValue(aCx, value, aOut, aDepth + 1);
  }
  aOut.Append('}');
}

// Describes aObj without running page script: proxies (including
// cross-compartment wrappers) are only described by their class.
static void DescribeObject(JSContext* aCx, JS::Handle<JSObject*> aObj,
                           nsACString& aOut, uint32_t aDepth) {
  JS::Rooted<JSObject*> unwrapped(aCx, js::UncheckedUnwrap(aObj));
  {
    size_t length = 0;
    bool isShared = false;
    uint8_t* data = nullptr;
    if (JSObject* view = JS_GetObjectAsArrayBufferView(unwrapped, &length,
                                                       &isShared, &data)) {
      size_t byteLength = JS_GetArrayBufferViewByteLength(view);
      size_t elements = length;
      if (JS_IsTypedArrayObject(view)) {
        elements = JS_GetTypedArrayLength(view);
      }
      AppendBytesSummary(JS::GetClass(view)->name, elements, data, byteLength,
                         aOut);
      return;
    }
    if (JSObject* buffer =
            JS::GetObjectAsArrayBuffer(unwrapped, &length, &data)) {
      AppendBytesSummary(JS::GetClass(buffer)->name, length, data, length,
                         aOut);
      return;
    }
  }
  if (DescribeDOMObject(aCx, aObj, aOut)) {
    return;
  }
  if (js::IsProxy(aObj)) {
    aOut.AppendPrintf("[object %s]", JS::GetClass(unwrapped)->name);
    return;
  }
  if (JS_ObjectIsFunction(aObj)) {
    JS::Rooted<JSFunction*> fun(aCx, JS_GetObjectFunction(aObj));
    JS::Rooted<JSString*> name(aCx);
    aOut.AppendLiteral("[function");
    if (fun && JS_GetFunctionId(aCx, fun, &name) && name) {
      nsAutoCString chars;
      bool truncated = false;
      if (StringToUTF8(aCx, name, kMaxArgLength, chars, &truncated) &&
          !chars.IsEmpty()) {
        aOut.Append(' ');
        aOut.Append(chars);
      }
    }
    JS_ClearPendingException(aCx);
    aOut.Append(']');
    return;
  }
  bool isArray = false;
  if (JS::IsArrayObject(aCx, aObj, &isArray) && isArray) {
    DescribeArrayElements(aCx, aObj, aOut, aDepth);
    return;
  }
  JS_ClearPendingException(aCx);
  if (JS::IsPlainObject(aObj)) {
    DescribePlainObject(aCx, aObj, aOut, aDepth);
    return;
  }
  js::ESClass cls = js::ESClass::Other;
  if (JS::GetBuiltinClass(aCx, aObj, &cls) && cls == js::ESClass::Error) {
    JS::BorrowedErrorReport report(aCx);
    if (JS_ErrorFromException(aCx, aObj, report) && report->message()) {
      aOut.AppendPrintf("Error: \"%s\"", report->message().c_str());
      return;
    }
  }
  JS_ClearPendingException(aCx);
  aOut.AppendPrintf("[object %s]", JS::GetClass(aObj)->name);
}

static void DescribeValue(JSContext* aCx, JS::Handle<JS::Value> aValue,
                          nsACString& aOut, uint32_t aDepth) {
  if (aValue.isUndefined()) {
    aOut.AppendLiteral("undefined");
  } else if (aValue.isNull()) {
    aOut.AppendLiteral("null");
  } else if (aValue.isBoolean()) {
    aOut.Append(aValue.toBoolean() ? "true" : "false");
  } else if (aValue.isInt32()) {
    aOut.AppendInt(aValue.toInt32());
  } else if (aValue.isNumber()) {
    char chars[JS::MaximumNumberToStringLength];
    JS::NumberToString(aValue.toNumber(), chars);
    aOut.Append(chars);
  } else if (aValue.isString()) {
    JS::Rooted<JSString*> str(aCx, aValue.toString());
    AppendString(aCx, str, aOut);
  } else if (aValue.isObject()) {
    JS::Rooted<JSObject*> obj(aCx, &aValue.toObject());
    DescribeObject(aCx, obj, aOut, aDepth);
  } else if (aValue.isSymbol()) {
    aOut.AppendLiteral("<symbol>");
  } else if (aValue.isBigInt()) {
    aOut.AppendLiteral("<bigint>");
  } else {
    aOut.AppendLiteral("<other>");
  }
}

// Describes aValue in the current compartment, leaving any pending exception
// in place.
static void DescribeTopLevel(JSContext* aCx, JS::Handle<JS::Value> aValue,
                             nsACString& aOut) {
  JS::AutoSaveExceptionState savedException(aCx);
  JS::Rooted<JS::Value> value(aCx, aValue);
  if (!JS_WrapValue(aCx, &value)) {
    JS_ClearPendingException(aCx);
    aOut.AppendLiteral("<unavailable>");
    return;
  }
  DescribeValue(aCx, value, aOut, 0);
}

static void DescribeCaller(JSContext* aCx, nsACString& aOut) {
  JS::AutoFilename filename;
  uint32_t lineno = 0;
  JS::ColumnNumberOneOrigin column;
  if (!JS::DescribeScriptedCaller(&filename, aCx, &lineno, &column) ||
      !filename.get()) {
    return;
  }
  aOut.Assign(filename.get());
  if (aOut.Length() > kMaxScriptLength) {
    aOut.Truncate(kMaxScriptLength);
    aOut.AppendLiteral("...");
  }
  aOut.AppendPrintf(":%u:%u", lineno, column.oneOriginValue());
}

static void AppendDistinct(nsTArray<nsCString>& aArray, const nsCString& aValue,
                           uint32_t aMax) {
  if (aValue.IsEmpty() || aArray.Length() >= aMax || aArray.Contains(aValue)) {
    return;
  }
  aArray.AppendElement(aValue);
}

static void AppendCallLocked(ApiStats& aStats, nsTArray<nsCString>&& aArgs,
                             const nsACString& aResult,
                             const nsACString& aScript) {
  for (CallRecord& call : aStats.mCalls) {
    if (call.mResult == aResult && call.mArgs == aArgs) {
      call.mCount++;
      return;
    }
  }
  if (aStats.mCalls.Length() >= kMaxDistinctCalls) {
    return;
  }
  CallRecord* call = aStats.mCalls.AppendElement();
  call->mArgs = std::move(aArgs);
  call->mResult = aResult;
  call->mScript = aScript;
  call->mCount = 1;
}

// Counts a call and, for sampled calls, records aArgDesc and the caller.
// Returns whether the call is sampled.
static bool RecordApiDesc(const ContextKey& aKey, const char* aName,
                          const nsACString& aArgDesc, const nsACString& aCaller,
                          nsTArray<nsCString>* aCallArgs = nullptr,
                          const nsACString* aResult = nullptr) {
  bool first = false;
  {
    StaticMutexAutoLock lock(sMutex);
    ContextRecord* context = GetOrCreateContextLocked(aKey);
    if (!context) {
      return false;
    }
    ApiStats* stats = context->mApis.GetOrInsertNew(aName);
    first = stats->mCount == 0;
    if (first) {
      stats->mFirstSeen = PR_Now();
    }
    stats->mCount++;
    if (stats->mSamples >= kMaxSamplesPerApi) {
      return false;
    }
    stats->mSamples++;
    AppendDistinct(stats->mArgs, nsCString(aArgDesc), kMaxDistinctArgs);
    AppendDistinct(stats->mScripts, nsCString(aCaller), kMaxDistinctScripts);
    if (aCallArgs) {
      AppendCallLocked(*stats, std::move(*aCallArgs),
                       aResult ? *aResult : EmptyCString(), aCaller);
    }
  }
  if (first) {
    MOZ_LOG(sLog, LogLevel::Info,
            ("window=%" PRIu64 " context=%" PRIu64 " %s%s%s caller=%s",
             aKey.mWindowKey, aKey.mSerial, aName,
             aArgDesc.IsEmpty() ? "" : " arg=",
             PromiseFlatCString(aArgDesc).get(),
             PromiseFlatCString(aCaller).get()));
  }
  MOZ_LOG(sLog, LogLevel::Verbose,
          ("window=%" PRIu64 " context=%" PRIu64 " %s arg=%s caller=%s",
           aKey.mWindowKey, aKey.mSerial, aName,
           PromiseFlatCString(aArgDesc).get(),
           PromiseFlatCString(aCaller).get()));
  return true;
}

// Counts a call and returns whether it is sampled. Only sampled calls pay for
// describing their first argument and caller.
static bool CountCall(const ContextKey& aKey, const char* aName) {
  StaticMutexAutoLock lock(sMutex);
  ContextRecord* context = GetOrCreateContextLocked(aKey);
  if (!context) {
    return false;
  }
  ApiStats* stats = context->mApis.GetOrInsertNew(aName);
  if (stats->mCount == 0) {
    stats->mFirstSeen = PR_Now();
  }
  stats->mCount++;
  if (stats->mSamples >= kMaxSamplesPerApi) {
    return false;
  }
  stats->mSamples++;
  return true;
}

static void AddSampleLocked(const ContextKey& aKey, const char* aName,
                            const nsACString& aArgDesc,
                            const nsACString& aCaller) MOZ_REQUIRES(sMutex) {
  ContextRecord* context = GetContextLocked(aKey);
  if (!context) {
    return;
  }
  if (ApiStats* stats = context->mApis.Get(aName)) {
    AppendDistinct(stats->mArgs, nsCString(aArgDesc), kMaxDistinctArgs);
    AppendDistinct(stats->mScripts, nsCString(aCaller), kMaxDistinctScripts);
  }
}

static void LogCall(const ContextKey& aKey, const char* aName,
                    const nsACString& aArgDesc, const nsACString& aCaller) {
  MOZ_LOG(sLog, LogLevel::Verbose,
          ("window=%" PRIu64 " context=%" PRIu64 " %s arg=%s caller=%s",
           aKey.mWindowKey, aKey.mSerial, aName,
           PromiseFlatCString(aArgDesc).get(),
           PromiseFlatCString(aCaller).get()));
}

static void RecordApi(JSContext* aCx, const ContextKey& aKey, const char* aName,
                      JS::Handle<JS::Value> aArg, bool aHasArg) {
  if (!CountCall(aKey, aName)) {
    return;
  }
  nsAutoCString argDesc;
  if (aHasArg) {
    DescribeTopLevel(aCx, aArg, argDesc);
  }
  nsAutoCString caller;
  DescribeCaller(aCx, caller);
  LogCall(aKey, aName, argDesc, caller);
  StaticMutexAutoLock lock(sMutex);
  AddSampleLocked(aKey, aName, argDesc, caller);
}

// Whether aText contains the `debugger` keyword as a statement rather than
// as part of an identifier or property name. Strings and comments that
// contain the word also match.
static bool ContainsDebuggerKeyword(const nsACString& aText) {
  constexpr auto keyword = "debugger"_ns;
  auto isIdentifierChar = [](char aChar) {
    return IsAsciiAlphanumeric(aChar) || aChar == '_' || aChar == '$' ||
           aChar == '.';
  };
  int32_t from = 0;
  while ((from = aText.Find(keyword, from)) != kNotFound) {
    uint32_t end = from + keyword.Length();
    if ((!from || !isIdentifierChar(aText[from - 1])) &&
        (end == aText.Length() || !isIdentifierChar(aText[end]))) {
      return true;
    }
    from = int32_t(end);
  }
  return false;
}

static void StoreCode(uint64_t aWindowKey, uint64_t aSerial,
                      const ContextKey* aKey, const char* aKind,
                      const nsACString& aURL, nsCString&& aText,
                      uint32_t aLength, HashNumber aHash, bool aTruncated,
                      bool aAntiDebug, bool aBase64) {
  StaticMutexAutoLock lock(sMutex);
  ContextRecord* context = aKey ? GetOrCreateContextLocked(*aKey)
                                : GetContextLocked(aWindowKey, aSerial);
  if (!context) {
    return;
  }
  for (CodeRecord& code : context->mCode) {
    if (code.mHash == aHash && code.mLength == aLength &&
        !strcmp(code.mKind, aKind)) {
      code.mCount++;
      return;
    }
  }
  if (context->mCode.Length() >= kMaxCodeRecordsPerContext) {
    return;
  }
  if (context->mCodeBytes + aText.Length() > kMaxCodeBytesPerContext) {
    aText.Truncate();
    aTruncated = true;
  }
  context->mCodeBytes += aText.Length();
  CodeRecord* code = context->mCode.AppendElement();
  code->mKind = aKind;
  code->mURL = aURL;
  code->mText = std::move(aText);
  code->mLength = aLength;
  code->mHash = aHash;
  code->mTruncated = aTruncated;
  code->mAntiDebug = aAntiDebug;
  code->mBase64 = aBase64;
  code->mCount = 1;
  code->mFirstSeen = PR_Now();
}

static void RecordCode(JSContext* aCx, const ContextKey& aKey,
                       const char* aKind, const nsACString& aURL,
                       nsCString&& aText, uint32_t aLength, bool aTruncated) {
  bool antiDebug = ContainsDebuggerKeyword(aText);
  if (antiDebug) {
    nsAutoCString where(aKind);
    if (!aURL.IsEmpty()) {
      where.Append(' ');
      where.Append(aURL);
    }
    JS::Rooted<JS::Value> arg(aCx);
    if (JSString* str = JS_NewStringCopyN(aCx, where.get(), where.Length())) {
      arg.setString(str);
    } else {
      JS_ClearPendingException(aCx);
    }
    RecordApi(aCx, aKey, "debugger()", arg, !arg.isUndefined());
  }

  HashNumber hash = HashString(aText.BeginReading(), aText.Length());
  MOZ_LOG(sLog, LogLevel::Info,
          ("window=%" PRIu64 " context=%" PRIu64 " %s %s (%u chars)",
           aKey.mWindowKey, aKey.mSerial, aKind, PromiseFlatCString(aURL).get(),
           aLength));
  StoreCode(aKey.mWindowKey, aKey.mSerial, &aKey, aKind, aURL,
            std::move(aText), aLength, hash, aTruncated, antiDebug, false);
}

static void RecordBytes(uint64_t aWindowKey, uint64_t aSerial,
                        const ContextKey* aKey, const char* aKind,
                        const nsACString& aURL, const nsACString& aBytes,
                        uint32_t aLength, bool aTruncated) {
  HashNumber hash = HashBytes(aBytes.BeginReading(), aBytes.Length());
  nsCString text;
  if (NS_FAILED(Base64Encode(aBytes, text))) {
    return;
  }
  MOZ_LOG(sLog, LogLevel::Info,
          ("window=%" PRIu64 " context=%" PRIu64 " %s %s (%u bytes)",
           aWindowKey, aSerial, aKind, PromiseFlatCString(aURL).get(),
           aLength));
  StoreCode(aWindowKey, aSerial, aKey, aKind, aURL, std::move(text), aLength,
            hash, aTruncated, false, true);
}

static uint32_t MaxCapturedBytes() { return sMaxCodeLength / 4 * 3; }

// setTimeout() and setInterval() compile string arguments without going
// through the eval() security callback.
static const char* StringTimerKind(const char* aName) {
  const char* dot = strrchr(aName, '.');
  if (!dot) {
    return nullptr;
  }
  if (!strcmp(dot, ".setTimeout()")) {
    return "setTimeout";
  }
  if (!strcmp(dot, ".setInterval()")) {
    return "setInterval";
  }
  return nullptr;
}

CallSample* BeginCall(JSContext* aCx, const char* aName,
                      JS::Handle<JS::Value> aFirstArg, bool aHasArg) {
  ContextKey key;
  if (!GetContextKey(aCx, key)) {
    return nullptr;
  }
  bool sampled = CountCall(key, aName);
  if (aHasArg && aFirstArg.isString()) {
    if (const char* kind = StringTimerKind(aName)) {
      JS::Rooted<JSString*> code(aCx, aFirstArg.toString());
      nsAutoCString caller;
      DescribeCaller(aCx, caller);
      nsCString text;
      bool truncated = false;
      uint32_t length = JS::GetStringLength(code);
      if (StringToUTF8(aCx, code, sMaxCodeLength, text, &truncated)) {
        RecordCode(aCx, key, kind, caller, std::move(text), length, truncated);
      }
    }
  }
  if (!sampled) {
    return nullptr;
  }
  auto sample = MakeUnique<CallSample>();
  sample->mCx = aCx;
  sample->mKey = key;
  sample->mName = aName;
  DescribeCaller(aCx, sample->mCaller);
  nsAutoCString argDesc;
  if (aHasArg) {
    DescribeTopLevel(aCx, aFirstArg, argDesc);
  }
  LogCall(key, aName, argDesc, sample->mCaller);
  {
    StaticMutexAutoLock lock(sMutex);
    AddSampleLocked(key, aName, argDesc, sample->mCaller);
  }
  return sample.release();
}

void AddCallArg(CallSample* aSample, JS::Handle<JS::Value> aArg) {
  nsCString* desc = aSample->mArgs.AppendElement();
  DescribeTopLevel(aSample->mCx, aArg, *desc);
}

static bool OnPromiseSettled(JSContext* aCx, unsigned aArgc, JS::Value* aVp) {
  JS::CallArgs args = JS::CallArgsFromVp(aArgc, aVp);
  JSObject* callee = &args.callee();
  uint64_t id = uint64_t(js::GetFunctionNativeReserved(callee, 0).toNumber());
  bool rejected = js::GetFunctionNativeReserved(callee, 1).toBoolean();
  args.rval().setUndefined();

  UniquePtr<PendingPromise> pending;
  {
    StaticMutexAutoLock lock(sMutex);
    if (!sPendingPromises) {
      return true;
    }
    if (auto extracted = sPendingPromises->Extract(id)) {
      pending = std::move(*extracted);
    }
  }
  if (!pending) {
    return true;
  }
  nsAutoCString result(rejected ? "Promise rejected: "
                                : "Promise resolved: ");
  DescribeTopLevel(aCx, args.get(0), result);
  StaticMutexAutoLock lock(sMutex);
  ContextRecord* context =
      GetContextLocked(pending->mWindowKey, pending->mSerial);
  if (!context) {
    return true;
  }
  if (ApiStats* stats = context->mApis.Get(pending->mName)) {
    AppendCallLocked(*stats, std::move(pending->mArgs), result,
                     pending->mScript);
  }
  return true;
}

// Records what aPromise settles with once it does. Returns false if the
// reactions could not be added.
static bool WatchPromise(JSContext* aCx, CallSample* aSample,
                         JS::Handle<JSObject*> aPromise) {
  uint64_t id;
  {
    StaticMutexAutoLock lock(sMutex);
    if (!sPendingPromises ||
        sPendingPromises->Count() >= kMaxPendingPromises) {
      return false;
    }
    id = ++sNextPromiseId;
  }
  JSFunction* resolveFun =
      js::NewFunctionWithReserved(aCx, OnPromiseSettled, 1, 0, "");
  if (!resolveFun) {
    return false;
  }
  JS::Rooted<JSObject*> onResolve(aCx, JS_GetFunctionObject(resolveFun));
  JSFunction* rejectFun =
      js::NewFunctionWithReserved(aCx, OnPromiseSettled, 1, 0, "");
  if (!rejectFun) {
    return false;
  }
  JS::Rooted<JSObject*> onReject(aCx, JS_GetFunctionObject(rejectFun));
  js::SetFunctionNativeReserved(onResolve, 0, JS::DoubleValue(double(id)));
  js::SetFunctionNativeReserved(onResolve, 1, JS::FalseValue());
  js::SetFunctionNativeReserved(onReject, 0, JS::DoubleValue(double(id)));
  js::SetFunctionNativeReserved(onReject, 1, JS::TrueValue());

  auto pending = MakeUnique<PendingPromise>();
  pending->mWindowKey = aSample->mKey.mWindowKey;
  pending->mSerial = aSample->mKey.mSerial;
  pending->mName = aSample->mName;
  pending->mArgs = aSample->mArgs.Clone();
  pending->mScript = aSample->mCaller;
  {
    StaticMutexAutoLock lock(sMutex);
    if (!sPendingPromises) {
      return false;
    }
    sPendingPromises->InsertOrUpdate(id, std::move(pending));
  }
  if (!JS::AddPromiseReactionsIgnoringUnhandledRejection(aCx, aPromise,
                                                         onResolve, onReject)) {
    StaticMutexAutoLock lock(sMutex);
    if (sPendingPromises) {
      sPendingPromises->Remove(id);
    }
    return false;
  }
  return true;
}

// Completes a sample with no exception pending on the context. aThrew tells
// whether the call threw aException.
static void FinishCall(CallSample* aSample, JS::Handle<JS::Value> aResult,
                       bool aHasResult, JS::Handle<JS::Value> aException,
                       bool aThrew) {
  UniquePtr<CallSample> sample(aSample);
  JSContext* cx = sample->mCx;
  nsAutoCString result;
  if (aThrew) {
    result.AssignLiteral("threw ");
    DescribeTopLevel(cx, aException, result);
  } else if (aHasResult) {
    JS::Rooted<JS::Value> value(cx, aResult);
    if (value.isObject() && JS_WrapValue(cx, &value)) {
      JS::Rooted<JSObject*> obj(cx, &value.toObject());
      if (!js::IsProxy(obj) && JS::IsPromiseObject(obj) &&
          WatchPromise(cx, sample.get(), obj)) {
        return;
      }
    }
    JS_ClearPendingException(cx);
    DescribeTopLevel(cx, aResult, result);
  }
  StaticMutexAutoLock lock(sMutex);
  ContextRecord* context = GetContextLocked(sample->mKey);
  if (!context) {
    return;
  }
  if (ApiStats* stats = context->mApis.Get(sample->mName)) {
    AppendCallLocked(*stats, std::move(sample->mArgs), result,
                     sample->mCaller);
  }
}

void EndCall(CallSample* aSample, JS::Handle<JS::Value> aResult,
             bool aHasResult) {
  JSContext* cx = aSample->mCx;
  JS::Rooted<JS::Value> exception(cx);
  bool threw =
      JS_IsExceptionPending(cx) && JS_GetPendingException(cx, &exception);
  JS::AutoSaveExceptionState savedException(cx);
  FinishCall(aSample, aResult, aHasResult, exception, threw);
}

void RecordSetter(JSContext* aCx, const char* aName,
                  JS::Handle<JS::Value> aValue) {
  if (CallSample* sample = BeginCall(aCx, aName, aValue, true)) {
    AddCallArg(sample, aValue);
    EndCall(sample, JS::UndefinedHandleValue, false);
  }
}

static void RecordKeyDesc(JSContext* aCx, const char* aName,
                          const nsACString& aKey,
                          JS::Handle<JS::Value> aValue) {
  ContextKey key;
  if (!GetContextKey(aCx, key) || !CountCall(key, aName)) {
    return;
  }
  nsAutoCString caller;
  DescribeCaller(aCx, caller);
  nsTArray<nsCString> args;
  args.AppendElement(aKey);
  if (!aValue.isUndefined()) {
    DescribeTopLevel(aCx, aValue, *args.AppendElement());
  }
  LogCall(key, aName, aKey, caller);
  StaticMutexAutoLock lock(sMutex);
  AddSampleLocked(key, aName, aKey, caller);
  if (ContextRecord* context = GetContextLocked(key)) {
    if (ApiStats* stats = context->mApis.Get(aName)) {
      AppendCallLocked(*stats, std::move(args), EmptyCString(), caller);
    }
  }
}

void RecordKey(JSContext* aCx, const char* aName, uint32_t aIndex,
               JS::Handle<JS::Value> aValue) {
  nsAutoCString key;
  key.AppendInt(aIndex);
  RecordKeyDesc(aCx, aName, key, aValue);
}

void RecordKey(JSContext* aCx, const char* aName, const nsAString& aKey,
               JS::Handle<JS::Value> aValue) {
  nsAutoCString key;
  AppendQuoted(aKey, key);
  RecordKeyDesc(aCx, aName, key, aValue);
}

static bool IsWasmBytesBuiltin(const char* aName) {
  return !strcmp(aName, "new WebAssembly.Module()") ||
         !strcmp(aName, "WebAssembly.compile()") ||
         !strcmp(aName, "WebAssembly.instantiate()") ||
         !strcmp(aName, "WebAssembly.validate()");
}

// Captures the module bytes passed to the synchronous and buffer-based
// WebAssembly entry points.
static void RecordWasmArg(JSContext* aCx, const ContextKey& aKey,
                          JS::Handle<JS::Value> aArg) {
  if (!aArg.isObject()) {
    return;
  }
  JSObject* obj = js::UncheckedUnwrap(&aArg.toObject());
  size_t length = 0;
  bool isShared = false;
  uint8_t* data = nullptr;
  if (JSObject* view =
          JS_GetObjectAsArrayBufferView(obj, &length, &isShared, &data)) {
    length = JS_GetArrayBufferViewByteLength(view);
  } else if (!JS::GetObjectAsArrayBuffer(obj, &length, &data)) {
    return;
  }
  if (!data) {
    return;
  }
  uint32_t captured = std::min<size_t>(length, MaxCapturedBytes());
  nsCString bytes;
  bytes.Assign(reinterpret_cast<const char*>(data), captured);
  nsAutoCString caller;
  DescribeCaller(aCx, caller);
  RecordBytes(aKey.mWindowKey, aKey.mSerial, &aKey, "wasm", caller, bytes,
              uint32_t(length), captured < length);
}

static void BuiltinCalled(JSContext* aCx, const char* aName,
                          const JS::CallArgs& aArgs, bool aOk) {
  if (!IsEnabled()) {
    return;
  }
  JS::Rooted<JS::Value> exception(aCx);
  bool threw = !aOk && JS_IsExceptionPending(aCx) &&
               JS_GetPendingException(aCx, &exception);
  JS::AutoSaveExceptionState savedException(aCx);
  if (IsWasmBytesBuiltin(aName) && aArgs.length() > 0) {
    ContextKey key;
    if (GetContextKey(aCx, key)) {
      RecordWasmArg(aCx, key, aArgs[0]);
    }
  }
  CallSample* sample = BeginCall(aCx, aName, aArgs.get(0), aArgs.length() > 0);
  if (!sample) {
    return;
  }
  for (unsigned i = 0; i < aArgs.length() && i < kMaxCallArgs; i++) {
    AddCallArg(sample, aArgs[i]);
  }
  FinishCall(sample, aArgs.rval(), aOk, exception, threw);
}

void RecordScriptSource(JSContext* aCx, nsIURI* aURI, const char* aKind,
                        const MaybeSourceText& aSource) {
  ContextKey key;
  if (!IsEnabled() || aSource.empty() || !GetContextKey(aCx, key)) {
    return;
  }
  nsAutoCString url;
  if (aURI) {
    aURI->GetSpec(url);
  }
  uint32_t maxLength = sMaxCodeLength;
  nsCString text;
  uint32_t length = 0;
  bool truncated = false;
  if (aSource.constructed<JS::SourceText<char16_t>>()) {
    const auto& source = aSource.ref<JS::SourceText<char16_t>>();
    length = source.length();
    truncated = length > maxLength;
    CopyUTF16toUTF8(Span(source.get(), std::min(length, maxLength)), text);
  } else {
    const auto& source = aSource.ref<JS::SourceText<Utf8Unit>>();
    length = source.length();
    truncated = length > maxLength;
    text.Assign(reinterpret_cast<const char*>(source.get()),
                std::min(length, maxLength));
  }
  RecordCode(aCx, key, aKind, url, std::move(text), length, truncated);
}

void RecordCompiledScript(JSContext* aCx, nsIURI* aURI, const char* aKind,
                          JS::Handle<JSScript*> aScript) {
  ContextKey key;
  if (!IsEnabled() || !aScript || !GetContextKey(aCx, key)) {
    return;
  }
  JS::Rooted<JSString*> source(aCx, JS_DecompileScript(aCx, aScript));
  if (!source) {
    JS_ClearPendingException(aCx);
    return;
  }
  nsAutoCString url;
  if (aURI) {
    aURI->GetSpec(url);
  }
  nsCString text;
  bool truncated = false;
  uint32_t length = JS::GetStringLength(source);
  if (!StringToUTF8(aCx, source, sMaxCodeLength, text, &truncated)) {
    return;
  }
  RecordCode(aCx, key, aKind, url, std::move(text), length, truncated);
}

void RecordDynamicCode(JSContext* aCx, JS::RuntimeCode aKind,
                       JS::CompilationType aCompilationType,
                       JS::Handle<JSString*> aCode) {
  ContextKey key;
  // WebAssembly compilation is recorded, with the module bytes, by the
  // builtin audit hook.
  if (!IsEnabled() || aKind == JS::RuntimeCode::WASM ||
      !GetContextKey(aCx, key)) {
    return;
  }
  const char* kind =
      aCompilationType == JS::CompilationType::Function ? "Function" : "eval";
  const char* apiName = aCompilationType == JS::CompilationType::Function
                            ? "Function()"
                            : "eval()";
  JS::Rooted<JS::Value> codeValue(aCx);
  if (aCode) {
    codeValue.setString(aCode);
  }
  RecordApi(aCx, key, apiName, codeValue, !!aCode);

  nsAutoCString caller;
  DescribeCaller(aCx, caller);
  nsCString text;
  uint32_t length = 0;
  bool truncated = false;
  if (aCode) {
    length = JS::GetStringLength(aCode);
    if (!StringToUTF8(aCx, aCode, sMaxCodeLength, text, &truncated)) {
      return;
    }
  }
  RecordCode(aCx, key, kind, caller, std::move(text), length, truncated);
}

void RecordCodeText(JSContext* aCx, const char* aKind, const nsACString& aURL,
                    const nsAString& aText) {
  ContextKey key;
  if (!IsEnabled() || !GetContextKey(aCx, key)) {
    return;
  }
  uint32_t maxLength = sMaxCodeLength;
  uint32_t length = aText.Length();
  nsCString text;
  CopyUTF16toUTF8(Substring(aText, 0, std::min(length, maxLength)), text);
  RecordCode(aCx, key, aKind, aURL, std::move(text), length,
             length > maxLength);
}

UniquePtr<StreamCapture> StreamCapture::Create(JSContext* aCx,
                                               const char* aKind,
                                               const nsACString& aURL) {
  ContextKey key;
  if (!IsEnabled() || !GetContextKey(aCx, key)) {
    return nullptr;
  }
  {
    // Make sure the context exists by the time the stream ends.
    StaticMutexAutoLock lock(sMutex);
    GetOrCreateContextLocked(key);
  }
  return WrapUnique(new StreamCapture(key.mWindowKey, key.mSerial, aKind,
                                      aURL, MaxCapturedBytes()));
}

void StreamCapture::Append(const uint8_t* aData, uint32_t aLength) {
  mLength += aLength;
  uint32_t room = mMaxLength - std::min<uint32_t>(mBytes.Length(), mMaxLength);
  mBytes.Append(reinterpret_cast<const char*>(aData),
                std::min(aLength, room));
}

void StreamCapture::Finish() {
  RecordBytes(mWindowKey, mSerial, nullptr, mKind, mURL, mBytes,
              uint32_t(std::min<uint64_t>(mLength, UINT32_MAX)),
              mLength > mBytes.Length());
}

static void RecordForWindowId(uint64_t aInnerWindowId, const char* aName,
                              const nsACString& aArg,
                              const nsACString& aResult,
                              const nsACString& aSource) {
  MOZ_ASSERT(NS_IsMainThread());
  RefPtr<nsGlobalWindowInner> win =
      nsGlobalWindowInner::GetInnerWindowWithId(aInnerWindowId);
  if (!win) {
    return;
  }
  ContextKey key;
  key.mWindow = win;
  key.mWindowKey = aInnerWindowId;
  nsTArray<nsCString> args;
  args.AppendElement(aArg);
  RecordApiDesc(key, aName, aArg, aSource, &args, &aResult);
}

void RecordForDocument(const dom::Document* aDocument, const char* aName,
                       const nsACString& aArg, const nsACString& aResult,
                       const nsACString& aSource) {
  if (!aDocument || !IsEnabled() ||
      aDocument->NodePrincipal()->IsSystemPrincipal()) {
    return;
  }
  uint64_t innerWindowId = aDocument->InnerWindowID();
  if (!innerWindowId) {
    return;
  }
  if (NS_IsMainThread()) {
    RecordForWindowId(innerWindowId, aName, aArg, aResult, aSource);
    return;
  }
  NS_DispatchToMainThread(NS_NewRunnableFunction(
      "apiaudit::RecordForDocument",
      [innerWindowId, aName, arg = nsCString(aArg),
       result = nsCString(aResult), source = nsCString(aSource)] {
        RecordForWindowId(innerWindowId, aName, arg, result, source);
      }));
}

NS_IMPL_ISUPPORTS(ApiAuditService, nsIApiAuditService)

static StaticRefPtr<ApiAuditService> sService;

already_AddRefed<ApiAuditService> ApiAuditService::GetSingleton() {
  if (!sService) {
    sService = new ApiAuditService();
    ClearOnShutdown(&sService);
  }
  return do_AddRef(sService);
}

NS_IMETHODIMP
ApiAuditService::GetEnabled(bool* aEnabled) {
  *aEnabled = IsEnabled();
  return NS_OK;
}

static void WriteContext(JSONWriter& aWriter, const ContextRecord& aContext,
                         bool aIncludeCode) {
  aWriter.StartObjectElement();
  aWriter.IntProperty("serial", int64_t(aContext.mSerial));
  aWriter.StringProperty("kind", MakeStringSpan(aContext.mKind));
  aWriter.StringProperty("url", aContext.mURL);
  aWriter.StringProperty("name", aContext.mName);
  aWriter.StringProperty("parentUrl", aContext.mParentURL);
  aWriter.IntProperty("firstSeen", aContext.mFirstSeen / PR_USEC_PER_MSEC);
  aWriter.StartArrayProperty("apis");
  for (const auto& api : aContext.mApis) {
    const ApiStats& stats = *api.GetData();
    aWriter.StartObjectElement();
    aWriter.StringProperty("name", MakeStringSpan(api.GetKey()));
    aWriter.IntProperty("count", int64_t(stats.mCount));
    aWriter.IntProperty("firstSeen", stats.mFirstSeen / PR_USEC_PER_MSEC);
    aWriter.StartArrayProperty("args");
    for (const nsCString& arg : stats.mArgs) {
      aWriter.StringElement(arg);
    }
    aWriter.EndArray();
    aWriter.StartArrayProperty("scripts");
    for (const nsCString& script : stats.mScripts) {
      aWriter.StringElement(script);
    }
    aWriter.EndArray();
    aWriter.StartArrayProperty("calls");
    for (const CallRecord& call : stats.mCalls) {
      aWriter.StartObjectElement();
      aWriter.StartArrayProperty("args");
      for (const nsCString& arg : call.mArgs) {
        aWriter.StringElement(arg);
      }
      aWriter.EndArray();
      aWriter.StringProperty("result", call.mResult);
      aWriter.StringProperty("script", call.mScript);
      aWriter.IntProperty("count", int64_t(call.mCount));
      aWriter.EndObject();
    }
    aWriter.EndArray();
    aWriter.EndObject();
  }
  aWriter.EndArray();
  aWriter.StartArrayProperty("code");
  for (const CodeRecord& code : aContext.mCode) {
    aWriter.StartObjectElement();
    aWriter.StringProperty("kind", MakeStringSpan(code.mKind));
    aWriter.StringProperty("url", code.mURL);
    aWriter.IntProperty("length", code.mLength);
    aWriter.IntProperty("hash", code.mHash);
    aWriter.BoolProperty("truncated", code.mTruncated);
    aWriter.BoolProperty("antiDebug", code.mAntiDebug);
    if (code.mBase64) {
      aWriter.StringProperty("encoding", "base64");
    }
    aWriter.IntProperty("count", int64_t(code.mCount));
    aWriter.IntProperty("firstSeen", code.mFirstSeen / PR_USEC_PER_MSEC);
    if (aIncludeCode) {
      aWriter.StringProperty("text", code.mText);
    }
    aWriter.EndObject();
  }
  aWriter.EndArray();
  aWriter.EndObject();
}

NS_IMETHODIMP
ApiAuditService::GetRecordsJSON(bool aIncludeCode, nsACString& aResult) {
  IsEnabled();
  aResult.Truncate();
  JSONStringRefWriteFunc func(aResult);
  JSONWriter w(func);
  w.Start();
  w.StartArrayProperty("windows");
  {
    StaticMutexAutoLock lock(sMutex);
    PurgeDestroyedLocked();
    if (sWindows) {
      for (const auto& entry : *sWindows) {
        WindowRecord& record = *entry.GetData();
        if (!record.mDestroyedAt && !record.mIsWorker) {
          if (RefPtr<nsGlobalWindowInner> win =
                  nsGlobalWindowInner::GetInnerWindowWithId(entry.GetKey())) {
            FillWindowMetadata(win, record);
          }
        }
        w.StartObjectElement();
        w.IntProperty("innerWindowId", int64_t(entry.GetKey()));
        w.IntProperty("topInnerWindowId", int64_t(record.mTopInnerWindowId));
        w.IntProperty("browserId", int64_t(record.mBrowserId));
        w.BoolProperty("isTop", record.mIsTop);
        w.BoolProperty("isWorker", record.mIsWorker);
        w.StringProperty("url", record.mURL);
        w.StringProperty("origin", record.mOrigin);
        w.IntProperty("destroyedAt", record.mDestroyedAt / PR_USEC_PER_MSEC);
        w.IntProperty("serviceWorkerId", int64_t(record.mServiceWorkerId));
        w.StringProperty("serviceWorkerScope", record.mServiceWorkerScope);
        w.StringProperty("serviceWorkerUrl", record.mServiceWorkerURL);
        w.StartArrayProperty("contexts");
        for (const auto& context : record.mContexts) {
          WriteContext(w, *context, aIncludeCode);
        }
        w.EndArray();
        w.EndObject();
      }
    }
  }
  w.EndArray();
  w.End();
  return NS_OK;
}

NS_IMETHODIMP
ApiAuditService::Clear() {
  StaticMutexAutoLock lock(sMutex);
  if (sPendingPromises) {
    sPendingPromises->Clear();
  }
  if (sWindows) {
    for (auto iter = sWindows->Iter(); !iter.Done(); iter.Next()) {
      WindowRecord& record = *iter.Data();
      if (record.mDestroyedAt) {
        iter.Remove();
      } else {
        record.mContexts.Clear();
      }
    }
  }
  return NS_OK;
}

}  // namespace mozilla::apiaudit
