/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/ApiAudit.h"
#include "mozilla/ApiAuditScripts.h"
#include "mozilla/ApiAuditService.h"

#include "js/CharacterEncoding.h"
#include "js/ColumnNumber.h"
#include "js/Object.h"
#include "js/String.h"
#include "jsapi.h"
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
#include "nsThreadUtils.h"
#include "prtime.h"
#include "xpcpublic.h"

namespace mozilla::apiaudit {

static LazyLogModule sLog("ApiAudit");

#define PREF_ENABLED "privacy.apiaudit.enabled"
#define PREF_RETAIN_SECONDS "privacy.apiaudit.retainSeconds"
#define PREF_MAX_CODE_LENGTH "privacy.apiaudit.maxCodeLength"

static constexpr uint32_t kMaxSamplesPerApi = 64;
static constexpr uint32_t kMaxDistinctArgs = 24;
static constexpr uint32_t kMaxDistinctScripts = 12;
static constexpr uint32_t kMaxArgLength = 200;
static constexpr uint32_t kMaxScriptLength = 400;
static constexpr uint32_t kMaxCodeRecordsPerContext = 256;
static constexpr uint32_t kMaxCodeBytesPerContext = 32 * 1024 * 1024;
static constexpr uint32_t kDefaultMaxCodeLength = 512 * 1024;

// Window keys of workers that have no owning window (shared and service
// workers and their nested workers) have this bit set. Keys stay below 2^53
// so that they survive the JSON round trip to JS.
static constexpr uint64_t kWorkerWindowKeyBit = uint64_t(1) << 51;
static constexpr uint64_t kWorkerWindowKeyMask = kWorkerWindowKeyBit - 1;

Atomic<State, Relaxed> gState(State::Uninitialized);
static Atomic<uint32_t, Relaxed> sMaxCodeLength(kDefaultMaxCodeLength);
static Atomic<uint64_t> sNextWorkerSerial(0);
static Atomic<bool> sShutdown(false);

struct ApiStats {
  uint64_t mCount = 0;
  uint32_t mSamples = 0;
  PRTime mFirstSeen = 0;
  nsTArray<nsCString> mArgs;
  nsTArray<nsCString> mScripts;
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

static StaticMutex sMutex;
static StaticAutoPtr<nsClassHashtable<nsUint64HashKey, WindowRecord>> sWindows
    MOZ_GUARDED_BY(sMutex);

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
      StaticMutexAutoLock lock(sMutex);
      sWindows = nullptr;
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

static ContextRecord* GetContextLocked(const ContextKey& aKey)
    MOZ_REQUIRES(sMutex) {
  if (!sWindows) {
    return nullptr;
  }
  WindowRecord* record = sWindows->Get(aKey.mWindowKey);
  if (!record) {
    return nullptr;
  }
  for (auto& context : record->mContexts) {
    if (context->mSerial == aKey.mSerial) {
      return context.get();
    }
  }
  return nullptr;
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
    aOut.AppendLiteral("...");
  }
  aOut.Append('"');
}

// Describes the DOM objects that wrap a URL or code string, such as the
// TrustedScriptURL passed to new Worker() on pages that enforce Trusted
// Types, without running any page script.
static bool DescribeDOMObject(JSContext* aCx, JS::Handle<JS::Value> aArg,
                              nsACString& aOut) {
  JS::Rooted<JSObject*> obj(aCx, &aArg.toObject());
  {
    dom::TrustedScriptURL* trusted = nullptr;
    if (NS_SUCCEEDED(UNWRAP_OBJECT(TrustedScriptURL, &obj, trusted))) {
      aOut.AssignLiteral("TrustedScriptURL ");
      AppendQuoted(trusted->mData, aOut);
      return true;
    }
  }
  {
    dom::TrustedScript* trusted = nullptr;
    if (NS_SUCCEEDED(UNWRAP_OBJECT(TrustedScript, &obj, trusted))) {
      aOut.AssignLiteral("TrustedScript ");
      AppendQuoted(trusted->mData, aOut);
      return true;
    }
  }
  {
    dom::TrustedHTML* trusted = nullptr;
    if (NS_SUCCEEDED(UNWRAP_OBJECT(TrustedHTML, &obj, trusted))) {
      aOut.AssignLiteral("TrustedHTML ");
      AppendQuoted(trusted->mData, aOut);
      return true;
    }
  }
  {
    dom::URL* url = nullptr;
    if (NS_SUCCEEDED(UNWRAP_OBJECT(URL, &obj, url))) {
      nsAutoCString href;
      url->GetHref(href);
      aOut.AssignLiteral("URL ");
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
  return false;
}

static void DescribeArg(JSContext* aCx, JS::Handle<JS::Value> aArg,
                        nsACString& aOut) {
  if (aArg.isUndefined()) {
    return;
  }
  if (aArg.isString()) {
    JS::Rooted<JSString*> str(aCx, aArg.toString());
    nsAutoCString chars;
    bool truncated = false;
    if (!StringToUTF8(aCx, str, kMaxArgLength, chars, &truncated)) {
      aOut.AssignLiteral("<string>");
      return;
    }
    aOut.Assign('"');
    aOut.Append(chars);
    if (truncated) {
      aOut.AppendLiteral("...");
    }
    aOut.Append('"');
    return;
  }
  if (aArg.isInt32()) {
    aOut.AppendInt(aArg.toInt32());
    return;
  }
  if (aArg.isNumber()) {
    aOut.AppendFloat(aArg.toNumber());
    return;
  }
  if (aArg.isBoolean()) {
    aOut.Assign(aArg.toBoolean() ? "true" : "false");
    return;
  }
  if (aArg.isNull()) {
    aOut.AssignLiteral("null");
    return;
  }
  if (aArg.isObject() && DescribeDOMObject(aCx, aArg, aOut)) {
    return;
  }
  if (aArg.isObject()) {
    aOut.AppendPrintf("[object %s]", JS::GetClass(&aArg.toObject())->name);
    return;
  }
  aOut.AssignLiteral("<other>");
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

static void RecordApi(JSContext* aCx, const ContextKey& aKey, const char* aName,
                      JS::Handle<JS::Value> aArg, bool aHasArg) {
  bool sample = false;
  bool first = false;
  {
    StaticMutexAutoLock lock(sMutex);
    ContextRecord* context = GetOrCreateContextLocked(aKey);
    if (!context) {
      return;
    }
    ApiStats* stats = context->mApis.GetOrInsertNew(aName);
    first = stats->mCount == 0;
    if (first) {
      stats->mFirstSeen = PR_Now();
    }
    stats->mCount++;
    if (stats->mSamples < kMaxSamplesPerApi) {
      stats->mSamples++;
      sample = true;
    }
  }

  if (!sample) {
    return;
  }

  nsAutoCString argDesc;
  if (aHasArg) {
    DescribeArg(aCx, aArg, argDesc);
  }
  nsAutoCString caller;
  DescribeCaller(aCx, caller);

  if (first) {
    MOZ_LOG(sLog, LogLevel::Info,
            ("window=%" PRIu64 " context=%" PRIu64 " %s%s%s caller=%s",
             aKey.mWindowKey, aKey.mSerial, aName,
             argDesc.IsEmpty() ? "" : " arg=", argDesc.get(), caller.get()));
  }
  MOZ_LOG(sLog, LogLevel::Verbose,
          ("window=%" PRIu64 " context=%" PRIu64 " %s arg=%s caller=%s",
           aKey.mWindowKey, aKey.mSerial, aName, argDesc.get(), caller.get()));

  StaticMutexAutoLock lock(sMutex);
  ContextRecord* context = GetContextLocked(aKey);
  if (!context) {
    return;
  }
  if (ApiStats* stats = context->mApis.Get(aName)) {
    AppendDistinct(stats->mArgs, argDesc, kMaxDistinctArgs);
    AppendDistinct(stats->mScripts, caller, kMaxDistinctScripts);
  }
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

  StaticMutexAutoLock lock(sMutex);
  ContextRecord* context = GetOrCreateContextLocked(aKey);
  if (!context) {
    return;
  }
  for (CodeRecord& code : context->mCode) {
    if (code.mHash == hash && code.mLength == aLength &&
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
  code->mHash = hash;
  code->mTruncated = aTruncated;
  code->mAntiDebug = antiDebug;
  code->mCount = 1;
  code->mFirstSeen = PR_Now();
}

void Record(JSContext* aCx, const char* aName) {
  ContextKey key;
  if (GetContextKey(aCx, key)) {
    RecordApi(aCx, key, aName, JS::UndefinedHandleValue, false);
  }
}

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

void RecordWithArg(JSContext* aCx, const char* aName,
                   JS::Handle<JS::Value> aArg) {
  ContextKey key;
  if (!GetContextKey(aCx, key)) {
    return;
  }
  RecordApi(aCx, key, aName, aArg, true);
  if (!aArg.isString()) {
    return;
  }
  if (const char* kind = StringTimerKind(aName)) {
    JS::Rooted<JSString*> code(aCx, aArg.toString());
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
  if (!IsEnabled() || !GetContextKey(aCx, key)) {
    return;
  }
  const char* kind = aKind == JS::RuntimeCode::WASM ? "wasm"
                     : aCompilationType == JS::CompilationType::Function
                         ? "Function"
                         : "eval";
  const char* apiName = aKind == JS::RuntimeCode::WASM ? "WebAssembly.compile()"
                        : aCompilationType == JS::CompilationType::Function
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
