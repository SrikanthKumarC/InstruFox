/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_ApiAudit_h
#define mozilla_ApiAudit_h

#include "js/TypeDecls.h"
#include "js/Value.h"
#include "mozilla/Atomics.h"
#include "nsStringFwd.h"

// Records every WebIDL member invoked by web content. The WebIDL bindings
// generator emits one of the recorders below at the start of each generated
// method, getter, setter, constructor and named or indexed property
// operation.
namespace mozilla::apiaudit {

enum class State : uint32_t { Uninitialized, Disabled, Enabled };

extern Atomic<State, Relaxed> gState;

bool InitSlow();

inline bool IsEnabled() {
  State s = gState;
  return s == State::Enabled || (s == State::Uninitialized && InitSlow());
}

// Number of arguments described for each sampled call.
static constexpr unsigned kMaxCallArgs = 8;

// A sampled call whose arguments and result are recorded once it returns.
struct CallSample;

// Counts a call to aName (a string literal, stored without being copied) and
// records its first argument. Returns the sample to pass to EndCall once the
// call returns, or null if this call is not sampled.
CallSample* BeginCall(JSContext* aCx, const char* aName,
                      JS::Handle<JS::Value> aFirstArg, bool aHasArg);
void AddCallArg(CallSample* aSample, JS::Handle<JS::Value> aArg);
// Records the arguments added so far and aResult (when aHasResult), or the
// pending exception, then frees aSample.
void EndCall(CallSample* aSample, JS::Handle<JS::Value> aResult,
             bool aHasResult);

void RecordSetter(JSContext* aCx, const char* aName,
                  JS::Handle<JS::Value> aValue);

// Named and indexed property operations. aValue is the value being assigned,
// or undefined for getters and deleters.
void RecordKey(JSContext* aCx, const char* aName, uint32_t aIndex,
               JS::Handle<JS::Value> aValue);
void RecordKey(JSContext* aCx, const char* aName, const nsAString& aKey,
               JS::Handle<JS::Value> aValue);

// Records a method or constructor call with its arguments and return value.
// Arguments are described after the call so that typed arrays the callee
// fills in (getFloatFrequencyData(), readPixels()) show their new contents.
template <typename Args>
class MOZ_RAII AutoRecordMethod {
 public:
  AutoRecordMethod(JSContext* aCx, const char* aName, const Args& aArgs)
      : mArgs(aArgs),
        mSample(IsEnabled() ? BeginCall(aCx, aName, aArgs.get(0),
                                        aArgs.length() > 0)
                            : nullptr) {}

  ~AutoRecordMethod() {
    if (mSample) {
      for (unsigned i = 0; i < mArgs.length() && i < kMaxCallArgs; i++) {
        AddCallArg(mSample, mArgs.get(i));
      }
      EndCall(mSample, mArgs.rval(), true);
    }
  }

 private:
  const Args& mArgs;
  CallSample* mSample;
};

template <typename Args>
class MOZ_RAII AutoRecordGetter {
 public:
  AutoRecordGetter(JSContext* aCx, const char* aName, Args& aArgs)
      : mArgs(aArgs),
        mSample(IsEnabled()
                    ? BeginCall(aCx, aName, JS::UndefinedHandleValue, false)
                    : nullptr) {}

  ~AutoRecordGetter() {
    if (mSample) {
      EndCall(mSample, mArgs.rval(), true);
    }
  }

 private:
  Args& mArgs;
  CallSample* mSample;
};

}  // namespace mozilla::apiaudit

#endif  // mozilla_ApiAudit_h
