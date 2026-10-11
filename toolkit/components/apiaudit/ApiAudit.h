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

// Records every WebIDL member invoked by web content. The WebIDL bindings
// generator emits a call to Record/RecordMethod at the start of each
// generated method, getter, setter and constructor.
namespace mozilla::apiaudit {

enum class State : uint32_t { Uninitialized, Disabled, Enabled };

extern Atomic<State, Relaxed> gState;

bool InitSlow();

inline bool IsEnabled() {
  State s = gState;
  return s == State::Enabled || (s == State::Uninitialized && InitSlow());
}

// aName must be a string literal; it is stored without being copied.
void Record(JSContext* aCx, const char* aName);
void RecordWithArg(JSContext* aCx, const char* aName,
                   JS::Handle<JS::Value> aArg);

template <typename Args>
inline void RecordMethod(JSContext* aCx, const char* aName, const Args& aArgs) {
  RecordWithArg(aCx, aName, aArgs.get(0));
}

}  // namespace mozilla::apiaudit

#endif  // mozilla_ApiAudit_h
