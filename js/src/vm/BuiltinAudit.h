/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * vim: set ts=8 sts=2 et sw=2 tw=80:
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef vm_BuiltinAudit_h
#define vm_BuiltinAudit_h

#include <atomic>

#include "jsfriendapi.h"

#include "js/CallArgs.h"

namespace js {

extern std::atomic<BuiltinAuditHook> gBuiltinAuditHook;

// Wraps a JSNative so that the builtin audit hook sees each call to it once
// it returns. Inlined JIT paths of inlinable natives bypass the wrapper.
template <JSNative Native, const char* Name>
bool AuditedNative(JSContext* cx, unsigned argc, JS::Value* vp) {
  bool ok = Native(cx, argc, vp);
  if (BuiltinAuditHook hook =
          gBuiltinAuditHook.load(std::memory_order_acquire)) {
    hook(cx, Name, JS::CallArgsFromVp(argc, vp), ok);
  }
  return ok;
}

}  // namespace js

#endif  // vm_BuiltinAudit_h
