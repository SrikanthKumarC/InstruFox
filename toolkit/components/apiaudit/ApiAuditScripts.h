/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_ApiAuditScripts_h
#define mozilla_ApiAuditScripts_h

#include "js/Principals.h"
#include "js/SourceText.h"
#include "js/TypeDecls.h"
#include "mozilla/MaybeOneOf.h"
#include "mozilla/Utf8.h"

class nsIURI;

// Captures code that runs in web content but is not visible through the
// WebIDL bindings: worker scripts (including blob: and data: workers) and
// strings compiled with eval(), Function() or WebAssembly.
namespace mozilla::apiaudit {

using MaybeSourceText =
    MaybeOneOf<JS::SourceText<char16_t>, JS::SourceText<Utf8Unit>>;

// aKind is a string literal such as "worker-script".
void RecordScriptSource(JSContext* aCx, nsIURI* aURI, const char* aKind,
                        const MaybeSourceText& aSource);

// Records the source of a compiled main-thread or module script. Works for
// scripts compiled off-thread or restored from the bytecode cache, where the
// source text is no longer attached to the load request.
void RecordCompiledScript(JSContext* aCx, nsIURI* aURI, const char* aKind,
                          JS::Handle<JSScript*> aScript);

void RecordDynamicCode(JSContext* aCx, JS::RuntimeCode aKind,
                       JS::CompilationType aCompilationType,
                       JS::Handle<JSString*> aCode);

}  // namespace mozilla::apiaudit

#endif  // mozilla_ApiAuditScripts_h
