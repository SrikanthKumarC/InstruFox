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
#include "mozilla/UniquePtr.h"
#include "mozilla/Utf8.h"
#include "nsString.h"

class nsIURI;

// Captures code and observations of web content that are not visible through
// the WebIDL bindings: worker scripts (including blob: and data: workers),
// strings compiled with eval() or Function(), inline event handlers,
// javascript: URLs, WebAssembly modules and stylesheet conditions.
namespace mozilla {

namespace dom {
class Document;
}

namespace apiaudit {

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

// Records code compiled from a string, such as an inline event handler
// attribute or a javascript: URL, in the context of aCx's global.
void RecordCodeText(JSContext* aCx, const char* aKind, const nsACString& aURL,
                    const nsAString& aText);

// Records an observation of aDocument that does not go through a binding,
// such as a media query evaluated in a stylesheet. aName is a string literal;
// aSource is where the observation comes from, such as a stylesheet URL.
// May be called off the main thread.
void RecordForDocument(const dom::Document* aDocument, const char* aName,
                       const nsACString& aArg, const nsACString& aResult,
                       const nsACString& aSource);

// Captures the bytes of a streamed WebAssembly module as they are read, on
// any thread, and records them when the stream ends.
class StreamCapture final {
 public:
  // Returns null if recording is disabled or aCx runs system code.
  static UniquePtr<StreamCapture> Create(JSContext* aCx, const char* aKind,
                                         const nsACString& aURL);

  void Append(const uint8_t* aData, uint32_t aLength);
  void Finish();

 private:
  StreamCapture(uint64_t aWindowKey, uint64_t aSerial, const char* aKind,
                const nsACString& aURL, uint32_t aMaxLength)
      : mWindowKey(aWindowKey),
        mSerial(aSerial),
        mKind(aKind),
        mURL(aURL),
        mMaxLength(aMaxLength) {}

  const uint64_t mWindowKey;
  const uint64_t mSerial;
  const char* const mKind;
  const nsCString mURL;
  const uint32_t mMaxLength;
  nsCString mBytes;
  uint64_t mLength = 0;
};

}  // namespace apiaudit
}  // namespace mozilla

#endif  // mozilla_ApiAuditScripts_h
