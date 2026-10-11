/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Returns the API records of this process to the parent.
 */
export class ApiAuditChild extends JSProcessActorChild {
  receiveMessage(message) {
    let service = Cc["@mozilla.org/api-audit-service;1"].getService(
      Ci.nsIApiAuditService
    );
    switch (message.name) {
      case "ApiAudit:GetRecords":
        return service.getRecordsJSON(!!message.data?.includeCode);
      case "ApiAudit:Clear":
        service.clear();
        return null;
    }
    return null;
  }
}
