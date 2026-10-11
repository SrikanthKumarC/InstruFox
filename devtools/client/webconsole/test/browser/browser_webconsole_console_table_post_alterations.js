/* Any copyright is dedicated to the Public Domain.
 * http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

// Check how console.table reacts to a variable being modified around the
// console.table calls. Console messages are serialized in a later event
// loop turn than the call itself, so that the page-visible cost of a
// console call does not depend on DevTools being open. A mutation that
// happens in the same task as the call therefore shows up in the table,
// while a mutation that happens after the table was serialized does not.

const TEST_URI = `data:text/html,<!DOCTYPE html>Test console.table with modified variable`;

add_task(async function () {
  const hud = await openNewTabAndConsole(TEST_URI);

  await SpecialPowers.spawn(gBrowser.selectedBrowser, [], async () => {
    const x = ["a", "b"];
    content.wrappedJSObject.console.table(x);
    // Mutating in the same task as the call is visible once the messages of
    // this task are serialized: both tables show [a, b, c].
    x.push("c");
    content.wrappedJSObject.console.table(x);
    // Task boundary: the two messages are serialized during the wait.
    // eslint-disable-next-line mozilla/no-arbitrary-setTimeout
    await new Promise(resolve =>
      content.wrappedJSObject.setTimeout(resolve, 0)
    );
    x.sort((a, b) => {
      if (a < b) {
        return 1;
      }
      if (a > b) {
        return -1;
      }
      return 0;
    });
    content.wrappedJSObject.console.table(x);
  });

  const [table1, table2, table3] = await waitFor(() => {
    const res = hud.ui.outputNode.querySelectorAll(".message .consoletable");
    if (res.length === 3) {
      return res;
    }
    return null;
  });

  info("Check the rows of the first table");
  checkTable(table1, [
    [0, "a"],
    [1, "b"],
    [2, "c"],
  ]);

  info("Check the rows of the table after adding an element to the array");
  checkTable(table2, [
    [0, "a"],
    [1, "b"],
    [2, "c"],
  ]);

  info("Check the rows of the table after sorting the array in another task");
  checkTable(table3, [
    [0, "c"],
    [1, "b"],
    [2, "a"],
  ]);
});

function checkTable(node, expectedRows) {
  const rows = Array.from(node.querySelectorAll("tbody tr"));
  is(rows.length, expectedRows.length, "table has the expected number of rows");

  expectedRows.forEach((expectedRow, rowIndex) => {
    const rowCells = Array.from(rows[rowIndex].querySelectorAll("td"));
    is(rowCells.map(x => x.textContent).join(" | "), expectedRow.join(" | "));
  });
}
