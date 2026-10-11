const { JSDOM } = require("jsdom"); const assert = require("assert");
const BASE = "http://127.0.0.1:8765";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, label, ms = 8000) { const t = Date.now(); while (Date.now() - t < ms) { try { const v = fn(); if (v) return v; } catch (e) {} await sleep(100); } throw new Error("timeout waiting for: " + label); }
(async () => {
  const html = await (await fetch(BASE + "/")).text();
  const dom = new JSDOM(html, { url: BASE + "/", runScripts: "dangerously", resources: "usable", pretendToBeVisual: true,
    beforeParse(w) { w.fetch = (u, o) => fetch(new URL(u, BASE).href, o); w.HTMLDialogElement.prototype.showModal = function () { this.setAttribute("open", ""); };
      w.URL.createObjectURL = () => "blob:x"; w.URL.revokeObjectURL = () => {}; w.confirm = () => true; w.HTMLAnchorElement.prototype.click = function () { w.__downloaded = this.download; }; } });
  const w = dom.window, d = w.document, $ = (s) => d.querySelector(s);
  await waitFor(() => w.formatError, "app.js loaded");
  const results = [];
  const ok = (name) => { results.push(name); console.log("PASS", name); };

  // formatError unit checks (the [object Object] fix)
  assert.strictEqual(w.formatError({ detail: [{ loc: ["body", "target"], msg: "Field required" }] }), "target: Field required");
  assert.strictEqual(w.formatError({ detail: "plain" }), "plain");
  assert.strictEqual(w.formatError(new Error("net down")), "net down");
  assert.strictEqual(w.formatError({ detail: { a: 1 } }), '{"a":1}');
  assert.ok(!w.formatError({ detail: [{ x: 1 }, { y: 2 }] }).includes("[object Object]"));
  ok("formatError never yields [object Object]");

  await waitFor(() => $("#stats").children.length === 6, "stats rendered"); ok("page loads, stats strip renders");
  await waitFor(() => $("#detail .chip"), "empty state"); ok("empty state with example chips");

  // validation error from server shows readable text
  $("#target").value = "192.168.1.1"; $("#searchForm").dispatchEvent(new w.Event("submit", { cancelable: true }));
  await waitFor(() => !$("#formMsg").hidden, "error message");
  assert.ok($("#formMsg").textContent.includes("Private"), $("#formMsg").textContent); assert.ok(!$("#formMsg").textContent.includes("[object"));
  ok("private IP rejected with readable message: " + $("#formMsg").textContent.slice(0, 60));

  // auto detect hint
  $("#target").value = "8.8.8.8"; $("#target").dispatchEvent(new w.Event("input"));
  await waitFor(() => $("#detected").textContent.includes("IP address"), "detect hint"); ok("auto-detect hint shows 'IP address'");

  // full investigation
  $("#optMon").checked = true;
  $("#searchForm").dispatchEvent(new w.Event("submit", { cancelable: true }));
  await waitFor(() => $("#detail h3") && $("#detail h3").textContent === "8.8.8.8", "case opened");
  await waitFor(() => $("#detail .group"), "findings rendered"); 
  const txt = $("#detail").textContent;
  assert.ok(txt.includes("Sensitive services exposed") && txt.includes("Shodan InternetDB")); assert.ok(!txt.includes("[object"));
  assert.ok($("#detail .summary").textContent.includes("rule-based") || $("#detail .summary").textContent.includes("Automatic rule-based"));
  assert.ok($("#list li.sel .t").textContent === "8.8.8.8"); ok("IP investigation completes, findings + summary + history row render");
  assert.ok($("#detail .big b").textContent !== "..."); ok("risk score shown: " + $("#detail .big b").textContent);

  // exports
  $("#detail [data-act=csv]").click(); await waitFor(() => w.__downloaded === undefined ? false : true, "csv"); assert.strictEqual(w.__downloaded, "investigation_1.csv"); ok("CSV download triggered");
  w.__downloaded = undefined; $("#detail [data-act=pdf]").click(); await waitFor(() => w.__downloaded, "pdf"); assert.strictEqual(w.__downloaded, "investigation_1.pdf"); ok("PDF download triggered");

  // monitoring toggle + sources + alerts tabs
  assert.ok($("#detail [data-act=monitor]").textContent.includes("Stop")); ok("monitoring shows as on");
  d.querySelector('[data-tab=sources]').click(); await waitFor(() => $("#srcTable").textContent.includes("VIRUSTOTAL_API_KEY"), "sources"); 
  await waitFor(() => $("#monInfo").textContent.includes("mon-1"), "monitoring info"); ok("Sources tab shows 'needs key' + active monitoring job");
  d.querySelector('[data-tab=alerts]').click(); await waitFor(() => $("#alertList").textContent.includes("No alerts yet"), "alerts"); ok("Alerts tab renders empty state");
  d.querySelector('[data-tab=cases]').click();

  // rerun then delete
  $("#detail [data-act=rerun]").click(); await waitFor(() => $("#detail").textContent.includes("Runs: 2"), "rerun", 10000); ok("re-run increments run count");
  $("#detail [data-act=delete]").click(); await waitFor(() => $("#detail .chip"), "deleted"); await waitFor(() => $("#list").textContent.includes("Nothing yet"), "list empty"); ok("delete returns to empty state");
  console.log("\n" + results.length + " frontend checks passed"); process.exit(0);
})().catch((e) => { console.error("FAIL:", e.message); process.exit(1); });
