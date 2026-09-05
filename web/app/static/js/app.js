/* VolatileGUI front-end. Vanilla JS only — no CDN, works offline. */
(function () {
  "use strict";

  // ----------------------------------------------------------------- theme
  // The initial value is resolved by the inline script in <head> (before
  // paint). This only handles the explicit switch.
  window.toggleTheme = function () {
    var root = document.documentElement;
    var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("mf-theme", next); } catch (e) {}
  };

  // If the viewer has never chosen explicitly, follow the OS when it changes.
  if (window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: light)");
    var onChange = function (e) {
      var stored;
      try { stored = localStorage.getItem("mf-theme"); } catch (err) {}
      if (stored === "light" || stored === "dark") return;
      document.documentElement.setAttribute("data-theme", e.matches ? "light" : "dark");
    };
    if (mq.addEventListener) mq.addEventListener("change", onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }

  // ---------------------------------------------------------------- toasts
  function toastWrap() {
    var w = document.querySelector(".toast-wrap");
    if (!w) {
      w = document.createElement("div");
      w.className = "toast-wrap";
      document.body.appendChild(w);
    }
    return w;
  }

  window.toast = function (msg, kind, ms) {
    var el = document.createElement("div");
    el.className = "toast " + (kind || "");
    el.textContent = msg;
    toastWrap().appendChild(el);
    setTimeout(function () { el.remove(); }, ms || 4200);
  };

  // ------------------------------------------------------- plugin picker
  function syncPluginRow(input) {
    var row = input.closest(".pl");
    if (row) row.classList.toggle("checked", input.checked);
  }

  function selectedCount() {
    return document.querySelectorAll('input[name="plugins"]:checked').length;
  }

  function refreshCounter() {
    var el = document.getElementById("selcount");
    if (el) el.textContent = selectedCount();
    var btn = document.getElementById("runbtn");
    if (btn) btn.disabled = selectedCount() === 0;
  }

  window.initPluginPicker = function () {
    document.querySelectorAll('input[name="plugins"]').forEach(function (cb) {
      syncPluginRow(cb);
      cb.addEventListener("change", function () {
        syncPluginRow(cb);
        refreshCounter();
        var p = document.querySelector(".preset.on");
        if (p) p.classList.remove("on");
        var hid = document.getElementById("presetfield");
        if (hid) hid.value = "";
      });
    });
    refreshCounter();

    var search = document.getElementById("pluginsearch");
    if (search) {
      search.addEventListener("input", function () {
        var q = search.value.trim().toLowerCase();
        document.querySelectorAll(".plugin-cat").forEach(function (cat) {
          var shown = 0;
          cat.querySelectorAll(".pl").forEach(function (row) {
            var hay = row.dataset.search || "";
            var hit = !q || hay.indexOf(q) !== -1;
            row.style.display = hit ? "" : "none";
            if (hit) shown++;
          });
          cat.style.display = shown ? "" : "none";
          if (q && shown) cat.open = true;
        });
      });
    }
  };

  window.applyPreset = function (key, names) {
    document.querySelectorAll(".preset").forEach(function (p) {
      p.classList.toggle("on", p.dataset.preset === key);
    });
    var hid = document.getElementById("presetfield");
    if (hid) hid.value = key;
    var want = {};
    (names || []).forEach(function (n) { want[n] = true; });
    document.querySelectorAll('input[name="plugins"]').forEach(function (cb) {
      cb.checked = !!want[cb.value];
      syncPluginRow(cb);
      if (cb.checked) {
        var cat = cb.closest(".plugin-cat");
        if (cat) cat.open = true;
      }
    });
    refreshCounter();
    window.toast((names || []).length + " plugin(s) selected", "ok", 2200);
  };

  window.selectAllVisible = function (on) {
    document.querySelectorAll(".pl").forEach(function (row) {
      if (row.style.display === "none") return;
      var cb = row.querySelector('input[name="plugins"]');
      if (cb && !cb.disabled) { cb.checked = on; syncPluginRow(cb); }
    });
    refreshCounter();
  };

  window.selectPopular = function () {
    document.querySelectorAll('input[name="plugins"]').forEach(function (cb) {
      cb.checked = cb.dataset.popular === "1";
      syncPluginRow(cb);
    });
    refreshCounter();
  };

  // ------------------------------------------------------------- console
  function classify(line) {
    var l = (line || "").toLowerCase();
    if (l.indexOf("$ ") === 0) return "ln-cmd";
    if (l.indexOf("error") !== -1 || l.indexOf("traceback") !== -1 ||
        l.indexOf("unsatisfied") !== -1 || l.indexOf("failed") !== -1) return "ln-err";
    if (l.indexOf("warn") !== -1) return "ln-warn";
    if (l.indexOf("state:") === 0 || l.indexOf("[runner]") !== -1) return "ln-sys";
    if (l.indexOf("finished") !== -1 || l.indexOf("100.00") !== -1) return "ln-ok";
    return "";
  }

  window.attachJobStream = function (uid, opts) {
    opts = opts || {};
    var box = document.getElementById("console");
    var bar = document.getElementById("progbar");
    var pct = document.getElementById("progpct");
    var badge = document.getElementById("jobstatus");
    var stuck = false;

    function append(text, cls) {
      if (!box) return;
      var atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
      var span = document.createElement("div");
      if (cls) span.className = cls;
      span.textContent = text;
      box.appendChild(span);
      while (box.childElementCount > 4000) box.removeChild(box.firstChild);
      if (atBottom) box.scrollTop = box.scrollHeight;
    }

    var es = new EventSource("/api/stream/job/" + uid);
    es.addEventListener("update", function (e) {
      var d;
      try { d = JSON.parse(e.data); } catch (err) { return; }
      if (d.type === "log" || d.type === "status") {
        append((d.ts ? "[" + d.ts + "] " : "") + d.line, classify(d.line));
      } else if (d.type === "progress") {
        if (bar) bar.style.width = Math.min(100, d.pct) + "%";
        if (pct) pct.textContent = d.pct.toFixed(1) + "%";
      } else if (d.type === "findings") {
        window.toast(d.total + " triage finding(s) raised", "err", 6000);
      } else if (d.type === "job") {
        if (badge) {
          badge.className = "st st-" + d.status;
          badge.textContent = d.status;
        }
        if (d.final) {
          if (bar) bar.style.width = "100%";
          append("--- run finished: " + d.status + " (" +
                 (d.rows || 0) + " rows) ---", "ln-ok");
          if (!stuck && opts.reloadOnFinish) {
            stuck = true;
            setTimeout(function () { location.reload(); }, 1200);
          }
        }
      }
    });
    es.addEventListener("close", function () { es.close(); });
    es.onerror = function () { /* browser retries automatically */ };
    return es;
  };

  // Global job ticker used on list pages.
  window.attachJobsStream = function (onUpdate) {
    var es = new EventSource("/api/stream/jobs");
    es.addEventListener("update", function (e) {
      try { onUpdate(JSON.parse(e.data)); } catch (err) {}
    });
    return es;
  };

  window.livePoll = function (url, targetId, ms) {
    var el = document.getElementById(targetId);
    if (!el) return;
    function tick() {
      fetch(url, { headers: { "X-Requested-With": "fetch" } })
        .then(function (r) { return r.text(); })
        .then(function (html) { el.innerHTML = html; })
        .catch(function () {});
    }
    tick();
    return setInterval(tick, ms || 3000);
  };

  // -------------------------------------------------------------- upload
  window.initUploader = function () {
    var zone = document.getElementById("dropzone");
    var input = document.getElementById("fileinput");
    var progress = document.getElementById("uploadprog");
    var bar = document.getElementById("uploadbar");
    var label = document.getElementById("uploadlabel");
    if (!zone || !input) return;

    var uploading = false;

    function setUploading(state) {
      uploading = state;
      zone.classList.toggle("disabled", state);
      input.disabled = state;
    }

    function upload(file) {
      if (!file || uploading) return;
      setUploading(true);
      progress.style.display = "block";
      label.textContent = "Uploading " + file.name + " …";
      var caseSel = document.getElementById("case_id");
      var url = "/api/evidence/raw?filename=" + encodeURIComponent(file.name);
      if (caseSel && caseSel.value) url += "&case_id=" + caseSel.value;

      var xhr = new XMLHttpRequest();
      xhr.open("PUT", url, true);
      xhr.upload.onprogress = function (e) {
        if (!e.lengthComputable) return;
        var p = (e.loaded / e.total) * 100;
        bar.style.width = p.toFixed(1) + "%";
        label.textContent = file.name + " — " + p.toFixed(1) + "% (" +
          (e.loaded / 1073741824).toFixed(2) + " / " +
          (e.total / 1073741824).toFixed(2) + " GB)";
      };
      xhr.onload = function () {
        if (xhr.status >= 200 && xhr.status < 300) {
          var res = JSON.parse(xhr.responseText);
          label.textContent = "Done — opening evidence…";
          window.toast("Upload complete", "ok");
          setTimeout(function () { location.href = res.redirect; }, 700);
        } else {
          label.textContent = "Upload failed: " + xhr.responseText;
          window.toast("Upload failed", "err", 8000);
          setUploading(false);
        }
      };
      xhr.onerror = function () {
        label.textContent = "Upload failed (network error)";
        window.toast("Upload failed", "err");
        setUploading(false);
      };
      xhr.send(file);
    }

    zone.addEventListener("click", function () { if (!uploading) input.click(); });
    input.addEventListener("change", function () { upload(input.files[0]); });
    ["dragenter", "dragover"].forEach(function (ev) {
      zone.addEventListener(ev, function (e) {
        e.preventDefault();
        if (!uploading) zone.classList.add("hot");
      });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      zone.addEventListener(ev, function (e) {
        e.preventDefault(); zone.classList.remove("hot");
      });
    });
    zone.addEventListener("drop", function (e) {
      if (!uploading && e.dataTransfer.files.length) upload(e.dataTransfer.files[0]);
    });
  };

  // -------------------------------------------------------- table filter
  window.initTableFilter = function (inputId, tableId) {
    var input = document.getElementById(inputId);
    var table = document.getElementById(tableId);
    if (!input || !table) return;
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      var n = 0;
      table.querySelectorAll("tbody tr").forEach(function (tr) {
        var hit = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
        tr.style.display = hit ? "" : "none";
        if (hit) n++;
      });
      var c = document.getElementById(inputId + "-count");
      if (c) c.textContent = n;
    });
  };

  window.confirmSubmit = function (form, message) {
    if (window.confirm(message)) form.submit();
    return false;
  };

  window.copyText = function (text) {
    navigator.clipboard.writeText(text).then(function () {
      window.toast("Copied", "ok", 1500);
    });
  };

  document.addEventListener("DOMContentLoaded", function () {
    if (document.getElementById("dropzone")) window.initUploader();
    if (document.querySelector('input[name="plugins"]')) window.initPluginPicker();
    var box = document.getElementById("console");
    if (box) box.scrollTop = box.scrollHeight;
  });
})();
