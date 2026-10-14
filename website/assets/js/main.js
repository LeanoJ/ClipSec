// ClipSec – Webseite. Ohne Abhängigkeiten, CSP-tauglich (kein Inline-Code).
(() => {
  "use strict";

  const config = Object.assign(
    { githubUrl: "https://github.com/LeanoJ/ClipSec", downloadsPath: "downloads/" },
    window.CLIPSEC_CONFIG || {}
  );
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // ------------------------------------------------------------ Links aus der Konfiguration
  const repo = config.githubUrl.replace(/\/+$/, "");
  $$(".js-github").forEach((a) => (a.href = repo));
  $$(".js-releases").forEach((a) => (a.href = repo + "/releases"));
  $$(".js-security").forEach((a) => (a.href = repo + "/security/policy"));

  // ------------------------------------------------------------ Mobile Navigation
  const toggle = $(".nav-toggle");
  const nav = $("#site-nav");
  if (toggle && nav) {
    toggle.addEventListener("click", () => {
      const open = nav.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    nav.addEventListener("click", (e) => {
      if (e.target.closest("a")) {
        nav.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  // ------------------------------------------------------------ Download (latest.json)
  const formatSize = (bytes) => (bytes / 1024 / 1024).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " MB";
  const formatDate = (iso) => {
    const d = new Date(iso + "T00:00:00");
    return isNaN(d) ? iso : d.toLocaleDateString("de-DE", { day: "numeric", month: "long", year: "numeric" });
  };
  const safeFile = (name) => /^[\w.\-]+$/.test(name || "") ? name : null;

  async function loadRelease() {
    const button = $(".js-dl-button");
    const label = $(".js-dl-label");
    try {
      const res = await fetch(config.downloadsPath + "latest.json", { cache: "no-store" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const info = await res.json();
      const file = safeFile(info.url || info.file);
      if (!file) throw new Error("Ungültiger Dateiname");

      button.href = config.downloadsPath + file;
      button.removeAttribute("aria-disabled");
      button.setAttribute("download", file);
      label.textContent = `Download v${info.version}`;
      $(".js-dl-meta").textContent =
        `Version ${info.version} · ${formatDate(info.date)} · ${formatSize(info.size)} · Windows 10/11 (64-Bit)`;

      $$(".js-version").forEach((el) => (el.textContent = `Version ${info.version}`));
      $$(".js-version-footer").forEach((el) => (el.textContent = `Version ${info.version}`));

      if (/^[0-9a-f]{64}$/i.test(info.sha256 || "")) {
        $(".js-hash-value").textContent = info.sha256.toLowerCase();
        $(".js-hash").hidden = false;
      }
    } catch (err) {
      // Keine lokale Datei (z. B. Container ohne Downloads) → auf GitHub-Releases verweisen
      button.href = repo + "/releases/latest";
      button.removeAttribute("aria-disabled");
      label.textContent = "Zu den GitHub-Releases";
      $(".js-dl-fallback").hidden = false;
      $$(".js-version").forEach((el) => (el.textContent = "Neueste Version"));
    }
  }
  loadRelease();

  const copyBtn = $(".js-copy-hash");
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText($(".js-hash-value").textContent);
        copyBtn.classList.add("is-done");
        copyBtn.querySelector("use").setAttribute("href", "#i-check");
        setTimeout(() => {
          copyBtn.classList.remove("is-done");
          copyBtn.querySelector("use").setAttribute("href", "#i-copy");
        }, 1800);
      } catch {
        // Zwischenablage nicht erlaubt (z. B. http ohne TLS) → Text markieren
        const range = document.createRange();
        range.selectNodeContents($(".js-hash-value"));
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
    });
  }

  // ------------------------------------------------------------ Tabs (ARIA, Pfeiltasten)
  const tabs = $$('[role="tab"]');
  function selectTab(tab, focus) {
    tabs.forEach((t) => {
      const selected = t === tab;
      t.setAttribute("aria-selected", String(selected));
      t.tabIndex = selected ? 0 : -1;
      $("#" + t.getAttribute("aria-controls")).hidden = !selected;
    });
    if (focus) tab.focus();
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => selectTab(tab, false));
    tab.addEventListener("keydown", (e) => {
      let next = null;
      if (e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
      if (e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
      if (e.key === "Home") next = tabs[0];
      if (e.key === "End") next = tabs[tabs.length - 1];
      if (next) {
        e.preventDefault();
        selectTab(next, true);
      }
    });
  });

  // Einstellungs-Seiten umschalten
  const settingsMain = $(".js-settings-main");
  $$(".thumb").forEach((btn) => {
    btn.addEventListener("click", () => {
      settingsMain.src = btn.dataset.src;
      settingsMain.alt = btn.dataset.alt;
      $$(".thumb").forEach((b) => b.classList.toggle("is-active", b === btn));
    });
  });

  // ------------------------------------------------------------ Lightbox
  const lightbox = $(".lightbox");
  const lightboxImg = $(".lightbox-img");
  let lastFocus = null;
  function openLightbox(img) {
    lastFocus = document.activeElement;
    lightboxImg.src = img.currentSrc || img.src;
    lightboxImg.alt = img.alt;
    lightbox.hidden = false;
    $(".lightbox-close").focus();
    document.body.style.overflow = "hidden";
  }
  function closeLightbox() {
    lightbox.hidden = true;
    lightboxImg.src = "data:,";
    document.body.style.overflow = "";
    if (lastFocus) lastFocus.focus();
  }
  $$(".zoomable").forEach((img) => {
    img.tabIndex = 0;
    img.setAttribute("role", "button");
    img.addEventListener("click", () => openLightbox(img));
    img.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openLightbox(img);
      }
    });
  });
  lightbox.addEventListener("click", closeLightbox);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !lightbox.hidden) closeLightbox();
  });
})();
