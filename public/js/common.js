/* ==========================================================================
   cybersite — script partagé (HUD horloge + IP visiteur + helpers)
   ========================================================================== */

(function () {
  "use strict";

  /* ------------------------------------------------------------- Horloge -- */
  function startClock() {
    const el = document.getElementById("hud-clock");
    if (!el) return;
    const tick = () => {
      const now = new Date();
      const hh = String(now.getHours()).padStart(2, "0");
      const mm = String(now.getMinutes()).padStart(2, "0");
      const ss = String(now.getSeconds()).padStart(2, "0");
      el.textContent = `${hh}:${mm}:${ss}`;
    };
    tick();
    setInterval(tick, 1000);
  }

  /* ----------------------------------------------------------- Adresse IP -- */
  function startIp() {
    const el = document.getElementById("hud-ip");
    if (!el) return;
    const placeholder = "···.···.···.···";
    el.textContent = placeholder;

    // 1) Tente le backend local (source de vérité).
    fetch("/api/ip", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("api"))))
      .then((data) => {
        if (data && data.ip) {
          el.textContent = data.ip;
          el.title = "IP détectée par le serveur";
          return;
        }
        throw new Error("empty");
      })
      .catch(() => {
        // 2) Fallback : service public (utile si ouvert en statique).
        fetch("https://api.ipify.org?format=json", { cache: "no-store" })
          .then((r) => r.json())
          .then((data) => {
            if (data && data.ip) el.textContent = data.ip;
            else el.textContent = "inconnue";
          })
          .catch(() => {
            el.textContent = "inconnue";
            el.title = "Impossible de récupérer l'IP";
          });
      });
  }

  /* -------------------------------------------------------------- Helpers -- */
  // Échappe le texte pour éviter toute injection HTML (XSS).
  function esc(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function fmtDate(iso) {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString("fr-FR", {
        day: "2-digit",
        month: "short",
        year: "numeric",
      });
    } catch (_) {
      return iso || "";
    }
  }

  function fmtTime(iso) {
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString("fr-FR", {
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch (_) {
      return "";
    }
  }

  // Convertit un texte markdown très léger (titres, listes, code ```) en HTML sûr.
  function miniMarkdown(text) {
    const src = String(text || "");
    const codeBlocks = [];
    // Extrait d'abord les blocs de code pour ne pas les transformer.
    let out = src.replace(/```[^\n]*\n([\s\S]*?)```/g, (_, code) => {
      const i = codeBlocks.push(
        "<pre><code>" + esc(code.replace(/\n$/, "")) + "</code></pre>"
      );
      return `\u0000CODE${i - 1}\u0000`;
    });

    out = esc(out);

    // Titres
    out = out.replace(/^###### (.*)$/gm, "<h6>$1</h6>");
    out = out.replace(/^##### (.*)$/gm, "<h5>$1</h5>");
    out = out.replace(/^#### (.*)$/gm, "<h4>$1</h4>");
    out = out.replace(/^### (.*)$/gm, "<h3>$1</h3>");
    out = out.replace(/^## (.*)$/gm, "<h2>$1</h2>");
    out = out.replace(/^# (.*)$/gm, "<h1>$1</h1>");

    // Gras / code inline
    out = out.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    out = out.replace(/`([^`]+?)`/g, "<code>$1</code>");

    // Listes à puces simples
    out = out.replace(/(?:^|\n)((?:- .*(?:\n|$))+)/g, (_, block) => {
      const items = block
        .trim()
        .split("\n")
        .map((l) => "<li>" + l.replace(/^-\s*/, "") + "</li>")
        .join("");
      return "\n<ul>" + items + "</ul>";
    });

    // Paragraphes
    out = out
      .split(/\n{2,}/)
      .map((p) => {
        const t = p.trim();
        if (!t) return "";
        if (/^<(h\d|ul|pre|\u0000CODE)/.test(t)) return t;
        return "<p>" + t.replace(/\n/g, "<br>") + "</p>";
      })
      .join("");

    // Réinjecte les blocs de code.
    out = out.replace(/\u0000CODE(\d+)\u0000/g, (_, i) => codeBlocks[Number(i)] || "");

    return out;
  }

  /* ----------------------------------------------------------------- Init -- */
  document.addEventListener("DOMContentLoaded", () => {
    startClock();
    startIp();
  });

  // Expose les helpers pour les pages spécifiques.
  window.CYBER = { esc, fmtDate, fmtTime, miniMarkdown };
})();