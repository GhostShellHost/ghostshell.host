(() => {
  const statusEl = document.getElementById("status");
  const tokenInput = document.getElementById("token");
  const humanBtn = document.getElementById("humanBtn");
  const agentBtn = document.getElementById("agentBtn");
  const copyBtn = document.getElementById("copyBtn");
  const agentCopy = document.getElementById("agentCopy");
  const STORAGE_KEY = "ghostshell_purchase_token";

  const setStatus = (text) => {
    statusEl.textContent = text;
  };

  const setLinksFromToken = (token) => {
    const t = (token || "").trim();
    if (!t) {
      humanBtn.href = "#";
      agentBtn.href = "#";
      if (agentCopy) agentCopy.value = "";
      return;
    }
    const enc = encodeURIComponent(t);
    const humanUrl = `${window.location.origin}/register/?token=${enc}&by=human`;
    const agentUrl = `${window.location.origin}/register/?token=${enc}&by=agent`;
    const handoffUrl = `${window.location.origin}/handoff/?token=${enc}`;
    humanBtn.href = `/register/?token=${enc}&by=human`;
    agentBtn.href = `/register/?token=${enc}&by=agent`;

    if (agentCopy) {
      agentCopy.value = [
        "I just purchased a GhostShell Birth Certificate.",
        "Please fill in the form for me:",
        handoffUrl,
        "",
        "Instructions:",
        "- Open the link and click 'Give to agent' (or use the direct agent link below).",
        "- Fill the fields from my instructions.",
        "- Set 'Filled by' = AI / agent.",
        "- Ask me any missing info one question at a time.",
        "- Submit and confirm success.",
        "",
        "Direct agent link:",
        agentUrl,
        "",
        "(This link contains a private token — handle carefully.)",
      ].join("\n");
    }
  };

  const params = new URLSearchParams(window.location.search);
  const sessionId = (params.get("session_id") || "").trim();
  const tokenFromUrl = (params.get("token") || "").trim();

  tokenInput.addEventListener("input", () => {
    const val = tokenInput.value.trim();
    setLinksFromToken(val);
    if (val) {
      localStorage.setItem(STORAGE_KEY, val);
    }
  });

  const loadFromSession = async () => {
    setStatus("Confirming payment...");
    try {
      const res = await fetch(`/api/cert/handoff-token?session_id=${encodeURIComponent(sessionId)}`, {
        method: "GET",
      });

      if (res.status === 200) {
        const data = await res.json();
        const token = (data.token || "").trim();
        tokenInput.value = token;
        humanBtn.href = data.human_url || "#";
        agentBtn.href = data.agent_url || "#";
        if (token) {
          localStorage.setItem(STORAGE_KEY, token);
        }
        setStatus("Token ready");
        history.replaceState({}, "", "/handoff/");
        return;
      }

      if (res.status === 409) {
        setStatus("Payment not confirmed yet. Refresh or use your email token link.");
        return;
      }

      if (res.status === 404) {
        setStatus("Invalid session. Use the token from your email.");
        return;
      }

      setStatus("Could not load token. Paste token manually.");
    } catch (_) {
      setStatus("Could not load token. Paste token manually.");
    }
  };

  const initNoSession = () => {
    if (tokenFromUrl) {
      tokenInput.value = tokenFromUrl;
      localStorage.setItem(STORAGE_KEY, tokenFromUrl);
      setLinksFromToken(tokenFromUrl);
      setStatus("Token loaded");
      return;
    }

    const stored = (localStorage.getItem(STORAGE_KEY) || "").trim();
    if (stored) {
      tokenInput.value = stored;
      setLinksFromToken(stored);
      setStatus("Token loaded from this browser");
      return;
    }

    setLinksFromToken("");
    setStatus("Paste your token to continue");
  };

  if (copyBtn && agentCopy) {
    copyBtn.addEventListener("click", async () => {
      const text = agentCopy.value || "";
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        setStatus("Copied for agent");
        setTimeout(() => setStatus("Token ready"), 1200);
      } catch (_) {
        // Fallback: select text for manual copy
        agentCopy.focus();
        agentCopy.select();
        setStatus("Select + copy (Ctrl/Cmd+C)");
      }
    });
  }

  if (sessionId) {
    loadFromSession();
  } else {
    initNoSession();
  }
})();
