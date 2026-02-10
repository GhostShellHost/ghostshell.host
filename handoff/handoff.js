(() => {
  const statusEl = document.getElementById("status");
  const tokenInput = document.getElementById("token");
  const humanBtn = document.getElementById("humanBtn");
  const agentBtn = document.getElementById("agentBtn");
  const STORAGE_KEY = "ghostshell_purchase_token";

  const setStatus = (text) => {
    statusEl.textContent = text;
  };

  const setLinksFromToken = (token) => {
    const t = (token || "").trim();
    if (!t) {
      humanBtn.href = "#";
      agentBtn.href = "#";
      return;
    }
    const enc = encodeURIComponent(t);
    humanBtn.href = `/register/?token=${enc}&by=human`;
    agentBtn.href = `/register/?token=${enc}&by=agent`;
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

  if (sessionId) {
    loadFromSession();
  } else {
    initNoSession();
  }
})();
