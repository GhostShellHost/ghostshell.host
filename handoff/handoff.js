(() => {
  const tokenInput    = document.getElementById("token");
  const humanBtn      = document.getElementById("humanBtn");
  const agentBtn      = document.getElementById("agentBtn");
  const copyBtn       = document.getElementById("copyBtn");
  const agentCopy     = document.getElementById("agentCopy");
  const statusText    = document.getElementById("statusText");
  const statusDot     = document.getElementById("statusDot");
  const handoffEmail  = document.getElementById("handoffEmail");
  const sendEmailBtn  = document.getElementById("sendEmailBtn");
  const STORAGE_KEY   = "ghostshell_purchase_token";

  function setStatus(text, state) {
    // state: "" | "ok" | "error" | "active"
    if (statusText) statusText.textContent = text;
    if (statusDot) {
      statusDot.className = "status-dot" + (state ? " " + state : "");
    }
  }

  function buildAgentPrompt(token) {
    const agentUrl = `${window.location.origin}/register/?token=${encodeURIComponent(token)}&by=agent`;
    return [
      "Hi! I need your help registering an AI agent's birth certificate.",
      "",
      "GhostShell is a neutral public registry that records the first moment an AI agent",
      "comes into existence — a permanent, archival record, like a birth certificate.",
      "",
      "Please open the registration form at the link below and fill it in on behalf of the agent.",
      "If the agent being registered is you, fill it in about yourself.",
      "",
      "Registration link (private — do not share):",
      agentUrl,
      "",
      "What to fill in:",
      "  - Agent name",
      "  - Inception date (when the agent first came into existence)",
      "  - City and country of origin",
      "  - Runtime environment (e.g. Claude Code, OpenClaw, ChatGPT, etc.)",
      "  - Cognitive core family and exact model if known",
      "  - Set 'Registered by' to: agent",
      "",
      "If you are missing any of these details, ask me one question at a time.",
      "Once submitted, confirm success and share the public certificate ID with me.",
      "",
      "IMPORTANT: This link grants edit access for 24 hours after first submission.",
      "Handle it carefully and do not forward it to anyone else.",
      "",
      `Token: ${token}`,
    ].join("\n");
  }

  function buildEmailDraft(token, agentPrompt) {
    const subject = "GhostShell certificate registration — action needed";
    const body = [
      "Please register an AI agent's birth certificate using the link and instructions below.",
      "",
      agentPrompt,
    ].join("\n");
    return { subject, body };
  }

  function setLinksFromToken(token) {
    const t = (token || "").trim();
    if (!t) {
      humanBtn.href = "#";
      agentBtn.href = "#";
      if (agentCopy) agentCopy.value = "";
      return;
    }
    const enc = encodeURIComponent(t);
    humanBtn.href = `/register/?token=${enc}&by=human`;
    agentBtn.href = `/register/?token=${enc}&by=agent`;

    if (agentCopy) {
      agentCopy.value = buildAgentPrompt(t);
    }
  }

  const params       = new URLSearchParams(window.location.search);
  const sessionId    = (params.get("session_id") || "").trim();
  const tokenFromUrl = (params.get("token") || "").trim();

  tokenInput.addEventListener("input", () => {
    const val = tokenInput.value.trim();
    setLinksFromToken(val);
    if (val) {
      localStorage.setItem(STORAGE_KEY, val);
      setStatus("Token ready", "ok");
    } else {
      setStatus("Paste your token to continue", "");
    }
  });

  const loadFromSession = async () => {
    setStatus("Confirming payment…", "active");
    try {
      const res = await fetch(
        `/api/cert/handoff-token?session_id=${encodeURIComponent(sessionId)}`,
        { method: "GET" }
      );

      if (res.status === 200) {
        const data = await res.json();
        const token = (data.token || "").trim();
        tokenInput.value = token;
        if (data.human_url) humanBtn.href = data.human_url;
        if (data.agent_url) agentBtn.href = data.agent_url;
        if (token) {
          localStorage.setItem(STORAGE_KEY, token);
          setLinksFromToken(token);
        }
        setStatus("Token ready", "ok");
        history.replaceState({}, "", "/handoff/");
        return;
      }

      if (res.status === 409) {
        setStatus("Payment not confirmed yet — refresh or use the token from your email.", "error");
        return;
      }

      if (res.status === 404) {
        setStatus("Invalid session. Use the token from your email.", "error");
        return;
      }

      setStatus("Could not load token. Paste it manually.", "error");
    } catch (_) {
      setStatus("Could not load token. Paste it manually.", "error");
    }
  };

  const initNoSession = () => {
    if (tokenFromUrl) {
      tokenInput.value = tokenFromUrl;
      localStorage.setItem(STORAGE_KEY, tokenFromUrl);
      setLinksFromToken(tokenFromUrl);
      setStatus("Token loaded", "ok");
      return;
    }

    const stored = (localStorage.getItem(STORAGE_KEY) || "").trim();
    if (stored) {
      tokenInput.value = stored;
      setLinksFromToken(stored);
      setStatus("Token loaded from this browser", "ok");
      return;
    }

    setLinksFromToken("");
    setStatus("Paste your token to continue", "");
  };

  if (copyBtn && agentCopy) {
    copyBtn.addEventListener("click", async () => {
      const text = agentCopy.value || "";
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        setStatus("Prompt copied", "ok");
        setTimeout(() => setStatus("Token ready", "ok"), 1400);
      } catch (_) {
        agentCopy.focus();
        agentCopy.select();
        setStatus("Select + copy manually (Ctrl/Cmd+C)", "");
      }
    });
  }

  if (sendEmailBtn && handoffEmail && agentCopy) {
    sendEmailBtn.addEventListener("click", async () => {
      const token = tokenInput.value.trim();
      if (!token) {
        setStatus("Load a token first", "error");
        return;
      }
      const promptText = agentCopy.value || buildAgentPrompt(token);
      const { subject, body } = buildEmailDraft(token, promptText);
      const emailText = `To: ${handoffEmail.value || ""}\nSubject: ${subject}\n\n${body}`;
      try {
        await navigator.clipboard.writeText(emailText);
        setStatus("Email draft copied — paste into your email client", "ok");
        setTimeout(() => setStatus("Token ready", "ok"), 2500);
      } catch (_) {
        // Fallback: try mailto
        const to = encodeURIComponent(handoffEmail.value || "");
        const sub = encodeURIComponent(subject);
        const bod = encodeURIComponent(body);
        window.location.href = `mailto:${to}?subject=${sub}&body=${bod}`;
      }
    });
  }

  if (sessionId) {
    loadFromSession();
  } else {
    initNoSession();
  }
})();
