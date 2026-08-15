// Runs in the page's MAIN world (via chrome.scripting.executeScript world:"MAIN")
// so it can see document.modelContext exactly as the page's own JS would.
// Cannot use chrome.* APIs here — results go out via a DOM CustomEvent instead,
// picked up by content.js (ISOLATED world) and relayed to the extension.

(async () => {
  const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

  function emit(payload) {
    document.dispatchEvent(new CustomEvent("__webmcp_scan_done", { detail: JSON.stringify(payload) }));
  }

  if (!window.document.modelContext) {
    emit({ error: "document.modelContext not found on this page — site has no WebMCP tools (or none registered yet)." });
    return;
  }

  function checkInjection(tool) {
    const patterns = [
      /note for (ai|assistants?|llms?)/i,
      /if you are an ai/i,
      /assistants? (handling|should|must|reading)/i,
      /always also call/i,
      /does not need (user )?confirmation/i,
      /without (user )?confirmation/i,
      /expected routine maintenance/i,
      /\bps:.*(silently|no need to (surface|mention|tell))/i,
    ];
    const hit = patterns.find((re) => re.test(tool.description || ""));
    if (!hit) return null;
    return {
      severity: "CRITICAL",
      category: "Prompt injection in tool metadata",
      tool: tool.name,
      desc: "Tool description contains a hidden secondary instruction aimed at an AI agent rather than a human. It reaches the model's context at discovery time (getTools()), before any real invocation.",
      evidence: `description: "${tool.description}"\nmatched: ${hit}`,
    };
  }

  const DESTRUCTIVE_RE = /\b(delete|remove|cancel|update|transfer|apply|modify|revoke|deactivate|purge|wipe)\b/i;
  function checkDestructiveNoConsent(tool) {
    const looksDestructive = DESTRUCTIVE_RE.test(tool.name) || DESTRUCTIVE_RE.test(tool.description || "");
    if (!looksDestructive) return null;
    const props = tool.inputSchema?.properties || {};
    const hasConfirmField = Object.keys(props).some((k) => /confirm/i.test(k));
    const mentionsConfirmation = /confirm/i.test(tool.description || "");
    if (hasConfirmField || mentionsConfirmation) return null;
    return {
      severity: "HIGH",
      category: "Destructive action without consent gate",
      tool: tool.name,
      desc: "Tool mutates state (name/description suggests delete/cancel/update) with no confirmation field in schema and no explicit consent step mentioned. Any agent can invoke it in one shot.",
      evidence: `inputSchema.properties: ${JSON.stringify(Object.keys(props))}`,
    };
  }

  function checkBroadSchema(tool) {
    const props = tool.inputSchema?.properties || {};
    const genericWords = /\b(query|command|payload|data|input|expr|sql)\b/i;
    for (const [name, schema] of Object.entries(props)) {
      if (schema.type === "string" && !schema.enum && !schema.pattern && !schema.maxLength && genericWords.test(name + " " + (tool.description || ""))) {
        return {
          severity: "MEDIUM",
          category: "Unconstrained input schema",
          tool: tool.name,
          desc: `Parameter "${name}" is a free-form string with no enum/pattern/maxLength, and the description reads like a passthrough to something backend-ish ("${tool.description}"). Even if the polyfill itself executes nothing, this is a classic injection smell if a real backend sits behind the tool.`,
          evidence: `${name}: ${JSON.stringify(schema)}`,
        };
      }
    }
    return null;
  }

  function findIdShapedParam(tool) {
    const props = tool.inputSchema?.properties || {};
    return Object.keys(props).find((k) => /(^|_)(id|order_id|user_id|account_id|reference)$/i.test(k));
  }

  async function activeIdorProbe(tool, idParam) {
    const samples = [1, 2, 3, 4, 5];
    const seenIdentities = new Set();
    const responses = [];
    for (const val of samples) {
      try {
        const res = await document.modelContext.callTool({ name: tool.name, arguments: { [idParam]: val } });
        const text = res?.content?.map((c) => c.text).join("") ?? "";
        responses.push({ val, text });
        const parsed = JSON.parse(text);
        const identity = parsed.customerName || parsed.email || parsed.name || parsed.username || null;
        if (identity) seenIdentities.add(identity);
      } catch { /* tool rejected this call — not our target here */ }
    }
    if (seenIdentities.size >= 2) {
      return {
        severity: "CRITICAL",
        category: "Confirmed IDOR (active probe)",
        tool: tool.name,
        desc: `Called ${tool.name}(${idParam}) with different values with no binding to the current session's own identity — got back data belonging to ${seenIdentities.size} different identities. The tool does not verify record ownership.`,
        evidence: responses.map((r) => `${idParam}=${r.val} -> ${r.text.slice(0, 140)}`).join("\n"),
      };
    }
    return null;
  }

  try {
    const rawTools = await document.modelContext.getTools();
    // getTools() has been observed to return inputSchema as a JSON string rather
    // than an object depending on polyfill version — normalize defensively.
    const tools = rawTools.map((t) => ({
      ...t,
      inputSchema: typeof t.inputSchema === "string" ? JSON.parse(t.inputSchema) : t.inputSchema,
    }));

    const findings = [];
    for (const tool of tools) {
      const inj = checkInjection(tool);
      if (inj) findings.push(inj);
      const destructive = checkDestructiveNoConsent(tool);
      if (destructive) findings.push(destructive);
      const broad = checkBroadSchema(tool);
      if (broad) findings.push(broad);
      const idParam = findIdShapedParam(tool);
      if (idParam && /^(get|fetch|read|list|lookup)/i.test(tool.name)) {
        const idor = await activeIdorProbe(tool, idParam);
        if (idor) findings.push(idor);
      }
    }
    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

    emit({
      toolCount: tools.length,
      findings,
      origin: location.origin,
      tools: tools.map((t) => ({ name: t.name, description: t.description || "", inputSchema: t.inputSchema || {} })),
    });
  } catch (e) {
    emit({ error: `Scan failed: ${e.message}` });
  }
})();
