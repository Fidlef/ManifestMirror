const RULES = {
  tabs: {weight: 2, capability: "Can inspect tab metadata such as URLs and titles when permitted by the browser."},
  cookies: {weight: 4, capability: "Can read or modify cookies for hosts the extension can access."},
  history: {weight: 4, capability: "Can read browsing history."},
  downloads: {weight: 2, capability: "Can initiate and observe downloads."},
  clipboardRead: {weight: 4, capability: "Can read clipboard contents in allowed contexts."},
  clipboardWrite: {weight: 1, capability: "Can write to the clipboard."},
  webRequest: {weight: 3, capability: "Can observe network request metadata for allowed hosts."},
  nativeMessaging: {weight: 5, capability: "Can communicate with a separately installed native application."},
  debugger: {weight: 5, capability: "Can attach browser debugging capabilities to tabs after browser approval."},
  management: {weight: 4, capability: "Can inspect and manage other installed extensions."},
};

function normalizedPermissions(manifest) {
  return new Set([...(manifest.permissions || []), ...(manifest.optional_permissions || [])].filter(x => typeof x === "string"));
}

function hostAccess(manifest) {
  const entries = [...(manifest.host_permissions || []), ...(manifest.permissions || []).filter(x => typeof x === "string" && (x.includes("://") || x === "<all_urls>"))];
  return [...new Set(entries)];
}

export function auditManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("The manifest must be a JSON object.");
  const permissions = normalizedPermissions(manifest);
  const hosts = hostAccess(manifest);
  const broadHost = hosts.some(host => host === "<all_urls>" || /^\*:\/\/\*\//.test(host));
  const findings = [];
  let score = 0;
  for (const permission of permissions) {
    const rule = RULES[permission];
    if (rule) {
      score += rule.weight;
      findings.push({severity: rule.weight >= 4 ? "high" : rule.weight >= 2 ? "medium" : "low", title: permission, detail: rule.capability});
    }
  }
  if (broadHost) {
    score += 5;
    findings.push({severity: "high", title: "Broad host access", detail: "The extension requests access across nearly every website instead of a narrow host list."});
  }
  if (broadHost && permissions.has("cookies")) {
    score += 5;
    findings.push({severity: "critical", title: "Combination: cookies + broad hosts", detail: "Together, these permissions may expose session data across many sites. Confirm that the feature truly requires both."});
  }
  if (broadHost && (permissions.has("webRequest") || permissions.has("tabs"))) {
    score += 3;
    findings.push({severity: "high", title: "Combination: observation + broad hosts", detail: "This combination creates a much wider browsing-observation capability than either permission suggests alone."});
  }
  if (permissions.has("nativeMessaging") && broadHost) {
    score += 4;
    findings.push({severity: "critical", title: "Combination: native messaging + broad hosts", detail: "Web content access combined with a native bridge creates a large trust boundary."});
  }
  if (manifest.manifest_version === 2) findings.push({severity: "medium", title: "Manifest V2", detail: "Review migration requirements and whether older background-page behavior is still necessary."});

  const questions = [];
  if (broadHost) questions.push("Can host access be limited to specific domains or granted only after a user action?");
  for (const permission of permissions) if (RULES[permission]?.weight >= 4) questions.push(`Which exact user-facing feature requires “${permission}”?`);
  if ((manifest.optional_permissions || []).length === 0 && score > 4) questions.push("Could sensitive permissions be requested optionally at the moment the feature is used?");
  if (questions.length === 0) questions.push("Are all requested permissions directly tied to a documented feature?");
  const bounded = Math.min(100, score * 6);
  const level = bounded >= 70 ? "High review priority" : bounded >= 35 ? "Moderate review priority" : "Low review priority";
  return {score: bounded, level, findings, questions, permissions: [...permissions], hosts, disclaimer: "Permissions describe capability, not proof of malicious behavior."};
}
