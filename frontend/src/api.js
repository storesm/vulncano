const BASE = "/api";

async function handle(response) {
  if (response.status === 204) return null;
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!response.ok) {
    const detail = body && body.detail ? body.detail : text || response.statusText;
    const error = new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    error.status = response.status;
    error.underDevelopment = Boolean(body && body.under_development) || response.status === 501;
    throw error;
  }
  return body;
}

function query(params) {
  const clean = {};
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") clean[key] = value;
  });
  const search = new URLSearchParams(clean).toString();
  return search ? `?${search}` : "";
}

export const api = {
  get: (path, params) => fetch(BASE + path + query(params)).then(handle),
  post: (path, body) =>
    fetch(BASE + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
    }).then(handle),
  put: (path, body) =>
    fetch(BASE + path, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
    }).then(handle),
  del: (path) => fetch(BASE + path, { method: "DELETE" }).then(handle),
  upload: (path, formData) => fetch(BASE + path, { method: "POST", body: formData }).then(handle),
  download: (path) => window.open(BASE + path, "_blank"),
};

export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

export function severityClass(severity) {
  return `sev ${severity}`;
}

export function formatScore(value) {
  return value === null || value === undefined ? "—" : value.toFixed(1);
}

export function formatDate(value) {
  if (!value) return "—";
  return String(value).slice(0, 10);
}

export function componentLines(components) {
  return (components || "").split("\n").filter((line) => line.trim());
}
