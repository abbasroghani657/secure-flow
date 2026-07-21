const BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8077";
const TOKEN_KEY = "sf_token";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t) {
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}

async function request(path, { method = "GET", body, auth = true, isForm = false } = {}) {
  const headers = {};
  if (!isForm) headers["Content-Type"] = "application/json";
  if (auth) {
    const t = getToken();
    if (t) headers.Authorization = `Bearer ${t}`;
  }
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: isForm ? body : body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data.detail || `Request failed (${res.status})`;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return data;
}

export const api = {
  register: (name, email, password) =>
    request("/api/auth/register", { method: "POST", body: { name, email, password }, auth: false }),
  login: (email, password) =>
    request("/api/auth/login", { method: "POST", body: { email, password }, auth: false }),
  me: () => request("/api/auth/me"),
  createScan: (target_url, scan_type = "web", auth = {}) =>
    request("/api/scans", { method: "POST", body: { target_url, scan_type, ...auth } }),
  uploadMobileScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return request("/api/scans/mobile", { method: "POST", body: fd, isForm: true });
  },
  uploadScaScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return request("/api/scans/sca", { method: "POST", body: fd, isForm: true });
  },
  uploadIosScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return request("/api/scans/ios", { method: "POST", body: fd, isForm: true });
  },
  uploadIacScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return request("/api/scans/iac", { method: "POST", body: fd, isForm: true });
  },
  listScans: () => request("/api/scans"),
  getScan: (id) => request(`/api/scans/${id}`),
  deleteScan: (id) => request(`/api/scans/${id}`, { method: "DELETE" }),

  // Targets
  createTarget: (url, label) =>
    request("/api/targets", { method: "POST", body: { url, label } }),
  listTargets: () => request("/api/targets"),
  getTarget: (id) => request(`/api/targets/${id}`),
  verifyTarget: (id) => request(`/api/targets/${id}/verify`, { method: "POST" }),
  deleteTarget: (id) => request(`/api/targets/${id}`, { method: "DELETE" }),

  // Schedules
  createSchedule: (body) => request("/api/schedules", { method: "POST", body }),
  listSchedules: () => request("/api/schedules"),
  updateSchedule: (id, body) => request(`/api/schedules/${id}`, { method: "PATCH", body }),
  deleteSchedule: (id) => request(`/api/schedules/${id}`, { method: "DELETE" }),
};
