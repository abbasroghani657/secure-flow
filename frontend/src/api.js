const BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8077";
export const API_BASE = BASE;
const TOKEN_KEY = "sf_token";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t) {
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}

export async function fetchWithAuth(path, { method = "GET", body, auth = true, isForm = false } = {}) {
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
    fetchWithAuth("/api/auth/register", { method: "POST", body: { name, email, password }, auth: false }),
  login: (email, password) =>
    fetchWithAuth("/api/auth/login", { method: "POST", body: { email, password }, auth: false }),
  me: () => fetchWithAuth("/api/auth/me"),
  updateProfile: (name) => fetchWithAuth("/api/auth/me", { method: "PATCH", body: { name } }),
  changePassword: (current_password, new_password) =>
    fetchWithAuth("/api/auth/change-password", { method: "POST", body: { current_password, new_password } }),
  deleteAccount: (password) => fetchWithAuth("/api/auth/me", { method: "DELETE", body: { password } }),
  verifyEmail: (token) => fetchWithAuth("/api/auth/verify-email", { method: "POST", body: { token } }),
  resendVerification: () => fetchWithAuth("/api/auth/resend-verification", { method: "POST" }),
  forgotPassword: (email) => fetchWithAuth("/api/auth/forgot-password", { method: "POST", body: { email } }),
  resetPassword: (token, new_password) => fetchWithAuth("/api/auth/reset-password", { method: "POST", body: { token, new_password } }),
  freezeAccount: (token) => fetchWithAuth(`/api/auth/freeze-account?token=${token}`),
  createScan: (target_url, scan_type = "web", auth = {}) =>
    fetchWithAuth("/api/scans", { method: "POST", body: { target_url, scan_type, ...auth } }),
  uploadMobileScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetchWithAuth("/api/scans/mobile", { method: "POST", body: fd, isForm: true });
  },
  uploadScaScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetchWithAuth("/api/scans/sca", { method: "POST", body: fd, isForm: true });
  },
  uploadIosScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetchWithAuth("/api/scans/ios", { method: "POST", body: fd, isForm: true });
  },
  uploadIacScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetchWithAuth("/api/scans/iac", { method: "POST", body: fd, isForm: true });
  },
  uploadSecretsScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetchWithAuth("/api/scans/secrets", { method: "POST", body: fd, isForm: true });
  },
  uploadCicdScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetchWithAuth("/api/scans/cicd", { method: "POST", body: fd, isForm: true });
  },
  uploadSastScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetchWithAuth("/api/scans/sast", { method: "POST", body: fd, isForm: true });
  },
  createCspmScan: (body) => fetchWithAuth("/api/scans/cspm", { method: "POST", body }),
  uploadApiScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetchWithAuth("/api/scans/api-spec", { method: "POST", body: fd, isForm: true });
  },
  uploadContainerScan: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetchWithAuth("/api/scans/container", { method: "POST", body: fd, isForm: true });
  },
  getPlan: () => fetchWithAuth("/api/billing/plan"),
  getRisk: () => fetchWithAuth("/api/risk"),
  getCompliance: () => fetchWithAuth("/api/compliance"),
  listScans: () => fetchWithAuth("/api/scans"),
  getScan: (id) => fetchWithAuth(`/api/scans/${id}`),
  setFindingStatus: (scanId, findingId, status) =>
    fetchWithAuth(`/api/scans/${scanId}/findings/${findingId}`, { method: "PATCH", body: { status } }),
  deleteScan: (id) => fetchWithAuth(`/api/scans/${id}`, { method: "DELETE" }),

  // Targets
  createTarget: (url, label) =>
    fetchWithAuth("/api/targets", { method: "POST", body: { url, label } }),
  listTargets: () => fetchWithAuth("/api/targets"),
  getTarget: (id) => fetchWithAuth(`/api/targets/${id}`),
  verifyTarget: (id) => fetchWithAuth(`/api/targets/${id}/verify`, { method: "POST" }),
  deleteTarget: (id) => fetchWithAuth(`/api/targets/${id}`, { method: "DELETE" }),

  // Schedules
  createSchedule: (body) => fetchWithAuth("/api/schedules", { method: "POST", body }),
  listSchedules: () => fetchWithAuth("/api/schedules"),
  updateSchedule: (id, body) => fetchWithAuth(`/api/schedules/${id}`, { method: "PATCH", body }),
  deleteSchedule: (id) => fetchWithAuth(`/api/schedules/${id}`, { method: "DELETE" }),

  // Integrations (Slack / Teams / Discord / webhook)
  listIntegrations: () => fetchWithAuth("/api/integrations"),
  createIntegration: (body) => fetchWithAuth("/api/integrations", { method: "POST", body }),
  updateIntegration: (id, body) => fetchWithAuth(`/api/integrations/${id}`, { method: "PATCH", body }),
  testIntegration: (id) => fetchWithAuth(`/api/integrations/${id}/test`, { method: "POST" }),
  deleteIntegration: (id) => fetchWithAuth(`/api/integrations/${id}`, { method: "DELETE" }),

  // API tokens (CLI / CI)
  listTokens: () => fetchWithAuth("/api/tokens"),
  createToken: (name) => fetchWithAuth("/api/tokens", { method: "POST", body: { name } }),
  revokeToken: (id) => fetchWithAuth(`/api/tokens/${id}`, { method: "DELETE" }),

  // Organizations / teams
  listOrgs: () => fetchWithAuth("/api/orgs"),
  getCurrentOrg: () => fetchWithAuth("/api/orgs/current"),
  createOrg: (name) => fetchWithAuth("/api/orgs", { method: "POST", body: { name } }),
  switchOrg: (id) => fetchWithAuth(`/api/orgs/switch/${id}`, { method: "POST" }),
  renameOrg: (name) => fetchWithAuth("/api/orgs/current", { method: "PATCH", body: { name } }),
  inviteMember: (email, role) => fetchWithAuth("/api/orgs/current/invitations", { method: "POST", body: { email, role } }),
  revokeInvite: (id) => fetchWithAuth(`/api/orgs/current/invitations/${id}`, { method: "DELETE" }),
  previewInvite: (token) => fetchWithAuth(`/api/orgs/invitations/${token}`),
  acceptInvite: (token) => fetchWithAuth(`/api/orgs/invitations/${token}/accept`, { method: "POST" }),
  changeRole: (userId, role) => fetchWithAuth(`/api/orgs/current/members/${userId}`, { method: "PATCH", body: { role } }),
  removeMember: (userId) => fetchWithAuth(`/api/orgs/current/members/${userId}`, { method: "DELETE" }),
  auditLog: () => fetchWithAuth("/api/orgs/current/audit"),
};
