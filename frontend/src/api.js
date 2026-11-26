const KEY = 'minisoc.token';

export const getToken = () => { try { return sessionStorage.getItem(KEY) || ''; } catch { return ''; } };
export const setToken = (token) => {
  try { if (token) sessionStorage.setItem(KEY, token); else sessionStorage.removeItem(KEY); } catch { /* kept in memory only */ }
};

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function call(path, { method = 'GET', body, token = getToken() } = {}) {
  const res = await fetch(path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && token) window.dispatchEvent(new Event('minisoc:unauthorized'));
  if (!res.ok) {
    const detail = await res.json().then((d) => d.detail).catch(() => res.statusText);
    throw new ApiError(res.status, typeof detail === 'string' ? detail : res.statusText);
  }
  return res.json();
}

export const api = {
  check: (token) => call('/api/stats', { token }),
  stats: () => call('/api/stats'),
  alerts: () => call('/api/alerts?limit=40'),
  incidents: () => call('/api/incidents'),
  incident: (id) => call(`/api/incidents/${id}`),
  patch: (id, body) => call(`/api/incidents/${id}`, { method: 'PATCH', body }),
  step: (id, index, done) => call(`/api/incidents/${id}/playbook/${index}`, { method: 'POST', body: { done } }),
  coverage: () => call('/api/coverage'),
};
