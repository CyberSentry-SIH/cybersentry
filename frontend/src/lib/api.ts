const API_BASE = typeof window !== 'undefined'
  ? '/api/v1'
  : (process.env.NEXT_PUBLIC_API_URL || 'https://cybersentry-backend-egmb.onrender.com/api/v1');

function getToken(): string | null {
  if (typeof window !== 'undefined') {
    return localStorage.getItem('cybersentry_token');
  }
  return null;
}

async function fetchWithAuth(endpoint: string, options: RequestInit = {}) {
  const token = getToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'CyberSentryClient',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...((options.headers as Record<string, string>) || {}),
  };

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (!res.ok) {
    if (res.status === 401 && typeof window !== 'undefined' && !endpoint.includes('/auth/login') && !endpoint.includes('/health')) {
      localStorage.removeItem('cybersentry_token');
    }
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || 'An API error occurred');
  }

  // Some endpoints (e.g. logout, PDF report) may not return JSON.
  const contentType = res.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return null;
  }
  return res.json();
}

export const api = {
  // Auth
  login: async (data: { email: string; password: string }) => {
    const res = await fetchWithAuth('/auth/login', { method: 'POST', body: JSON.stringify(data) });
    if (res && res.access_token && typeof window !== 'undefined') {
      localStorage.setItem('cybersentry_token', res.access_token);
    }
    return res;
  },
  logout: async () => {
    try {
      await fetchWithAuth('/auth/logout', { method: 'POST' });
    } finally {
      if (typeof window !== 'undefined') {
        localStorage.removeItem('cybersentry_token');
      }
    }
  },
  getMe: () => fetchWithAuth('/auth/me'),
  getHealth: () => fetchWithAuth('/health'),

  // Evidence & Upload
  uploadEml: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const token = getToken();
    const headers: Record<string, string> = {
      'X-Requested-With': 'CyberSentryClient',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
    const res = await fetch(`${API_BASE}/evidence/upload`, {
      method: 'POST',
      body: formData,
      headers,
      credentials: 'include',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
  },
  listEvidence: () => fetchWithAuth('/evidence/'),
  getEvidence: (id: string) => fetchWithAuth(`/evidence/${id}`),
  getCustody: (id: string) => fetchWithAuth(`/evidence/${id}/custody`),

  // Analysis & Dashboard
  getDashboardStats: () => fetchWithAuth('/analysis/dashboard-stats'),
  getAnalysis: (id: string) => fetchWithAuth(`/analysis/${id}`),
  getHopGeo: (emailId: string) => fetchWithAuth(`/analysis/hops/${emailId}/geo`),

  // Standalone IP Geolocation
  lookupGeo: (ip: string) => fetchWithAuth(`/geo/lookup?ip=${encodeURIComponent(ip)}`),
  getGeoSamples: () => fetchWithAuth('/geo/sample-ips'),

  // Campaigns & Investigation (includes Variant Comparison — kept as-is,
  // not modified: see backend/app/services/campaign_service.py)
  listCampaigns: () => fetchWithAuth('/campaigns/'),
  getCampaign: (id: string) => fetchWithAuth(`/campaigns/${id}`),
  getCampaignInvestigation: (id: string) => fetchWithAuth(`/campaigns/${id}/investigation`),
  compareEmails: (emailA: string, emailB: string) =>
    fetchWithAuth(`/campaigns/compare?email_a=${emailA}&email_b=${emailB}`),

  // Graph
  getAttackGraph: (emailId?: string) => fetchWithAuth(emailId ? `/graph/?email_id=${emailId}` : '/graph/'),

  // Cases
  listCases: () => fetchWithAuth('/cases/'),
  createCase: (data: any) => fetchWithAuth('/cases/', { method: 'POST', body: JSON.stringify(data) }),
  submitDecision: (caseId: string, data: any) =>
    fetchWithAuth(`/cases/${caseId}/decision`, { method: 'POST', body: JSON.stringify(data) }),

  // Reports
  getJsonReport: (evidenceId: string) => fetchWithAuth(`/reports/${evidenceId}/json`),
  getPdfReportUrl: (evidenceId: string) => `${API_BASE}/reports/${evidenceId}/pdf`,

  // Admin
  listUsers: () => fetchWithAuth('/admin/users'),
  listAuditEvents: () => fetchWithAuth('/admin/audit-events'),
  listThreatIntel: () => fetchWithAuth('/admin/threat-intel'),
};
