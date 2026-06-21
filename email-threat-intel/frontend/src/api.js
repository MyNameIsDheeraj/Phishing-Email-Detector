// src/api.js

const API_BASE_URL = 'http://localhost:8000';

/**
 * Helper to handle fetch responses and handle JSON / text error outputs
 */
async function handleResponse(response) {
  if (!response.ok) {
    let errorMsg = `API request failed with status ${response.status}`;
    try {
      const data = await response.json();
      errorMsg = data.error?.message || data.detail || errorMsg;
    } catch (_) {
      // ignore JSON parse failure
    }
    throw new Error(errorMsg);
  }
  return response.json();
}

export const api = {
  /**
   * Get dashboard statistics
   */
  getDashboardStats: async () => {
    const res = await fetch(`${API_BASE_URL}/dashboard/stats`);
    return handleResponse(res);
  },

  /**
   * Get paginated email history with optional verdict filtering
   */
  getEmails: async (skip = 0, limit = 50, verdict = null) => {
    let url = `${API_BASE_URL}/emails?skip=${skip}&limit=${limit}`;
    if (verdict && verdict !== 'ALL') {
      url += `&verdict=${verdict.toUpperCase()}`;
    }
    const res = await fetch(url);
    return handleResponse(res);
  },

  /**
   * Get 10 recent scans
   */
  getRecentEmails: async () => {
    const res = await fetch(`${API_BASE_URL}/emails/recent`);
    return handleResponse(res);
  },

  /**
   * Get detailed analysis of a single email
   */
  getEmailDetails: async (id) => {
    const res = await fetch(`${API_BASE_URL}/email/${id}`);
    return handleResponse(res);
  },

  /**
   * Get parsed timeline events of an email
   */
  getEmailTimeline: async (id) => {
    const res = await fetch(`${API_BASE_URL}/timeline/${id}`);
    return handleResponse(res);
  },

  /**
   * Upload an email file (.eml, .txt)
   */
  uploadEmailFile: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE_URL}/upload-email`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse(res);
  },

  /**
   * Submit raw email text for analysis
   */
  analyzeEmailText: async (emailText) => {
    const res = await fetch(`${API_BASE_URL}/analyze-email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email_text: emailText }),
    });
    return handleResponse(res);
  },

  /**
   * Force external lookup enrichment (VT and AbuseIPDB)
   */
  enrichEmail: async (id) => {
    const res = await fetch(`${API_BASE_URL}/email/${id}/enrich`, {
      method: 'POST',
    });
    return handleResponse(res);
  },

  /**
   * Delete an email scan record
   */
  deleteEmail: async (id) => {
    const res = await fetch(`${API_BASE_URL}/email/${id}`, {
      method: 'DELETE',
    });
    return handleResponse(res);
  },

  /**
   * Get the direct download URL for the PDF report
   */
  getReportDownloadUrl: (id) => {
    return `${API_BASE_URL}/report/${id}`;
  }
};
