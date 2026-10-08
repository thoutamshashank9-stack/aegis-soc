import axios from 'axios';

// Resolve API base URL dynamically from Vite environment variable
// In development: defaults to VITE_API_BASE_URL or relative /api
// In Render production: points directly to deployed backend (e.g., https://your-backend.onrender.com)
const rawBase = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '');
const API_BASE = rawBase ? (rawBase.endsWith('/api') ? rawBase : `${rawBase}/api`) : '/api';

const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 45000,
});

// Production error interceptor to ensure network/server failures produce clean user-facing messages
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    let message = 'An unexpected network error occurred while communicating with the threat analysis engine.';
    if (error.response?.data?.detail) {
      message = typeof error.response.data.detail === 'string'
        ? error.response.data.detail
        : JSON.stringify(error.response.data.detail);
    } else if (error.response?.data?.message) {
      message = error.response.data.message;
    } else if (error.message) {
      message = error.message;
    }

    // Attach human-readable status for SOC dashboard toast/alert displays
    const enhancedError = new Error(message);
    enhancedError.status = error.response?.status;
    enhancedError.data = error.response?.data;
    enhancedError.isNetworkError = !error.response;
    return Promise.reject(enhancedError);
  }
);

export const api = {
  // Base configuration inspection
  getBaseUrl: () => API_BASE,

  // Analyze uploaded .eml file
  analyzeFile: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await apiClient.post('/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  },

  // Analyze pasted raw email text
  analyzeText: async (rawText, filename = 'pasted_email.eml') => {
    const response = await apiClient.post('/analyze/text', {
      raw_text: rawText,
      filename: filename,
    });
    return response.data;
  },

  // Retrieve past investigations
  getAnalyses: async () => {
    const response = await apiClient.get('/analyses');
    return response.data;
  },

  // Dynamic database metrics
  getDashboardStats: async () => {
    const response = await apiClient.get('/dashboard/stats');
    return response.data;
  },

  // Retrieve specific analysis details
  getAnalysis: async (id) => {
    const response = await apiClient.get(`/analysis/${id}`);
    return response.data;
  },

  // Get executive report
  getReport: async (id) => {
    const response = await apiClient.get(`/analysis/${id}/report`);
    return response.data;
  },

  // Get IOCs
  getIOCs: async (id) => {
    const response = await apiClient.get(`/analysis/${id}/iocs`);
    return response.data;
  },

  // System & ML status
  getHealth: async () => {
    const response = await apiClient.get('/health');
    return response.data;
  },

  getSystemStatus: async () => {
    const response = await apiClient.get('/system/status');
    return response.data;
  },

  getMLStatus: async () => {
    const response = await apiClient.get('/ml/status');
    return response.data;
  },

  // Synthetic Test Samples
  getSamples: async () => {
    const response = await apiClient.get('/samples');
    return response.data;
  },

  getSampleContent: async (filename) => {
    const response = await apiClient.get(`/samples/${filename}`);
    return response.data;
  },
};
