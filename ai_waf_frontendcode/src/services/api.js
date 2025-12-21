import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error);
    return Promise.reject(error);
  }
);

// Admin API endpoints
export const adminAPI = {
  // Statistics
  getStats: () => api.get('/api/admin/stats'),
  
  // Logs
  getLogs: (limit = 100, offset = 0) => 
    api.get('/api/admin/logs', { params: { limit, offset } }),
  
  getLogDetails: (logId) => 
    api.get(`/api/admin/logs/${logId}`),
  
  getAttacks: (limit = 100) => 
    api.get('/api/admin/attacks', { params: { limit } }),
  
  // Whitelist
  getWhitelist: () => api.get('/api/admin/whitelist'),
  addToWhitelist: (ipAddress, reason, addedBy) => 
    api.post('/api/admin/whitelist', { ip_address: ipAddress, reason, added_by: addedBy }),
  removeFromWhitelist: (ipAddress) => 
    api.delete(`/api/admin/whitelist/${ipAddress}`),
  
  // Blacklist
  getBlacklist: () => api.get('/api/admin/blacklist'),
  addToBlacklist: (ipAddress, reason, addedBy, expiresHours) => 
    api.post('/api/admin/blacklist', { 
      ip_address: ipAddress, 
      reason, 
      added_by: addedBy,
      expires_hours: expiresHours 
    }),
  removeFromBlacklist: (ipAddress) => 
    api.delete(`/api/admin/blacklist/${ipAddress}`),
  
  // Configuration
  getConfig: () => api.get('/api/admin/config'),
  updateConfig: (configData) => api.put('/api/admin/config', configData),
  
  // ML Models
  getModels: () => api.get('/api/admin/models'),
  
  // Health check
  healthCheck: () => api.get('/api/admin/health'),
};

// Traffic API endpoints
export const trafficAPI = {
  getStats: () => api.get('/api/traffic/stats'),
  testWAF: (testData) => api.post('/api/traffic/test', testData),
  getLogs: (limit = 50, offset = 0, blockedOnly = false) => 
    api.get('/api/traffic/logs', { params: { limit, offset, blocked_only: blockedOnly } }),
  analyzeRequest: (requestData) => api.post('/api/traffic/analyze', requestData),
  getConfig: () => api.get('/api/traffic/config'),
  updateConfig: (configData) => api.put('/api/traffic/config', configData),
};

// System endpoints
export const systemAPI = {
  getHealth: () => api.get('/health'),
  getDocs: () => api.get('/docs'),
  getHome: () => api.get('/'),
};

export default api;

