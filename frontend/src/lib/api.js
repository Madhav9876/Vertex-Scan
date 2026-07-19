import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_URL ? `${API_URL}/api/v1` : '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (data) => api.post('/auth/register', data),
  login: (data) => api.post('/auth/login', data),
  me: () => api.get('/auth/me'),
  generateApiKey: () => api.post('/auth/api-key'),
  googleLogin: (credential) => api.post('/oauth/google', { credential }),
  forgotPassword: (email) => api.post('/auth/forgot-password', { email }),
  resetPassword: (token, new_password) => api.post('/auth/reset-password', { token, new_password }),
};

export const scansAPI = {
  list: (params) => api.get('/scans', { params }),
  create: (data) => api.post('/scans', data),
  get: (id) => api.get(`/scans/${id}`),
  delete: (id) => api.delete(`/scans/${id}`),
  stats: () => api.get('/scans/stats'),
  updateFinding: (scanId, findingId, data) =>
    api.patch(`/scans/${scanId}/findings/${findingId}`, data),
};

export const reportsAPI = {
  list: () => api.get('/reports'),
  generate: (data) => api.post('/reports', data),
};

export default api;