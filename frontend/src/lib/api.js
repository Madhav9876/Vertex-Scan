import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_URL ? `${API_URL}/api/v1` : '/api/v1',
  withCredentials: true,
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

// Automatically refresh the access token once when it expires (401), then retry
// the original request. If refresh fails, send the user back to login.
let isRefreshing = false;
let pendingSubscribers = [];

function subscribeTokenRefresh(cb) {
  pendingSubscribers.push(cb);
}

function onTokenRefreshed(token) {
  pendingSubscribers.forEach((cb) => cb(token));
  pendingSubscribers = [];
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // The backend returns 403 (not 401) for an expired/invalid access token.
    // Treat both as refreshable so the user stays signed in during a scan.
    const status = error.response?.status;
    const isTokenError =
      status === 401 ||
      (status === 403 &&
        /invalid or expired token|token revoked|not authenticated/i.test(error.response?.data?.error || ''));

    if (isTokenError && !originalRequest._retry) {
      if (originalRequest.url?.includes('/auth/refresh') || originalRequest.url?.includes('/auth/login')) {
        localStorage.removeItem('token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        window.location.href = '/login';
        return Promise.reject(error);
      }

      if (isRefreshing) {
        // Queue the request until the in-flight refresh completes.
        return new Promise((resolve) => {
          subscribeTokenRefresh((token) => {
            originalRequest.headers.Authorization = `Bearer ${token}`;
            resolve(api(originalRequest));
          });
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Send the stored refresh token as a fallback (covers cross-origin prod
        // where the httpOnly cookie may not be delivered).
        const storedRefresh = localStorage.getItem('refresh_token');
        const res = await api.post('/auth/refresh', storedRefresh ? { refresh_token: storedRefresh } : undefined);
        const newToken = res.data.token;
        localStorage.setItem('token', newToken);
        if (res.data.refresh_token) localStorage.setItem('refresh_token', res.data.refresh_token);
        if (res.data.user) {
          localStorage.setItem('user', JSON.stringify(res.data.user));
        }
        api.defaults.headers.Authorization = `Bearer ${newToken}`;
        onTokenRefreshed(newToken);
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);
      } catch (refreshErr) {
        localStorage.removeItem('token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        window.location.href = '/login';
        return Promise.reject(refreshErr);
      } finally {
        isRefreshing = false;
      }
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