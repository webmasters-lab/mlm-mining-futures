// src/services/api.js
import axios from 'axios';
import { store } from '../store';
import { logout, refreshToken } from '../store/slices/authSlice';
import { showToast } from '../utils/toast';
import { isTokenExpired, decodeToken } from '../utils/tokenUtils';
import { getRefreshToken, clearAuthData, saveAuthData } from '../utils/storage';
import { trackApiError } from '../utils/analytics';

// Environment-based configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://api.mlm-mining.com/api/v1';
const API_TIMEOUT = parseInt(process.env.REACT_APP_API_TIMEOUT) || 30000;
const API_MAX_RETRIES = parseInt(process.env.REACT_APP_API_MAX_RETRIES) || 3;

// Create Axios instance
const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: API_TIMEOUT,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-App-Version': process.env.REACT_APP_VERSION || '1.0.0',
    'X-Platform': 'web',
  },
});

// Request queue for token refresh
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// Request interceptor
axiosInstance.interceptors.request.use(
  async (config) => {
    // Add timestamp for cache busting
    if (config.method === 'get') {
      config.params = {
        ...config.params,
        _t: Date.now(),
      };
    }

    // Add authentication token
    const token = localStorage.getItem('access_token');
    if (token) {
      // Check if token is about to expire (within 5 minutes)
      if (isTokenExpired(token, 5 * 60 * 1000)) {
        if (!isRefreshing) {
          isRefreshing = true;
          try {
            const newToken = await refreshAuthToken();
            config.headers.Authorization = `Bearer ${newToken}`;
            processQueue(null, newToken);
          } catch (error) {
            processQueue(error, null);
            throw error;
          } finally {
            isRefreshing = false;
          }
        } else {
          // Wait for token refresh
          return new Promise((resolve, reject) => {
            failedQueue.push({ resolve, reject });
          }).then(token => {
            config.headers.Authorization = `Bearer ${token}`;
            return config;
          }).catch(err => {
            return Promise.reject(err);
          });
        }
      } else {
        config.headers.Authorization = `Bearer ${token}`;
      }
    }

    // Add request ID for tracking
    config.headers['X-Request-ID'] = generateRequestId();

    // For file uploads, change content type
    if (config.data instanceof FormData) {
      config.headers['Content-Type'] = 'multipart/form-data';
    }

    // Add language header
    const language = localStorage.getItem('i18nextLng') || 'en';
    config.headers['Accept-Language'] = language;

    // Log request in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`🌐 API Request: ${config.method.toUpperCase()} ${config.url}`, config);
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
axiosInstance.interceptors.response.use(
  (response) => {
    // Log successful response in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`✅ API Response: ${response.config.url}`, response.data);
    }

    // Handle custom response format
    if (response.data?.success === false) {
      throw new Error(response.data.message || 'Request failed');
    }

    return response.data;
  },
  async (error) => {
    const originalRequest = error.config;
    
    // Track API error
    trackApiError(error);

    // Network error
    if (!error.response) {
      showToast('Network error. Please check your connection.', 'error');
      return Promise.reject({
        message: 'Network error. Please check your internet connection.',
        code: 'NETWORK_ERROR',
      });
    }

    const { status, data } = error.response;
    const errorMessage = data?.message || 'An error occurred';

    // Handle specific HTTP status codes
    switch (status) {
      case 401: // Unauthorized
        if (originalRequest.url.includes('/auth/refresh')) {
          // Refresh token failed - logout user
          store.dispatch(logout());
          showToast('Session expired. Please login again.', 'error');
          return Promise.reject(error);
        }

        if (!originalRequest._retry) {
          originalRequest._retry = true;
          try {
            const newToken = await refreshAuthToken();
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            return axiosInstance(originalRequest);
          } catch (refreshError) {
            store.dispatch(logout());
            showToast('Session expired. Please login again.', 'error');
            return Promise.reject(refreshError);
          }
        }
        break;

      case 403: // Forbidden
        showToast('You do not have permission to perform this action.', 'error');
        break;

      case 404: // Not Found
        showToast('The requested resource was not found.', 'error');
        break;

      case 422: // Validation Error
        // Handle validation errors (show first error)
        const validationErrors = data?.errors;
        if (validationErrors) {
          const firstError = Object.values(validationErrors)[0];
          showToast(firstError[0] || 'Validation failed', 'error');
        }
        break;

      case 429: // Too Many Requests
        showToast('Too many requests. Please try again later.', 'error');
        break;

      case 500: // Server Error
        showToast('Server error. Please try again later.', 'error');
        break;

      case 503: // Service Unavailable
        showToast('Service temporarily unavailable. Please try again later.', 'error');
        break;

      default:
        showToast(errorMessage, 'error');
    }

    // Log error details in development
    if (process.env.NODE_ENV === 'development') {
      console.error('❌ API Error:', {
        url: originalRequest.url,
        method: originalRequest.method,
        status: error.response.status,
        data: error.response.data,
      });
    }

    return Promise.reject({
      code: status,
      message: errorMessage,
      errors: data?.errors,
      timestamp: new Date().toISOString(),
    });
  }
);

// Refresh token function
async function refreshAuthToken() {
  try {
    const refreshToken = getRefreshToken();
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
      refresh_token: refreshToken,
    });

    const { access_token, refresh_token, expires_in } = response.data;
    
    // Save new tokens
    saveAuthData({
      accessToken: access_token,
      refreshToken: refresh_token,
      expiresIn: expires_in,
    });

    // Update Axios default header
    axiosInstance.defaults.headers.Authorization = `Bearer ${access_token}`;

    return access_token;
  } catch (error) {
    clearAuthData();
    throw error;
  }
}

// Generate unique request ID
function generateRequestId() {
  return 'req_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// Retry function for failed requests
axiosInstance.retryRequest = async (requestFn, retries = API_MAX_RETRIES, delay = 1000) => {
  for (let i = 0; i < retries; i++) {
    try {
      return await requestFn();
    } catch (error) {
      if (i === retries - 1 || error.code === 'NETWORK_ERROR') {
        throw error;
      }
      // Exponential backoff
      await new Promise(resolve => setTimeout(resolve, delay * Math.pow(2, i)));
    }
  }
};

// API service methods
export const apiService = {
  // GET request
  get: (url, params = {}, config = {}) => {
    return axiosInstance.get(url, { params, ...config });
  },

  // POST request
  post: (url, data = {}, config = {}) => {
    return axiosInstance.post(url, data, config);
  },

  // PUT request
  put: (url, data = {}, config = {}) => {
    return axiosInstance.put(url, data, config);
  },

  // PATCH request
  patch: (url, data = {}, config = {}) => {
    return axiosInstance.patch(url, data, config);
  },

  // DELETE request
  delete: (url, config = {}) => {
    return axiosInstance.delete(url, config);
  },

  // Upload file
  upload: (url, formData, onUploadProgress) => {
    return axiosInstance.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress,
    });
  },

  // Download file
  download: (url, params = {}) => {
    return axiosInstance.get(url, {
      params,
      responseType: 'blob',
    });
  },

  // Multiple concurrent requests
  all: axios.all,

  // Cancel token
  createCancelToken: () => {
    return axios.CancelToken.source();
  },

  // Set authentication token
  setAuthToken: (token) => {
    if (token) {
      axiosInstance.defaults.headers.Authorization = `Bearer ${token}`;
      localStorage.setItem('access_token', token);
    } else {
      delete axiosInstance.defaults.headers.Authorization;
      localStorage.removeItem('access_token');
    }
  },

  // Clear authentication
  clearAuth: () => {
    delete axiosInstance.defaults.headers.Authorization;
    clearAuthData();
  },

  // Get base URL
  getBaseURL: () => API_BASE_URL,
};

// Export axios instance for custom use
export default apiService;

// Utility functions for specific API endpoints
export const authAPI = {
  login: (credentials) => apiService.post('/auth/login', credentials),
  register: (userData) => apiService.post('/auth/register', userData),
  logout: () => apiService.post('/auth/logout'),
  verifyEmail: (token) => apiService.post('/auth/verify-email', { token }),
  forgotPassword: (email) => apiService.post('/auth/forgot-password', { email }),
  resetPassword: (data) => apiService.post('/auth/reset-password', data),
  verify2FA: (code) => apiService.post('/auth/verify-2fa', { code }),
};

export const miningAPI = {
  getMiningStats: () => apiService.get('/mining/stats'),
  startMining: (contractId) => apiService.post('/mining/start', { contract_id: contractId }),
  stopMining: () => apiService.post('/mining/stop'),
  getHashRate: () => apiService.get('/mining/hashrate'),
  getEarnings: (period = 'daily') => apiService.get(`/mining/earnings?period=${period}`),
  getContracts: () => apiService.get('/mining/contracts'),
  purchaseContract: (contractData) => apiService.post('/mining/contracts/purchase', contractData),
};

export const walletAPI = {
  getBalance: () => apiService.get('/wallet/balance'),
  getTransactions: (params) => apiService.get('/wallet/transactions', params),
  deposit: (amount, method) => apiService.post('/wallet/deposit', { amount, method }),
  withdraw: (withdrawalData) => apiService.post('/wallet/withdraw', withdrawalData),
  getDepositAddress: (currency) => apiService.get(`/wallet/deposit-address/${currency}`),
  getWithdrawalHistory: () => apiService.get('/wallet/withdrawal-history'),
};

export const mlmAPI = {
  getDownline: (level = 1) => apiService.get(`/mlm/downline?level=${level}`),
  getCommissionSummary: () => apiService.get('/mlm/commissions'),
  getBinaryTree: () => apiService.get('/mlm/binary-tree'),
  getReferralLink: () => apiService.get('/mlm/referral-link'),
  getTeamPerformance: () => apiService.get('/mlm/team-performance'),
  getPayoutSchedule: () => apiService.get('/mlm/payout-schedule'),
};

export const userAPI = {
  getProfile: () => apiService.get('/user/profile'),
  updateProfile: (data) => apiService.put('/user/profile', data),
  updateKYC: (documents) => apiService.post('/user/kyc', documents),
  getNotifications: () => apiService.get('/user/notifications'),
  markNotificationRead: (id) => apiService.patch(`/user/notifications/${id}/read`),
  getSecurityLog: () => apiService.get('/user/security-log'),
  enable2FA: () => apiService.post('/user/enable-2fa'),
  disable2FA: () => apiService.post('/user/disable-2fa'),
};

export const adminAPI = {
  getUsers: (params) => apiService.get('/admin/users', params),
  getUserDetails: (userId) => apiService.get(`/admin/users/${userId}`),
  updateUserStatus: (userId, status) => apiService.patch(`/admin/users/${userId}/status`, { status }),
  getSystemStats: () => apiService.get('/admin/system-stats'),
  getWithdrawalRequests: () => apiService.get('/admin/withdrawal-requests'),
  processWithdrawal: (requestId, action) => apiService.post(`/admin/withdrawals/${requestId}/process`, { action }),
  getCommissionReport: (period) => apiService.get(`/admin/reports/commissions?period=${period}`),
};