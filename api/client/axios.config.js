import axios from 'axios';

// Create an Axios instance
const axiosInstance = axios.create({
    baseURL: 'https://api.example.com', // Replace with your API base URL
    timeout: 10000, // Set a timeout for requests
});

// Request interceptor
axiosInstance.interceptors.request.use(config => {
    // Add authorization headers
    const token = localStorage.getItem('auth_token'); // Adjust based on where you store your token
    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
}, error => {
    return Promise.reject(error);
});

// Response interceptor
axiosInstance.interceptors.response.use(response => {
    return response;
}, async error => {
    const originalRequest = error.config;

    // If the error is due to token expiration
    if (error.response.status === 401 && !originalRequest._retry) {
        originalRequest._retry = true;
        // Refresh token logic, adjust based on your implementation
        const refreshToken = localStorage.getItem('refresh_token');
        const response = await axios.post('/auth/refresh', { token: refreshToken });
        const { token } = response.data;
        localStorage.setItem('auth_token', token); // Store new token
        axiosInstance.defaults.headers['Authorization'] = `Bearer ${token}`;
        return axiosInstance(originalRequest);
    }

    // Error handling logic
    if (error.response) {
        console.error('API error:', error.response.data);
        // Handle error based on the response
    } else {
        console.error('Network error:', error.message);
    }

    return Promise.reject(error);
});

export default axiosInstance;