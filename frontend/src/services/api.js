import axios from 'axios';

// IMPORTANT: Replace YOUR_LOCAL_IP with your computer's IP address
// Find it by running: ipconfig (Windows) or ifconfig (Mac/Linux)
// Example: http://192.168.1.37:8000/api
const API_BASE_URL = 'http://192.168.1.37:8000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Authentication API
export const authAPI = {
  login: async (username, password) => {
    const response = await api.post('/auth/login', { username, password });
    return response.data;
  },

  register: async (username, email, password) => {
    const response = await api.post('/auth/register', {
      username,
      email,
      password,
    });
    return response.data;
  },

  logout: async () => {
    const response = await api.post('/auth/logout');
    return response. data;
  },
};

// Trip API
export const tripAPI = {
  createTrip:  async (tripData) => {
    const response = await api.post('/trips', tripData);
    return response.data;
  },

  getPrices: async (tripId) => {
    const response = await api.get(`/trips/${tripId}/prices`);
    return response.data;
  },

  getTripHistory: async () => {
    const response = await api.get('/trips/user/history');
    return response. data;
  },
};

export default api;