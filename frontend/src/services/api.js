import axios from 'axios';
import { API_BASE_URL, API_ENDPOINTS } from '../config/constants';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Store session token
let sessionToken = null;

export const setSessionToken = (token) => {
  sessionToken = token;
  if (token) {
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    delete api.defaults.headers.common['Authorization'];
  }
};

export const getSessionToken = () => sessionToken;

// API Functions
export const authAPI = {
  register: async (username, password, email) => {
    const response = await api.post(API_ENDPOINTS.REGISTER, {
      username,
      password,
      email:  email || username,
    });
    return response.data;
  },

  login: async (username, password) => {
    const response = await api.post(API_ENDPOINTS.LOGIN, {
      username,
      password,
    });
    if (response.data.session_token) {
      setSessionToken(response.data.session_token);
    }
    return response.data;
  },

  logout: async () => {
    try {
      await api.post(API_ENDPOINTS.LOGOUT);
    } finally {
      setSessionToken(null);
    }
  },
};

export const tripAPI = {
  createTrip: async (origin, destination) => {
    const response = await api.post(API_ENDPOINTS.CREATE_TRIP, {
      origin,
      destination,
    });
    return response.data;
  },

  getPrices: async (tripId) => {
    const response = await api.get(`${API_ENDPOINTS.GET_PRICES}/${tripId}/prices`);
    return response.data;
  },
};

export default api;