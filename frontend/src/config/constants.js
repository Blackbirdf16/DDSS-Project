// FairRide Configuration
export const APP_CONFIG = {
  APP_NAME: 'FairRide',
  APP_TAGLINE: 'Get a Fair Price, Every Time',
  VERSION: '1.0.0',
};

// API Configuration
export const API_CONFIG = {
  TIMEOUT: 30000, // 30 seconds
  RETRY_ATTEMPTS: 3,
};

// Supported ride-sharing providers in Spain
export const PROVIDERS = {
  UBER: {
    id: 'uber',
    name: 'Uber',
    color: '#000000',
    available: true,
  },
  CABIFY: {
    id: 'cabify',
    name: 'Cabify',
    color: '#6C1C99',
    available: true,
  },
  FREENOW: {
    id:  'freenow',
    name: 'FREE NOW',
    color: '#FFC933',
    available: true,
  },
  BOLT: {
    id: 'bolt',
    name: 'Bolt',
    color: '#34D186',
    available: true,
  },
};

// Regional Configuration - SPAIN
export const REGION_CONFIG = {
  country: 'Spain',
  countryCode: 'ES',
  currency: 'EUR',
  currencySymbol: '€',
  currencyFormat: 'after', // 10.50€
  locale: 'en-ES', // English language, Spain region
  distanceUnit: 'km', // kilometers
  timezone: 'Europe/Madrid',
  defaultCity: 'Madrid',
  majorCities: [
    'Madrid',
    'Barcelona',
    'Valencia',
    'Sevilla',
    'Zaragoza',
    'Málaga',
    'Murcia',
    'Palma',
    'Las Palmas',
    'Bilbao',
  ],
};

// Currency Formatting Helper
export const formatCurrency = (amount) => {
  const formatted = parseFloat(amount).toFixed(2);
  return `€${formatted}`; // €10.50
};

// Distance Formatting Helper
export const formatDistance = (km) => {
  return `${parseFloat(km).toFixed(1)} km`;
};

// UI Theme Colors
export const COLORS = {
  primary: '#f59e0b', // Orange
  secondary: '#0f172a', // Dark blue
  background: '#0f172a',
  cardBackground: '#1e293b',
  text: '#ffffff',
  textSecondary: '#cbd5e1',
  textMuted: '#94a3b8',
  border: '#334155',
  success: '#10b981',
  error: '#ef4444',
  warning:  '#f59e0b',
};

export default {
  APP_CONFIG,
  API_CONFIG,
  PROVIDERS,
  REGION_CONFIG,
  formatCurrency,
  formatDistance,
  COLORS,
};