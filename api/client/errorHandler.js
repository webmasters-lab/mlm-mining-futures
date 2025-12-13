// src/services/errorHandler.js
import { store } from '../store';
import { logout } from '../store/slices/authSlice';
import { showToast } from '../utils/toast';
import { trackError, trackApiError } from '../utils/analytics';
import { clearAuthData } from '../utils/storage';

// Error types
export const ErrorType = {
  NETWORK: 'NETWORK_ERROR',
  TIMEOUT: 'TIMEOUT_ERROR',
  VALIDATION: 'VALIDATION_ERROR',
  AUTH: 'AUTHENTICATION_ERROR',
  PERMISSION: 'PERMISSION_ERROR',
  NOT_FOUND: 'NOT_FOUND_ERROR',
  RATE_LIMIT: 'RATE_LIMIT_ERROR',
  SERVER: 'SERVER_ERROR',
  MAINTENANCE: 'MAINTENANCE_ERROR',
  UNKNOWN: 'UNKNOWN_ERROR',
};

// Error severity levels
export const ErrorSeverity = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical',
};

// Error context types
export const ErrorContext = {
  API: 'api',
  VALIDATION: 'validation',
  AUTH: 'authentication',
  PAYMENT: 'payment',
  MINING: 'mining',
  WALLET: 'wallet',
  MLM: 'mlm',
  UI: 'ui',
};

class AppError extends Error {
  constructor(message, type = ErrorType.UNKNOWN, context = ErrorContext.API, severity = ErrorSeverity.MEDIUM, originalError = null) {
    super(message);
    this.name = 'AppError';
    this.type = type;
    this.context = context;
    this.severity = severity;
    this.timestamp = new Date().toISOString();
    this.originalError = originalError;
    
    // Capture stack trace
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Comprehensive error handler for API responses
 * @param {Error} error - The error object from axios/fetch
 * @param {Object} options - Handler options
 * @param {string} options.context - Error context
 * @param {boolean} options.showToast - Whether to show toast notification
 * @param {boolean} options.logToConsole - Whether to log to console
 * @param {boolean} options.trackAnalytics - Whether to track in analytics
 * @param {Function} options.customHandler - Custom handler function
 * @returns {AppError} - Standardized error object
 */
export const handleError = (error, options = {}) => {
  const {
    context = ErrorContext.API,
    showToast: shouldShowToast = true,
    logToConsole = process.env.NODE_ENV === 'development',
    trackAnalytics = true,
    customHandler = null,
  } = options;

  let appError;

  // Handle custom handler first
  if (customHandler && typeof customHandler === 'function') {
    const customResult = customHandler(error);
    if (customResult) {
      appError = customResult;
    }
  }

  if (!appError) {
    // Handle axios errors
    if (error.isAxiosError) {
      appError = handleAxiosError(error, context);
    }
    // Handle fetch errors
    else if (error instanceof TypeError && error.message === 'Failed to fetch') {
      appError = new AppError(
        'Network connection failed. Please check your internet connection.',
        ErrorType.NETWORK,
        context,
        ErrorSeverity.HIGH,
        error
      );
    }
    // Handle custom AppError
    else if (error instanceof AppError) {
      appError = error;
    }
    // Handle validation errors
    else if (error.name === 'ValidationError') {
      appError = handleValidationError(error, context);
    }
    // Handle unknown errors
    else {
      appError = new AppError(
        error.message || 'An unexpected error occurred',
        ErrorType.UNKNOWN,
        context,
        ErrorSeverity.MEDIUM,
        error
      );
    }
  }

  // Log to console in development
  if (logToConsole) {
    console.error('❌ Error Handler:', {
      error: appError,
      originalError: error,
      context,
      timestamp: new Date().toISOString(),
    });
  }

  // Track in analytics
  if (trackAnalytics) {
    trackError(appError);
  }

  // Show toast notification
  if (shouldShowToast && appError.shouldShowToast !== false) {
    showErrorToast(appError);
  }

  // Handle critical errors
  if (appError.severity === ErrorSeverity.CRITICAL) {
    handleCriticalError(appError);
  }

  return appError;
};

/**
 * Handle Axios-specific errors
 */
const handleAxiosError = (error, context) => {
  const { response, request, code, message } = error;

  // Network errors (no response)
  if (!response) {
    if (request) {
      if (code === 'ECONNABORTED') {
        return new AppError(
          'Request timeout. Please try again.',
          ErrorType.TIMEOUT,
          context,
          ErrorSeverity.MEDIUM,
          error
        );
      }
      return new AppError(
        'Unable to connect to server. Please check your network connection.',
        ErrorType.NETWORK,
        context,
        ErrorSeverity.HIGH,
        error
      );
    }
  }

  const { status, data } = response;
  const errorMessage = data?.message || message;

  switch (status) {
    case 400:
      return handleBadRequestError(data, context, error);
    
    case 401:
      return handleUnauthorizedError(data, context, error);
    
    case 403:
      return new AppError(
        data?.message || 'You do not have permission to access this resource.',
        ErrorType.PERMISSION,
        context,
        ErrorSeverity.HIGH,
        error
      );
    
    case 404:
      return new AppError(
        data?.message || 'The requested resource was not found.',
        ErrorType.NOT_FOUND,
        context,
        ErrorSeverity.LOW,
        error
      );
    
    case 422: // Validation error
      return handleValidationError(data, context, error);
    
    case 429:
      return new AppError(
        data?.message || 'Too many requests. Please wait before trying again.',
        ErrorType.RATE_LIMIT,
        context,
        ErrorSeverity.MEDIUM,
        error
      );
    
    case 500:
      return new AppError(
        'Internal server error. Our team has been notified.',
        ErrorType.SERVER,
        context,
        ErrorSeverity.HIGH,
        error
      );
    
    case 502:
    case 503:
    case 504:
      return new AppError(
        'Service temporarily unavailable. Please try again later.',
        ErrorType.MAINTENANCE,
        context,
        ErrorSeverity.HIGH,
        error
      );
    
    default:
      return new AppError(
        errorMessage || `Unexpected error (${status})`,
        ErrorType.UNKNOWN,
        context,
        ErrorSeverity.MEDIUM,
        error
      );
  }
};

/**
 * Handle 400 Bad Request errors
 */
const handleBadRequestError = (data, context, originalError) => {
  if (data?.errors) {
    const firstError = Object.values(data.errors)[0];
    const errorMessage = Array.isArray(firstError) ? firstError[0] : firstError;
    return new AppError(
      errorMessage || 'Invalid request data.',
      ErrorType.VALIDATION,
      context,
      ErrorSeverity.MEDIUM,
      originalError
    );
  }
  
  return new AppError(
    data?.message || 'Invalid request. Please check your input.',
    ErrorType.VALIDATION,
    context,
    ErrorSeverity.MEDIUM,
    originalError
  );
};

/**
 * Handle 401 Unauthorized errors
 */
const handleUnauthorizedError = (data, context, originalError) => {
  const message = data?.message || 'Your session has expired. Please log in again.';
  
  // Dispatch logout action if token is invalid
  setTimeout(() => {
    store.dispatch(logout());
    clearAuthData();
  }, 1000);
  
  return new AppError(
    message,
    ErrorType.AUTH,
    context,
    ErrorSeverity.HIGH,
    originalError
  );
};

/**
 * Handle validation errors (422 or custom validation)
 */
const handleValidationError = (errorData, context, originalError) => {
  let errorMessage = 'Validation failed.';
  let errors = {};
  
  if (errorData?.errors) {
    errors = errorData.errors;
    const firstError = Object.values(errors)[0];
    errorMessage = Array.isArray(firstError) ? firstError[0] : firstError;
  } else if (errorData?.message) {
    errorMessage = errorData.message;
  }
  
  return new AppError(
    errorMessage,
    ErrorType.VALIDATION,
    context,
    ErrorSeverity.MEDIUM,
    originalError
  );
};

/**
 * Show appropriate toast notification based on error
 */
const showErrorToast = (error) => {
  const { type, message, severity } = error;
  
  let toastType = 'error';
  let duration = 5000;
  
  // Adjust toast type and duration based on severity
  switch (severity) {
    case ErrorSeverity.LOW:
      toastType = 'info';
      duration = 3000;
      break;
    case ErrorSeverity.MEDIUM:
      toastType = 'warning';
      duration = 4000;
      break;
    case ErrorSeverity.HIGH:
    case ErrorSeverity.CRITICAL:
      toastType = 'error';
      duration = 6000;
      break;
  }
  
  showToast(message, toastType, duration);
};

/**
 * Handle critical errors (app-level)
 */
const handleCriticalError = (error) => {
  console.error('🚨 Critical Error:', error);
  
  // Send to error monitoring service
  if (process.env.REACT_APP_SENTRY_DSN) {
    captureException(error.originalError || error);
  }
  
  // Logout user if authentication related
  if (error.type === ErrorType.AUTH) {
    store.dispatch(logout());
    clearAuthData();
  }
  
  // Show maintenance page if server is down
  if (error.type === ErrorType.MAINTENANCE) {
    window.location.href = '/maintenance';
  }
};

/**
 * Error boundary handler for React components
 */
export const handleReactError = (error, errorInfo) => {
  const appError = new AppError(
    error.message,
    ErrorType.UNKNOWN,
    ErrorContext.UI,
    ErrorSeverity.CRITICAL,
    error
  );
  
  appError.componentStack = errorInfo.componentStack;
  
  // Track UI errors
  trackError(appError);
  
  // Log to console
  console.error('🚨 React Error Boundary:', {
    error: appError,
    componentStack: errorInfo.componentStack,
  });
  
  return appError;
};

/**
 * Error handler for specific contexts
 */
export const createErrorHandler = (context, defaultOptions = {}) => {
  return (error, options = {}) => {
    return handleError(error, {
      context,
      ...defaultOptions,
      ...options,
    });
  };
};

// Pre-configured error handlers for different contexts
export const miningErrorHandler = createErrorHandler(ErrorContext.MINING, {
  showToast: true,
});

export const walletErrorHandler = createErrorHandler(ErrorContext.WALLET, {
  showToast: true,
});

export const paymentErrorHandler = createErrorHandler(ErrorContext.PAYMENT, {
  showToast: true,
  trackAnalytics: true,
});

export const mlmErrorHandler = createErrorHandler(ErrorContext.MLM, {
  showToast: true,
});

export const authErrorHandler = createErrorHandler(ErrorContext.AUTH, {
  showToast: true,
  logToConsole: true,
});

/**
 * Utility to extract validation errors for form display
 */
export const extractValidationErrors = (error) => {
  if (error.type !== ErrorType.VALIDATION || !error.originalError?.response?.data?.errors) {
    return {};
  }
  
  return error.originalError.response.data.errors;
};

/**
 * Check if error is retryable
 */
export const isRetryableError = (error) => {
  const nonRetryableTypes = [
    ErrorType.VALIDATION,
    ErrorType.PERMISSION,
    ErrorType.NOT_FOUND,
  ];
  
  return !nonRetryableTypes.includes(error.type);
};

/**
 * Create user-friendly error messages
 */
export const getUserFriendlyMessage = (error) => {
  const { type, message } = error;
  
  switch (type) {
    case ErrorType.NETWORK:
      return 'Unable to connect. Please check your internet connection.';
    
    case ErrorType.TIMEOUT:
      return 'Request took too long. Please try again.';
    
    case ErrorType.RATE_LIMIT:
      return 'Too many requests. Please wait a moment.';
    
    case ErrorType.MAINTENANCE:
      return 'Service is temporarily unavailable for maintenance.';
    
    default:
      return message;
  }
};

// Export AppError class for custom error creation
export { AppError };

// Default export for convenience
export default {
  handleError,
  handleReactError,
  createErrorHandler,
  AppError,
  ErrorType,
  ErrorSeverity,
  ErrorContext,
  miningErrorHandler,
  walletErrorHandler,
  paymentErrorHandler,
  mlmErrorHandler,
  authErrorHandler,
  extractValidationErrors,
  isRetryableError,
  getUserFriendlyMessage,
};