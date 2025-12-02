// api/client/errorHandler.js

export const handleError = (error) => {
    // Check if the error response exists
    if (!error.response) {
        console.error('Network Error:', error);
        return 'Network error, please try again later.';
    }

    const { status } = error.response;

    switch (status) {
        case 400:
            return 'Bad Request: Please check your input.';
        case 401:
            return 'Unauthorized: Please log in again.';
        case 403:
            return 'Forbidden: You do not have permission to access this resource.';
        case 404:
            return 'Not Found: The resource you are looking for was not found.';
        case 429:
            return 'Too Many Requests: Please wait a moment before trying again.';
        case 500:
            return 'Internal Server Error: Please try again later.';
        default:
            return 'An unexpected error occurred. Please try again.';
    }
};