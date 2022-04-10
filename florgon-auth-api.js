/*
    `florgon-auth-api`

    Florgon auth API library.

    Used for working with Florgon auth API.

    Current SDK version:
        v1.0.0
    Latest auth API version: 
        v1.0.1

    Source code:
        https://github.com/florgon/auth-sdk
    
    API documentation:
        https://github.com/florgon/auth-api/docs
    
    Homepages:
        https://profile.florgon.space/
        https://auth.florgon.space/
*/

// Settings.
const AUTH_API_EXPECTED_VERSION = "1.0.1";
const AUTH_API_ENDPOINT_URL = "https://api.florgon.space/auth/v1/";
const AUTH_API_HTTP_METHOD = "GET";
const AUTH_API_DEFAULT_HEADERS = {
    "Content-Type": "application/json",
};


/*
   Public methods for end-user.
*/


// See all methods in documentation:
// https://github.com/florgon/auth-api/blob/main/docs/API_METHODS.md

// Error codes.
const authApiErrorCode = {
    AUTH_USERNAME_TAKEN: 0,
    AUTH_EMAIL_TAKEN: 1,
    AUTH_INVALID_TOKEN: 10,
    AUTH_EXPIRED_TOKEN:  11,
    AUTH_INVALID_CREDENTIALS: 20,
    AUTH_REQUIRED: 21,
    AUTH_EMAIL_INVALID: 30,
    AUTH_PASSWORD_INVALID: 31,
    AUTH_USERNAME_INVALID: 32,
    API_INVALID_REQUEST: 40,
}

// Methods wrapper.
const authMethodUser = (accessToken, onSuccess=undefined, onError=undefined) => authApiRequest("user", "", accessToken, onSuccess, onError);
const authMethodSignin = (login, password, onSuccess=undefined, onError=undefined) => authApiRequest("signin", "login=" + login + "&password=" + password, onSuccess, onError);
const authMethodSignup = (username, email, password, onSuccess=undefined, onError=undefined) => authApiRequest("signup", "username=" + username + "&email=" + email + "&password=" + password, onSuccess, onError);

function authApiRequest(method, params="", accessToken="", onSuccess=undefined, onError=undefined){
    /// @description Makes request to API method.
    const onErrorHandler = function(raw, result){
        /// @description Error response handler.
        if (onError) onError(raw, result);
        if ("v" in result){
            if (result["v"] != AUTH_API_EXPECTED_VERSION){
                console.warn("[Florgon auth API] Working with unexpected API version! Expected version: " + AUTH_API_EXPECTED_VERSION + ", but got: " + result["v"])
            }
        }
    }

    const onSuccessHandler = function(raw, result){
        /// @description Success response handler.
        if (onSuccess) onSuccess(raw, result);
        if ("v" in result){
            if (result["v"] != AUTH_API_EXPECTED_VERSION){
                console.warn("[Florgon auth API] Working with unexpected API version! Expected version: " + AUTH_API_EXPECTED_VERSION + ", but got: " + result["v"])
            }
        }
    }

    // Requesting API.
    _apiRequestWrapper(method, params, onSuccessHandler, onErrorHandler, accessToken);
}


function authApiGetErrorMessageFromCode(code){
    /// @description Returns translation message from code.

    // See auth-api documentation:
    // https://github.com/florgon/auth-api/blob/main/docs/API_ERROR_CODES.md

    switch(code){
        case 0: return "auth-api-error-username-taken" // AUTH_USERNAME_TAKEN
        case 1: return "auth-api-error-email-taken" // AUTH_EMAIL_TAKEN
        case 10: return "auth-api-error-invalid-token" // AUTH_INVALID_TOKEN
        case 11: return "auth-api-error-expired-token" // AUTH_EXPIRED_TOKEN
        case 20: return "auth-api-error-invalid-credentials" // AUTH_INVALID_CREDENTIALS
        case 21: return "auth-api-error-auth-required" // AUTH_REQUIRED
        case 30: return "auth-api-error-email-invalid" // AUTH_EMAIL_INVALID
        case 31: return "auth-api-error-password-invalid" // AUTH_PASSWORD_INVALID
        case 32: return "auth-api-error-username-invalid" // AUTH_USERNAME_INVALID
        case 40: return "auth-api-error-invalid-request" // API_INVALID_REQUEST
        default: return "auth-api-error-unknown"; // Unknown error code.
    }
}


/*
    Private methods, that should not be used by end-user.
*/


function _buildRequestURL(apiMethod, apiParams){
    /// @description Returns ready request URL for auth API.
    return AUTH_API_ENDPOINT_URL + apiMethod + "?" + apiParams;
}


function _getHeaders(accessToken){
    /// @description Returns headers object for request.
    let headers = AUTH_API_DEFAULT_HEADERS;
    if (accessToken){
        headers["Authorization"] = accessToken;
    }
    return headers;
}


function _apiFetch(apiMethod, apiParams, accessToken){
    /// @description Returns fetch for API.
    return fetch(_buildRequestURL(apiMethod, apiParams), {
        method: AUTH_API_HTTP_METHOD,
        headers: _getHeaders(accessToken=accessToken)
    })
}


function _apiRequestWrapper(apiMethod, apiParams, successHandler, errorHandler, accessToken){
    /// @description Makes API request with given handlers.
    _apiFetch(apiMethod, apiParams, accessToken).then(raw_response => {
        // We got 200 OK.
        raw_response.json().then(((response) => {
            // We got valid JSON.
            if ("success" in response) return successHandler(raw_response, response);
            return errorHandler(raw_response, response);
        })).catch((error) => errorHandler(raw_response, error))
    }).catch(errorHandler);
}


export {
    authApiGetErrorMessageFromCode,

    authApiErrorCode,


    authApiRequest,


    authMethodUser,
    authMethodSignin,
    authMethodSignup
};