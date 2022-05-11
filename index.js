/*
    `florgon-auth-api`

    Florgon auth API library.

    Used for working with Florgon auth API.

    Current SDK version:
        v4.0.0
    Expected auth API version: 
        v1.2.3

    Source code:
        https://github.com/florgon/auth-sdk
    
    API documentation:
        https://github.com/florgon/auth-api/docs
    
    Homepages:
        https://profile.florgon.space/
        https://auth.florgon.space/
*/

// Settings.
const AUTH_API_EXPECTED_VERSION = "1.2.3";
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
    API_NOT_IMPLEMENTED: 41,

    CFT_INVALID_TOKEN: 50,
    CFT_EMAIL_NOT_FOUND:  51,
    CFT_EMAIL_ALREADY_CONFIRMED: 52,
    
    OAUTH_CLIENT_NOT_FOUND: 60,
    OAUTH_CLIENT_FORBIDDEN: 61,
}


// Methods wrapper.
// Other.
const authMethodChangelog = () => authApiRequest("changelog", "", "");
// User / token.
const authMethodVerify = (accessToken) => authApiRequest("verify", "", accessToken);
const authMethodUser = (accessToken) => authApiRequest("user", "", accessToken);
// Sign-in/up
const authMethodSignin = (login, password) => authApiRequest("signin", "login=" + login + "&password=" + password, "");
const authMethodSignup = (username, email, password) => authApiRequest("signup", "username=" + username + "&email=" + email + "&password=" + password, "");
// Email.
const authMethodEmailConfirm = (confirmationToken) => authApiRequest("email/confirm", "cft=" + confirmationToken, "");
const authMethodEmailResendConfirmation = (accessToken) => authApiRequest("email/resend_confirmation", "", accessToken);
// OAuth.
const authMethodOAuthAuthorize = (clientId, redirectUri, responseType, scope, state) => authApiRequest("oauth/authorize", `client_id=${clientId}&state=${state}&redirect_uri=${redirectUri}&scope=${scope}&response_type=${responseType}`, "");
const authMethodOAuthToken = (code) => authApiRequest("oauth/token", "code=" + code, "");
const authMethodOAuthDirect = (clientId, clientSecret, username, email, password) => authApiRequest("oauth/direct", `client_id=${clientId}&client_secret=${clientSecret}&username=${username}&email=${email}&password=${password}`, "");
// OAuth client.
const authMethodOAuthClientGet = (clientId) => authApiRequest("oauth/client/get", "client_id=" + clientId, "");
const authMethodOAuthClientNew = (displayName, accessToken) => authApiRequest("oauth/client/new", "display_name=" + displayName, accessToken);
const authMethodOAuthClientExpire = (clientId, accessToken) => authApiRequest("oauth/client/expire", "client_id=" + clientId, accessToken);

// Getter for OAuth authorization url.
// Use this for own redirect, or method below to direct redirect.
function authApiGetOAuthAuthorizationUrl(clientId, redirectUri, responseType="token", scope="", state=""){
    return _buildRequestURL("oauth/authorize", `client_id=${clientId}&state=${state}&redirect_uri=${redirectUri}&scope=${scope}&response_type=${responseType}`)
}
function authApiRedirectOAuthAuthorization(clientId, redirectUri, responseType="token", scope="", state=""){
    window.location.href = authApiGetOAuthAuthorizationUrl(clientId, redirectUri, responseType, scope, state);
}

function authApiRequest(method, params="", accessToken=""){
    /// @description Makes request to API method.
    return new Promise((resolve, reject) => {
        _apiFetch(method, params, accessToken).then((httpResponse) => {
            httpResponse.json().then((jsonResponse) => {
                _apiShowVersionWarn(jsonResponse);
                
                if ("success" in jsonResponse) resolve(jsonResponse, httpResponse);
                reject(jsonResponse, httpResponse);
            }).catch(reject);
        }).catch(reject);
    });
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
        case 41: return "auth-api-error-not-implemented" // API_NOT_IMPLEMENTED
        case 50: return "auth-api-error-cft-invalid-token" // CFT_INVALID_TOKEN
        case 51: return "auth-api-error-cft-email-not-found" // CFT_EMAIL_NOT_FOUND
        case 52: return "auth-api-error-cft-email-already-confirmed" // CFT_EMAIL_ALREADY_CONFIRMED
        case 60: return "auth-api-error-oauth-client-not-found" // OAUTH_CLIENT_NOT_FOUND
        case 61: return "auth-api-error-oauth-client-forbidden" // OAUTH_CLIENT_FORBIDDEN
        default: return "auth-api-error-unknown"; // Unknown error code.
    }
}

/*
    Private methods, that should not be used by end-user.
*/

function _apiFetch(apiMethod, apiParams, accessToken){
    /// @description Returns fetch for API.
    return fetch(_buildRequestURL(apiMethod, apiParams), {
        method: AUTH_API_HTTP_METHOD,
        headers: _getHeaders(accessToken=accessToken)
    })
}


function _apiShowVersionWarn(jsonResponse){
    /// @description Makes API request with given handlers.
    if (jsonResponse && "v" in jsonResponse){
        if (jsonResponse["v"] != AUTH_API_EXPECTED_VERSION){
            console.warn("[Florgon auth API] Working with unexpected API version! Expected version: " + AUTH_API_EXPECTED_VERSION + ", but got: " + jsonResponse["v"])
        }
    }
}

function _buildRequestURL(apiMethod, apiParams){
    /// @description Returns ready request URL for auth API.
    return AUTH_API_ENDPOINT_URL + apiMethod + "?" + apiParams;
}


function _getHeaders(accessToken){
    /// @description Returns headers object for request.
    let headers = AUTH_API_DEFAULT_HEADERS;

    if (accessToken){
        // Send authorization headers.
        headers["Authorization"] = accessToken;
    }

    return headers;
}

module.exports = {
    authApiGetErrorMessageFromCode,

    authApiErrorCode,

    authApiRedirectOAuthAuthorization,
    authApiGetOAuthAuthorizationUrl,

    authApiRequest,


    authMethodUser,
    authMethodSignin,
    authMethodSignup,
    authMethodVerify,
    authMethodChangelog,
    authMethodEmailConfirm,
    authMethodEmailResendConfirmation,

    authMethodOAuthDirect,
    authMethodOAuthAuthorize,
    authMethodOAuthToken,
    authMethodOAuthClientGet,
    authMethodOAuthClientNew,
    authMethodOAuthClientExpire,
};