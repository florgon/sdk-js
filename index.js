/*
    `florgon-auth-api`

    Florgon auth API library.

    Used for working with Florgon auth API.

    Current SDK version:
        v0.2.0
    Expected auth API version: 
        v0.2.0

    Source code:
        https://github.com/florgon/auth-sdk
    
    API documentation:
        https://github.com/florgon/auth-api/docs
    
    Homepages:
        https://profile.florgon.space/
        https://auth.florgon.space/
*/

// Settings.
const AUTH_API_EXPECTED_VERSION = "0.2.0";
const AUTH_API_ENDPOINT_URL = "https://api.florgon.space/auth/v2/";
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

    EMAIL_CONFIRMATION_TOKEN_INVALID: 50,
    EMAIL_CONFIRMATION_USER_NOT_FOUND:  51,
    EMAIL_CONFIRMATION_ALREADY_CONFIRMED: 52,
    
    OAUTH_CLIENT_NOT_FOUND: 60,
    OAUTH_CLIENT_FORBIDDEN: 61,
    OAUTH_CLIENT_REDIRECT_URI_MISMATCH: 62,
    OAUTH_CLIENT_ID_MISMATCH: 63,
    OAUTH_CLIENT_SECRET_MISMATCH: 64,

    USER_DEACTIVATED: 100,
}



// Methods wrapper.
// User.
const authMethodUserGetInfo = (accessToken) => authApiRequest("user.getInfo", "", accessToken);
const authMethodUserSetInfo = (accessToken) => authApiRequest("user.setInfo", "", accessToken);
// Session.
const _authMethodSessionSignin = (login, password) => authApiRequest("_session._signin", `login=${login}&password=${password}`, "");
const _authMethodSessionSignup = (username, email, password) => authApiRequest("_session._signup", `username=${username}&email=${email}&password=${password}`, "");
const _authMethodSessionGetUserInfo = (sessionToken) => authApiRequest("_session._getUserInfo", `session_token=${sessionToken}`, "");
// Email.
const _authMethodEmailConfirmationConfirm = (confirmationToken) => authApiRequest("_emailConfirmation.confirm", `cft=${confirmationToken}`, "");
const _authMethodEmailConfirmationResend = (accessToken) => authApiRequest("_emailConfirmation.resend", "", accessToken);
// OAuth.
const authMethodOAuthAuthorize = (clientId, redirectUri, responseType, scope, state) => authApiRequest("oauth.authorize", `client_id=${clientId}&state=${state}&redirect_uri=${redirectUri}&scope=${scope}&response_type=${responseType}`, "");
const authMethodOAuthAccessToken = (code, clientId, clientSecret, redirectUri) => authApiRequest("oauth.accessToken", `code=${code}&client_id=${clientId}client_secret=${clientSecret}&redirect_uri=${redirectUri}`, "");
const _authMethodOAuthAllowClient = (sessionToken, clientId, state, redirectUri, scope, responseType) => authApiRequest("_oauth._allowClient", `client_id=${clientId}&session_token=${sessionToken}&state=${state}&redirect_uri=${redirectUri}&scope=${scope}&response_type=${responseType}`, "");

// OAuth client.
const authMethodOAuthClientGet = (clientId) => authApiRequest("oauthClient.get", `client_id=${clientId}`, "");
const authMethodOAuthClientList = (accessToken) => authApiRequest("oauthClient.list", "", accessToken);
const authMethodOAuthClientNew = (displayName, accessToken) => authApiRequest("oauthClient.new", `display_name=${displayName}`, accessToken);
const authMethodOAuthClientExpireSecret = (clientId, accessToken) => authApiRequest("oauthClient.expireSecret", `client_id=${clientId}`, accessToken);
const authMethodOAuthClientEdit = (clientId, accessToken, displayName="", displayAvatar="") => authApiRequest("oauthClient.edit", `client_id=${clientId}&display_name=${displayName}&display_avatar=${displayAvatar}`, accessToken);

// Getter for OAuth authorization url.
// Use this for own redirect, or method below to direct redirect.
function authApiGetOAuthAuthorizationUrl(clientId, redirectUri, responseType="token", scope="", state=""){
    return _buildRequestURL("oauth.authorize", `client_id=${clientId}&state=${state}&redirect_uri=${redirectUri}&scope=${scope}&response_type=${responseType}`)
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
        case 50: return "auth-api-error-email-confirmation_token-invalid" // EMAIL_CONFIRMATION_TOKEN_INVALID
        case 51: return "auth-api-error-email-confirmation-user-not-found" // EMAIL_CONFIRMATION_USER_NOT_FOUND
        case 52: return "auth-api-error-email-confirmation-already-confirmed" // EMAIL_CONFIRMATION_ALREADY_CONFIRMED
        case 60: return "auth-api-error-oauth-client-not-found" // OAUTH_CLIENT_NOT_FOUND
        case 61: return "auth-api-error-oauth-client-forbidden" // OAUTH_CLIENT_FORBIDDEN

        case 62: return "auth-api-error-oauth-client-redirect-uri-mismatch" // OAUTH_CLIENT_REDIRECT_URI_MISMATCH
        case 63: return "auth-api-error-oauth-client-id-mismatch" // OAUTH_CLIENT_ID_MISMATCH
        case 64: return "auth-api-error-oauth-client-secret-mismatch" // OAUTH_CLIENT_SECRET_MISMATCH

        case 100: return "auth-api-error-user-deactivated" // USER_DEACTIVATED
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
    authApiErrorCode,
    authApiGetErrorMessageFromCode,

    authApiRedirectOAuthAuthorization,
    authApiGetOAuthAuthorizationUrl,

    authApiRequest,

    _authMethodEmailConfirmationConfirm,
    _authMethodEmailConfirmationResend,
    _authMethodOAuthAllowClient,
    _authMethodSessionSignin,
    _authMethodSessionSignup,
    _authMethodSessionGetUserInfo,

    authMethodOAuthAccessToken,
    authMethodOAuthAuthorize,
    authMethodOAuthClientEdit,
    authMethodOAuthClientExpireSecret,
    authMethodOAuthClientGet,
    authMethodOAuthClientList,
    authMethodOAuthClientNew,
    authMethodUserGetInfo,
    authMethodUserSetInfo
};