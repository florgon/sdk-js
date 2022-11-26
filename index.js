/*
    `florgon-auth-api`
    (Will be renamed in the future)

    Florgon API library.

    Used for working with Florgon API.

    Current SDK version:
        v0.2.10
    Expected API version: 
        v0.0.1

    Source code:
        https://github.com/florgon/sdk-js
    
    API documentation:
        https://florgon.space/dev/apis/auth
    
    Homepages:
        https://florgon.space/ 
        https://florgon.space/profile
*/

// Settings.
const AUTH_OAUTH_SCREEN_URL = "https://florgon.space/oauth/authorize";
const AUTH_API_EXPECTED_VERSION = "0.0.1";
const AUTH_API_ENDPOINT_URL = "https://api.florgon.space/v1/";
const AUTH_API_HTTP_METHOD = "GET";
const AUTH_API_DEFAULT_HEADERS = {
  "Content-Type": "application/json",
};

/*
   Public methods for end-user.
*/

// See all methods in documentation:
// https://dev.florgon.space/apis/auth

// Error codes.
const authApiErrorCode = {
  // Auth taken.
  AUTH_USERNAME_TAKEN: 0,
  AUTH_EMAIL_TAKEN: 1,

  // Auth token.
  AUTH_INVALID_TOKEN: 10,
  AUTH_EXPIRED_TOKEN: 11,

  // Auth.
  AUTH_INVALID_CREDENTIALS: 20,
  AUTH_REQUIRED: 21,
  AUTH_EMAIL_INVALID: 30,
  AUTH_PASSWORD_INVALID: 31,
  AUTH_USERNAME_INVALID: 32,
  AUTH_INSUFFICIENT_PERMISSSIONS: 33,

  // API.
  API_INVALID_REQUEST: 40,
  API_NOT_IMPLEMENTED: 41,
  API_INTERNAL_SERVER_ERROR: 42,
  API_METHOD_NOT_FOUND: 43,
  API_TOO_MANY_REQUESTS: 44,
  API_FORBIDDEN: 45,
  API_UNKNOWN_ERROR: 46,

  // Email confirmation.
  EMAIL_CONFIRMATION_TOKEN_INVALID: 50,
  EMAIL_CONFIRMATION_USER_NOT_FOUND: 51,
  EMAIL_CONFIRMATION_ALREADY_CONFIRMED: 52,

  // Oauth client.
  OAUTH_CLIENT_NOT_FOUND: 60,
  OAUTH_CLIENT_FORBIDDEN: 61,
  OAUTH_CLIENT_REDIRECT_URI_MISMATCH: 62,
  OAUTH_CLIENT_ID_MISMATCH: 63,
  OAUTH_CLIENT_SECRET_MISMATCH: 64,

  // User.
  USER_DEACTIVATED: 100,
  USER_EMAIL_NOT_CONFIRMED: 101,
  USER_NOT_FOUND: 102,
  USER_PROFILE_PRIVATE: 103,
  USER_PROFILE_AUTH_REQUIRED: 104,

  // Gifts.
  GIFT_EXPIRED: 700,
  GIFT_USED: 701,
  GIFT_CANNOT_ACCEPTED: 702,

  // 2FA OTP.
  AUTH_TFA_OTP_REQUIRED: 800,
  AUTH_TFA_OTP_INVALID: 801,
  AUTH_TFA_NOT_ENABLED: 802,
};

// Methods wrapper.
// See all methods in documentation:
// https://dev.florgon.space/apis/auth

// User.
const authMethodUserGetInfo = (accessToken) =>
  authApiRequest("user.getInfo", "", accessToken);
const authMethodUserSetInfo = (
  accessToken,
  firstName = undefined,
  lastName = undefined,
  sex = undefined,
  avatarUrl = undefined
) => {
  let params = "";
  if (firstName !== undefined) params = `first_name=${firstName}`;
  if (lastName !== undefined) params = `last_name=${lastName}`;
  if (sex !== undefined) params = `sex=${sex}`;
  if (avatarUrl !== undefined) params = `avatar_url=${avatarUrl}`;
  return authApiRequest("user.setInfo", params, accessToken);
};
const authMethodUserProfileGetInfo = (
  userId = undefined,
  username = undefined,
  accessToken = undefined
) => {
  let params = "";
  if (userId !== undefined) params = `user_id=${userId}`;
  if (username !== undefined) params = `username=${username}`;
  return authApiRequest("user.getProfileInfo", params, accessToken);
};
const authMethodUserProfileSetInfo = (accessToken) =>
  authApiRequest("user.setProfileInfo", "", accessToken);

// OAuth.
const authMethodOAuthAuthorize = (
  clientId,
  redirectUri,
  responseType,
  scope,
  state
) =>
  authApiRequest(
    "oauth.authorize",
    `client_id=${clientId}&state=${state}&redirect_uri=${redirectUri}&scope=${scope}&response_type=${responseType}`,
    ""
  );
const authMethodOAuthAccessToken = (
  code,
  clientId,
  clientSecret,
  redirectUri
) =>
  authApiRequest(
    "oauth.accessToken",
    `code=${code}&client_id=${clientId}client_secret=${clientSecret}&redirect_uri=${redirectUri}`,
    ""
  );

// Utils.
const authMethodUtilsGetServerTime = () =>
  authApiRequest("utils.getServerTime", "", "");

// Gifts.
const authMethodGiftAccept = (promocode, accessToken) =>
  authApiRequest("gift.accept", `promocode=${promocode}`, accessToken);

// OAuth client.
const authMethodOAuthClientGet = (clientId) =>
  authApiRequest("oauthClient.get", `client_id=${clientId}`, "");
const authMethodOAuthClientList = (accessToken) =>
  authApiRequest("oauthClient.list", "", accessToken);
const authMethodOAuthClientNew = (displayName, accessToken) =>
  authApiRequest("oauthClient.new", `display_name=${displayName}`, accessToken);
const authMethodOAuthClientExpireSecret = (clientId, accessToken) =>
  authApiRequest(
    "oauthClient.expireSecret",
    `client_id=${clientId}`,
    accessToken
  );
const authMethodOAuthClientEdit = (
  clientId,
  accessToken,
  displayName = "",
  displayAvatar = ""
) =>
  authApiRequest(
    "oauthClient.edit",
    `client_id=${clientId}&display_name=${displayName}&display_avatar=${displayAvatar}`,
    accessToken
  );

// Getter for OAuth authorization url.
// Use this for own redirect, or method below to direct redirect.
function authApiGetOAuthAuthorizationUrl(
  clientId,
  redirectUri,
  responseType = "token",
  scope = "",
  state = ""
) {
  return _buildRequestURL(
    "oauth.authorize",
    `client_id=${clientId}&state=${state}&redirect_uri=${redirectUri}&scope=${scope}&response_type=${responseType}`
  );
}
function authApiRedirectOAuthAuthorization(
  clientId,
  redirectUri,
  responseType = "token",
  scope = "",
  state = ""
) {
  window.location.href = authApiGetOAuthAuthorizationUrl(
    clientId,
    redirectUri,
    responseType,
    scope,
    state
  );
}
function authDirectGetOAuthAuthorizationUrl(
  clientId,
  redirectUri,
  responseType = "token",
  scope = "",
  state = ""
) {
  return `${AUTH_OAUTH_SCREEN_URL}?client_id=${clientId}&state=${state}&redirect_uri=${redirectUri}&scope=${scope}&response_type=${responseType}`;
}
function authDirectRedirectOAuthAuthorization(
  clientId,
  redirectUri,
  responseType = "token",
  scope = "",
  state = ""
) {
  window.location.href = authDirectGetOAuthAuthorizationUrl(
    clientId,
    redirectUri,
    responseType,
    scope,
    state
  );
}
function authApiRequest(method, params = "", accessToken = "") {
  /// @description Makes request to API method.
  return new Promise((resolve, reject) => {
    _apiFetch(method, params, accessToken)
      .then((httpResponse) => {
        httpResponse
          .json()
          .then((jsonResponse) => {
            _apiShowVersionWarn(jsonResponse);
            if ("success" in jsonResponse) resolve(jsonResponse, httpResponse);
            reject(jsonResponse, httpResponse);
          })
          .catch(reject);
      })
      .catch(reject);
  });
}

function authApiGetErrorMessageFromCode(code) {
  /// @description Returns translation message from code.

  // See error codes list at developer documentation.
  // https://dev.florgon.space/apis/auth

  switch (code) {
    case 0:
      return "api-error-username-taken"; // AUTH_USERNAME_TAKEN
    case 1:
      return "api-error-email-taken"; // AUTH_EMAIL_TAKEN

    case 10:
      return "api-error-invalid-token"; // AUTH_INVALID_TOKEN
    case 11:
      return "api-error-expired-token"; // AUTH_EXPIRED_TOKEN

    case 20:
      return "api-error-invalid-credentials"; // AUTH_INVALID_CREDENTIALS
    case 21:
      return "api-error-auth-required"; // AUTH_REQUIRED
    case 30:
      return "api-error-email-invalid"; // AUTH_EMAIL_INVALID
    case 31:
      return "api-error-password-invalid"; // AUTH_PASSWORD_INVALID
    case 32:
      return "api-error-username-invalid"; // AUTH_USERNAME_INVALID
    case 33:
      return "api-error-insufficient-permissions"; // AUTH_INSUFFICIENT_PERMISSSIONS

    case 40:
      return "api-error-invalid-request"; // API_INVALID_REQUEST
    case 41:
      return "api-error-not-implemented"; // API_NOT_IMPLEMENTED
    case 42:
      return "api-error-internal-server-error"; // API_INTERNAL_SERVER_ERROR
    case 43:
      return "api-error-method-not-found"; // API_METHOD_NOT_FOUND

    case 44:
      return "api-error-too-many-requests"; // API_TOO_MANY_REQUESTS
    case 45:
      return "api-error-access-denied"; // API_FORBIDDEN
    case 46:
      return "api-error-unknown-server-error"; // API_UNKNOWN_ERROR

    case 50:
      return "api-error-email-confirmation_token-invalid"; // EMAIL_CONFIRMATION_TOKEN_INVALID
    case 51:
      return "api-error-email-confirmation-user-not-found"; // EMAIL_CONFIRMATION_USER_NOT_FOUND
    case 52:
      return "api-error-email-confirmation-already-confirmed"; // EMAIL_CONFIRMATION_ALREADY_CONFIRMED

    case 60:
      return "api-error-oauth-client-not-found"; // OAUTH_CLIENT_NOT_FOUND
    case 61:
      return "api-error-oauth-client-forbidden"; // OAUTH_CLIENT_FORBIDDEN
    case 62:
      return "api-error-oauth-client-redirect-uri-mismatch"; // OAUTH_CLIENT_REDIRECT_URI_MISMATCH
    case 63:
      return "api-error-oauth-client-id-mismatch"; // OAUTH_CLIENT_ID_MISMATCH
    case 64:
      return "api-error-oauth-client-secret-mismatch"; // OAUTH_CLIENT_SECRET_MISMATCH

    case 100:
      return "api-error-user-deactivated"; // USER_DEACTIVATED
    case 101:
      return "api-error-user-email-not-confirmed"; // USER_EMAIL_NOT_CONFIRMED
    case 102:
      return "api-error-user-not-found"; // USER_NOT_FOUND
    case 103:
      return "api-error-user-profile-private"; // USER_PROFILE_PRIVATE
    case 104:
      return "api-error-user-profile-auth-required"; // USER_PROFILE_AUTH_REQUIRED

    case 700:
      return "api-error-gift-expired"; // GIFT_EXPIRED
    case 701:
      return "api-error-gift-used"; // GIFT_USED
    case 702:
      return "api-error-gift-cannot-accepted"; // GIFT_CANNOT_ACCEPTED

    case 800:
      return "api-error-tfa-otp-required"; // AUTH_TFA_OTP_REQUIRED
    case 801:
      return "api-error-tfa-otp-invalid"; // AUTH_TFA_OTP_INVALID
    case 802:
      return "api-error-tfa-not-enabled"; // AUTH_TFA_NOT_ENABLED

    default:
      return "api-error-unknown"; // Unknown error code.
  }
}

/*
    Private methods, that should not be used by end-user.
*/

function _apiFetch(apiMethod, apiParams, accessToken) {
  /// @description Returns fetch for API.
  return fetch(_buildRequestURL(apiMethod, apiParams), {
    method: AUTH_API_HTTP_METHOD,
    headers: _getHeaders((accessToken = accessToken)),
  });
}

function _apiShowVersionWarn(jsonResponse) {
  /// @description Makes API request with given handlers.
  if (jsonResponse && "v" in jsonResponse) {
    if (jsonResponse["v"] != AUTH_API_EXPECTED_VERSION) {
      console.warn(
        "[Florgon auth API] Working with unexpected API version! Expected version: " +
          AUTH_API_EXPECTED_VERSION +
          ", but got: " +
          jsonResponse["v"]
      );
    }
  }
}

function _buildRequestURL(apiMethod, apiParams) {
  /// @description Returns ready request URL for auth API.
  return AUTH_API_ENDPOINT_URL + apiMethod + "?" + apiParams;
}

function _getHeaders(accessToken) {
  /// @description Returns headers object for request.
  let headers = AUTH_API_DEFAULT_HEADERS;

  if (accessToken !== undefined && accessToken) {
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
  authDirectRedirectOAuthAuthorization,
  authDirectGetOAuthAuthorizationUrl,

  authApiRequest,

  authMethodOAuthAccessToken,
  authMethodOAuthAuthorize,
  authMethodOAuthClientEdit,
  authMethodOAuthClientExpireSecret,
  authMethodOAuthClientGet,
  authMethodOAuthClientList,
  authMethodOAuthClientNew,
  authMethodUserGetInfo,
  authMethodUserSetInfo,
  authMethodUserProfileGetInfo,
  authMethodUserProfileSetInfo,
  authMethodUtilsGetServerTime,
  authMethodGiftAccept,
};
