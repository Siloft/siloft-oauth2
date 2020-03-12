/**
 * Export `ClientOAuth2` class.
 */
module.exports = ClientOAuth2

/**
 * Default headers for executing OAuth 2.0 flows.
 */
var DEFAULT_HEADERS = {
  'Accept': 'application/json, application/x-www-form-urlencoded',
  'Content-Type': 'application/x-www-form-urlencoded'
}

/**
 * Format error response types to regular strings for displaying to clients.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.1.2.1
 */
var ERROR_RESPONSES = {
  'invalid_request': [
    'The request is missing a required parameter, includes an',
    'invalid parameter value, includes a parameter more than',
    'once, or is otherwise malformed.'
  ].join(' '),
  'invalid_client': [
    'Client authentication failed (e.g., unknown client, no',
    'client authentication included, or unsupported',
    'authentication method).'
  ].join(' '),
  'invalid_grant': [
    'The provided authorization grant (e.g., authorization',
    'code, resource owner credentials) or refresh token is',
    'invalid, expired, revoked, does not match the redirection',
    'URI used in the authorization request, or was issued to',
    'another client.'
  ].join(' '),
  'unauthorized_client': [
    'The client is not authorized to request an authorization',
    'code using this method.'
  ].join(' '),
  'unsupported_grant_type': [
    'The authorization grant type is not supported by the',
    'authorization server.'
  ].join(' '),
  'access_denied': [
    'The resource owner or authorization server denied the request.'
  ].join(' '),
  'unsupported_response_type': [
    'The authorization server does not support obtaining',
    'an authorization code using this method.'
  ].join(' '),
  'invalid_scope': [
    'The requested scope is invalid, unknown, or malformed.'
  ].join(' '),
  'server_error': [
    'The authorization server encountered an unexpected',
    'condition that prevented it from fulfilling the request.',
    '(This error code is needed because a 500 Internal Server',
    'Error HTTP status code cannot be returned to the client',
    'via an HTTP redirect.)'
  ].join(' '),
  'temporarily_unavailable': [
    'The authorization server is currently unable to handle',
    'the request due to a temporary overloading or maintenance',
    'of the server.'
  ].join(' ')
}

/**
 * Check if properties exist on an object and throw when they aren't.
 *
 * @throws {TypeError} If an expected property is missing.
 *
 * @param {Object}    obj
 * @param {...string} props
 */
function expects (obj) {
  for (var i = 1; i < arguments.length; i++) {
    var prop = arguments[i]

    if (obj[prop] == null) {
      throw new TypeError('Expected "' + prop + '" to exist')
    }
  }
}

/**
 * Pull an authentication error from the response data.
 *
 * @param  {Object} data
 * @return {string}
 */
function getAuthError (body) {
  var message = ERROR_RESPONSES[body.error] ||
    body.error_description ||
    body.error

  if (message) {
    var err = new Error(message)
    err.body = body
    err.code = 'EAUTH'
    return err
  }
}

/**
 * Create basic auth header.
 *
 * @param  {string} username
 * @param  {string} password
 * @return {string}
 */
function auth (username, password) {
  username = username == null ? '' : String(username)
  password = password == null ? '' : String(password)
  return 'Basic ' + window.btoa(username + ':' + password)
}

/**
 * Merge request options from an options object.
 */
function requestOptions (requestOptions, options) {
  return {
    url: requestOptions.url,
    method: requestOptions.method,
    body: Object.assign({}, requestOptions.body, options.body),
    query: Object.assign({}, requestOptions.query, options.query),
    headers: Object.assign({}, requestOptions.headers, options.headers)
  }
}

/*******************************************************************************
 * Client OAuth
 *******************************************************************************/

/**
 * Construct an object to handle the OAuth 2.0 Authorization Code Flow.
 *
 * @param {Object} options
 */
function ClientOAuth2 (options) {
  this.options = options
  this.code = new CodeFlow(this)
}

/**
 * Alias the token constructor.
 *
 * @type {Function}
 */
ClientOAuth2.Token = ClientOAuth2Token

/**
 * Create a new token from existing data.
 *
 * @param  {string} access
 * @param  {string} [refresh]
 * @param  {string} [type]
 * @param  {Object} [data]
 * @return {Object}
 */
ClientOAuth2.prototype.createToken = function (access, refresh, type, data) {
  var options = Object.assign(
    {},
    data,
    { access_token: access },
    { refresh_token: refresh },
    { token_type: type }
  )

  return new ClientOAuth2.Token(this, options)
}

/**
 * Make a request using `XMLHttpRequest`.
 *
 * @param   {string}  method
 * @param   {string}  url
 * @param   {string}  body
 * @param   {Object}  headers
 * @returns {Promise}
 */
ClientOAuth2.prototype._requestBrowser = function (method, url, body, headers) {
  return new Promise(function (resolve, reject) {
    var xhr = new window.XMLHttpRequest()

    xhr.open(method, url)

    xhr.onload = function () {
      return resolve({
        status: xhr.status,
        body: xhr.responseText
      })
    }

    xhr.onerror = xhr.onabort = function () {
      return reject(new Error(xhr.statusText || 'XHR aborted: ' + url))
    }

    Object.keys(headers).forEach(function (header) {
      xhr.setRequestHeader(header, headers[header])
    })

    xhr.send(body)
  })
}

/**
 * Using the built-in request method, we'll automatically attempt to parse
 * the response.
 *
 * @param  {Object}  options
 * @return {Promise}
 */
ClientOAuth2.prototype._request = function (options) {
  var url = options.url
  var body = Querystring.stringify(options.body)
  var query = Querystring.stringify(options.query)

  if (query) {
    url += (url.indexOf('?') === -1 ? '?' : '&') + query
  }

  return this._requestBrowser(options.method, url, body, options.headers)
    .then(function (res) {
      var body = JSON.parse(res.body)
      var authErr = getAuthError(body)

      if (authErr) {
        return Promise.reject(authErr)
      }

      if (res.status < 200 || res.status >= 399) {
        var statusErr = new Error('HTTP status ' + res.status)
        statusErr.status = res.status
        statusErr.body = res.body
        statusErr.code = 'ESTATUS'
        return Promise.reject(statusErr)
      }

      return body
    })
}

/*******************************************************************************
 * Client OAuth Token
 *******************************************************************************/

/**
 * General purpose client token generator.
 *
 * @param {Object} client
 * @param {Object} data
 */
function ClientOAuth2Token (client, data) {
  this.client = client
  this.data = data
  this.tokenType = data.token_type && data.token_type.toLowerCase()
  this.accessToken = data.access_token
  this.refreshToken = data.refresh_token

  this.expiresIn(Number(data.expires_in))
}

/**
 * Expire the token after some time.
 *
 * @param  {number|Date} duration Seconds from now to expire, or a date to expire on.
 * @return {Date}
 */
ClientOAuth2Token.prototype.expiresIn = function (duration) {
  if (typeof duration === 'number') {
    this.expires = new Date()
    this.expires.setSeconds(this.expires.getSeconds() + duration)
  } else if (duration instanceof Date) {
    this.expires = new Date(duration.getTime())
  } else {
    throw new TypeError('Unknown duration: ' + duration)
  }

  return this.expires
}

/**
 * Sign a standardised request object with user authentication information.
 *
 * @param  {Object} requestObject
 * @return {Object}
 */
ClientOAuth2Token.prototype.sign = function (requestObject) {
  if (!this.accessToken) {
    throw new Error('Unable to sign without access token')
  }

  requestObject.headers = requestObject.headers || {}

  if (this.tokenType === 'bearer') {
    requestObject.headers.Authorization = 'Bearer ' + this.accessToken
  } else {
    var parts = requestObject.url.split('#')
    var token = 'access_token=' + this.accessToken
    var url = parts[0].replace(/[?&]access_token=[^&#]/, '')
    var fragment = parts[1] ? '#' + parts[1] : ''

    // Prepend the correct query string parameter to the url.
    requestObject.url = url + (url.indexOf('?') > -1 ? '&' : '?') + token + fragment

    // Attempt to avoid storing the url in proxies, since the access token
    // is exposed in the query parameters.
    requestObject.headers.Pragma = 'no-store'
    requestObject.headers['Cache-Control'] = 'no-store'
  }

  return requestObject
}

/**
 * Refresh a user access token with the supplied token.
 *
 * @param  {Object}  opts
 * @return {Promise}
 */
ClientOAuth2Token.prototype.refresh = function (opts) {
  var self = this
  var options = Object.assign({}, this.client.options, opts)

  if (!this.refreshToken) {
    return Promise.reject(new Error('No refresh token'))
  }

  return this.client._request(requestOptions({
    url: options.accessTokenUri,
    method: 'POST',
    headers: Object.assign({}, DEFAULT_HEADERS, {
      Authorization: auth(options.clientId, options.clientSecret)
    }),
    body: {
      refresh_token: this.refreshToken,
      grant_type: 'refresh_token'
    }
  }, options))
    .then(function (data) {
      return self.client.createToken(Object.assign({}, self.data, data))
    })
}

/**
 * Check whether the token has expired.
 *
 * @return {boolean}
 */
ClientOAuth2Token.prototype.expired = function () {
  return Date.now() > this.expires.getTime()
}

/*******************************************************************************
 * Client OAuth Authorization Flow
 *******************************************************************************/

/**
 * Support authorization code OAuth 2.0 grant.
 *
 * Reference: http://tools.ietf.org/html/rfc6749#section-4.1
 *
 * @param {ClientOAuth2} client
 */
function CodeFlow (client) {
  this.client = client
}

/**
 * Generate the uri for doing the first redirect.
 *
 * @param  {Object} [opts]
 * @return {string}
 */
CodeFlow.prototype.getUri = function (opts) {
  var options = Object.assign({}, this.client.options, opts)

  // Check the required parameters are set.
  expects(options, 'clientId', 'authorizationUri')

  return options.authorizationUri + '?' + Querystring.stringify(Object.assign({
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    scope: options.scopes.join(' '),
    response_type: 'code',
    state: options.state
  }, options.query))
}

/**
 * Get the code token from the redirected uri and make another request for
 * the user access token.
 *
 * @param  {string|Object} uri
 * @param  {Object}        [opts]
 * @return {Promise}
 */
CodeFlow.prototype.getToken = function (uri, opts) {
  var self = this
  var options = Object.assign({}, this.client.options, opts)

  expects(options, 'clientId', 'accessTokenUri')

  var url = typeof uri === 'object' ? uri : Url.parse(uri, true)

  if (
    typeof options.redirectUri === 'string' &&
    typeof url.pathname === 'string' &&
    url.pathname !== Url.parse(options.redirectUri).pathname
  ) {
    return Promise.reject(
      new TypeError('Redirected path should match configured path, but got: ' + url.pathname)
    )
  }

  if (!url.query) {
    return Promise.reject(new TypeError('Unable to process uri: ' + uri))
  }

  var data = typeof url.query === 'string' ? Querystring.parse(url.query) : (url.query || {})
  var err = getAuthError(data)

  if (err) {
    return Promise.reject(err)
  }

  if (options.state != null && data.state !== options.state) {
    return Promise.reject(new TypeError('Invalid state: ' + data.state))
  }

  // Check whether the response code is set.
  if (!data.code) {
    return Promise.reject(new TypeError('Missing code, unable to request token'))
  }

  var headers = Object.assign({}, DEFAULT_HEADERS)
  var body = { code: data.code, grant_type: 'authorization_code', redirect_uri: options.redirectUri }

  // `client_id`: REQUIRED, if the client is not authenticating with the
  // authorization server as described in Section 3.2.1.
  // Reference: https://tools.ietf.org/html/rfc6749#section-3.2.1
  if (options.clientSecret) {
    headers.Authorization = auth(options.clientId, options.clientSecret)
  } else {
    body.client_id = options.clientId
  }

  return this.client._request(requestOptions({
    url: options.accessTokenUri,
    method: 'POST',
    headers: headers,
    body: body
  }, options))
    .then(function (data) {
      return self.client.createToken(data)
    })
}
