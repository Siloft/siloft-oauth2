/**
 * Produces a URL query string from given object.
 *
 * @param  {object} object
 */
function queryString (object) {
  var query = ''
  if (object !== null && object !== undefined && typeof object === 'object') {
    Object.keys(object).forEach(function (key) {
      query += (query !== '' ? '&' : '') + key + '=' + object[key]
    })
  }
  return query
}

/**
 * Construct an object that can handle the OAuth 2.0 client credentials flow.
 *
 * @param {String} the url
 */
function ClientOAuth2 (url) {
  this.url = url
}

/**
 * Request an access token using the client credentials.
 *
 * @param  {Object}  [opts]
 * @return {Promise}
 */
ClientOAuth2.prototype.getToken = function (clientId, clientSecret) {
  return this._request({
    url: this.url,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + window.btoa(clientId + ":" + clientSecret)
    },
    body: {
      'grant_type': 'client_credentials'
    }
  })
  .then(function (json) {
    var expires = new Date()
    expires.setSeconds(expires.getSeconds() + json.expires_in)
    sessionStorage.setItem('expires_in', expires)
    sessionStorage.setItem('access_token', json.access_token)
    sessionStorage.setItem('token_type', json.token_type)
  })
}

/**
 * Sign a standardised request object with user authentication information.
 *
 * @param  {Object}  options
 * @return {Object}
 */
ClientOAuth2.prototype.sign = function (options) {
  options.method = options.method ? options.method : 'GET'
  options.query = options.query ? options.query : {}
  options.headers = options.headers ? options.headers : {}
  options.body = options.body ? options.body : {}

  // Sign request with access token
  var tokenType = sessionStorage.getItem('token_type')
  var accessToken = sessionStorage.getItem('access_token')
  if (tokenType && accessToken) {
    options.headers['Authorization'] = tokenType + ' ' + accessToken
  }

  return this._request(options)
}

/**
 * Check whether the token has expired.
 *
 * @return {boolean}
 */
ClientOAuth2.prototype.expired = function () {
  var expiresIn = sessionStorage.getItem('expires_in')
  var expires = new Date(expiresIn)
  return Date.now() > expires.getTime()
}

/**
 * Make a request and parse the response.
 *
 * @param  {Object}  options
 * @return {Promise}
 */
ClientOAuth2.prototype._request = function (options) {
  var url = options.url
  var body = queryString(options.body)
  var query = queryString(options.query)
  var parts = url.split('#')
  var fragment = parts[1] ? '#' + parts[1] : ''

  url = parts[0]
  if (query) {
    url += (url.indexOf('?') === -1 ? '?' : '&') + query
  }
  url += fragment

  return new Promise(function (resolve, reject) {
    var xhr = new window.XMLHttpRequest()

    xhr.open(options.method, url)

    xhr.onload = function () {
      return resolve({
        status: xhr.status,
        body: xhr.responseText
      })
    }

    xhr.onerror = xhr.onabort = function () {
      return reject(new Error(xhr.statusText || 'XHR aborted: ' + url))
    }

    Object.keys(options.headers).forEach(function (header) {
      xhr.setRequestHeader(header, options.headers[header])
    })

    xhr.send(body)
  })
  .then(function (res) {

    try {
      var body = JSON.parse(res.body)
    } finally {
      if (body) {
        if (body.error) {
          var err = new Error(body.error)
          err.status = res.status
          err.body = body
          err.code = 'EAUTH'
          return Promise.reject(err)
        }

        if (res.status < 200 || res.status >= 399) {
          var err = new Error('HTTP status ' + res.status)
          err.status = res.status
          err.body = res.body
          err.code = 'ESTATUS'
          return Promise.reject(err)
        }

        return body
      }

      var err = new Error('HTTP status ' + res.status)
      err.status = res.status
      err.body = res.body
      err.code = 'ESTATUS'
      return Promise.reject(err)
    }
  })
}