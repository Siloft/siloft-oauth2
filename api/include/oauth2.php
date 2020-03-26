<?php
/*
 * Copyright (c) 2020 Siloft
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 
require_once 'http.php';

class OAuth2
{
  private static function generate_token()
  {
    $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~+/';
    $token = '';
    for ($i = 0; $i < 16; $i++)
    {
      $token .= substr($chars, rand(0, strlen($chars)), 1);
    }
    return $token;
  }

  public static function get_token()
  {
    $grantType = $_POST['grant_type'];
    $authorization = getallheaders()['Authorization'];

    if ($grantType === null)
    {
      HTTP::bad_request('invalid_request');
    }
    if ($grantType !== 'client_credentials')
    {
      HTTP::bad_request('unsupported_grant_type');
    }
    if ($authorization === null)
    {
      HTTP::bad_request('invalid_request');
    }

    // TODO: validate whether the authorization matches with an user in the database
    if ($authorization !== 'Basic YWJjOjEyMw==')
    {
      HTTP::unauthorized('invalid_client');
    }

    $accessToken = self::generate_token();
    // TODO: Store in database with sha512(host) and sha512(user-agent)

    HTTP::ok([
      'access_token' => $accessToken,
      'token_type' => 'Bearer',
      'expires_in' => 3600
    ]);
  }

  public static function validate_token()
  {
    $authorization = getallheaders()['Authorization'];

    if ($authorization === null)
    {
      HTTP::bad_request('invalid_request');
    }

    // TODO: validate whether the authorization matches with a token in the database, if so also validate:
    // User-Agent hash (check if client matches with token request)
    // Host hash (check if client matches with token request)
    if ($authorization !== 'Bearer XQvRpmwIQWOkgdDV')
    {
      HTTP::unauthorized('invalid_token');
    }
  }
}