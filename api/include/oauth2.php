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

require_once 'mysql.php';
require_once 'http.php';

if (!defined('OAUTH2_TOKEN_TYPE')) define('OAUTH2_TOKEN_TYPE', 'Bearer');
if (!defined('OAUTH2_EXPIRES_IN')) define('OAUTH2_EXPIRES_IN', 3600);

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

    $user = MySQL::query("SELECT * FROM `user` WHERE `authorization` = ?", "s", hash('sha512', $authorization))[0];
    if ($user === null)
    {
      HTTP::unauthorized('invalid_client');
    }

    $accessToken = self::generate_token();
    $result = MySQL::query("INSERT INTO `token` VALUES(?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE `authorization` = ?, `host` = ?, `user_agent` = ?, `expires` = ?", "isssisssi", $user['id'], hash('sha512', OAUTH2_TOKEN_TYPE . ' ' . $accessToken), hash('sha512', self::get_host()), hash('sha512', $_SERVER['HTTP_USER_AGENT']), time() + OAUTH2_EXPIRES_IN, hash('sha512', OAUTH2_TOKEN_TYPE . ' ' . $accessToken), hash('sha512', self::get_host()), hash('sha512', $_SERVER['HTTP_USER_AGENT']), time() + OAUTH2_EXPIRES_IN);
    if ($result < 0)
    {
      HTTP::internal_server_error(MySQL::getError());
    }

    HTTP::ok([
      'access_token' => $accessToken,
      'token_type' => OAUTH2_TOKEN_TYPE,
      'expires_in' => OAUTH2_EXPIRES_IN
    ]);
  }

  public static function validate_token()
  {
    $authorization = getallheaders()['Authorization'];

    if ($authorization === null)
    {
      HTTP::bad_request('invalid_request');
    }

    $host = self::get_host();
    $token = MySQL::query("SELECT * FROM `token` WHERE `authorization` = ? AND `host` = ? AND `user_agent` = ?", "sss", hash('sha512', $authorization), hash('sha512', self::get_host()), hash('sha512', $_SERVER['HTTP_USER_AGENT']))[0];
    if ($token === null || $token['expires'] <= time())
    {
      HTTP::unauthorized('invalid_token');
    }
  }

  private static function get_host()
  {
    $ipAddress = (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '');
    $ipAddress = (isset($_SERVER['HTTP_FORWARDED']) ? $_SERVER['HTTP_FORWARDED'] : $ipAddress);
    $ipAddress = (isset($_SERVER['HTTP_FORWARDED_FOR']) ? $_SERVER['HTTP_FORWARDED_FOR'] : $ipAddress);
    $ipAddress = (isset($_SERVER['HTTP_X_FORWARDED']) ? $_SERVER['HTTP_X_FORWARDED'] : $ipAddress);
    $ipAddress = (isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $ipAddress);
    return (isset($_SERVER['HTTP_CLIENT_IP']) ? $_SERVER['HTTP_CLIENT_IP'] : $ipAddress);
  }
}