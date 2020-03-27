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

class HTTP
{
  public static function ok($data)
  {
    self::send(200, 'OK', $data);
  }

  public static function bad_request($error)
  {
    self::send(400, 'Bad Request', [ 'error' => $error ]);
  }

  public static function unauthorized($error)
  {
    self::send(401, 'Unauthorized', [ 'error' => $error ]);
  }

  public static function not_found($error)
  {
    self::send(404, 'Not Found', [ 'error' => $error ]);
  }

  public static function internal_server_error($error)
  {
    self::send(500, 'Internal Server Error', [ 'error' => $error ]);
  }

  private static function send($code, $name, $data)
  {
    header("HTTP/1.1 $code $name");
    header('Content-Type: application/json; charset=UTF-8', false);
    header('Cache-Control: no-store', false);
    header('Pragma: no-cache', false);
    exit(json_encode($data));
  }
}