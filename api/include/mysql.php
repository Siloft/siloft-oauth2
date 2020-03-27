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

if (!defined('MYSQL_HOST')) define('MYSQL_HOST', 'localhost');
if (!defined('MYSQL_PORT')) define('MYSQL_PORT', 3306);
if (!defined('MYSQL_USER')) define('MYSQL_USER', 'oauth2');
if (!defined('MYSQL_PASSWORD')) define('MYSQL_PASSWORD', 'oauth2');
if (!defined('MYSQL_DATABASE')) define('MYSQL_DATABASE', 'oauth2');

class MySQL
{
  private static $connection = null;
  private static $error = null;

  public function __construct()
  {
    if (!isset(self::$connection) || !self::$connection->ping())
    {
      self::$connection = new \mysqli(MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE, MYSQL_PORT);
    }
  }

  function __destruct()
  {
    if (isset(self::$connection))
    {
      self::$connection->close();
      self::$connection = null;
    }
  }

  public static function escape($input)
  {
    return mysqli_real_escape_string(self::$connection, $input);
  }

  public static function getError()
  {
    return self::$error;
  }

  public static function query()
  {
    self::$error = null;

    // Verify input parameters
    if (func_num_args() <= 0)
    {
      self::$error = "Failed executing database query (no parameters specified)";
      return -1;
    }

    // Get parameters
    $query = func_get_arg(0);
    $params = func_get_args();
    array_shift($params);
    $failureValue = (strpos(strtoupper($query), "SELECT") === 0 ? null : -1);

    // Check whether is connected
    if (!isset(self::$connection) || !self::$connection->ping())
    {
      self::$error = "Failed executing database query (not connected)";
      return $failureValue;
    }

    // Prepare the query statement
    $stmt = self::$connection->prepare($query);
    if ($stmt === false)
    {
      self::$error = "Failed executing database query (" . self::$connection->errno . ") " . self::$connection->error;
      return $failureValue;
    }

    // Bind parameters to the prepared query
    if (sizeof($params) > 1)
    {
      call_user_func_array(array($stmt, "bind_param"), self::refValues($params));
    }

    // Execute the prepared query
    if ($stmt->execute() === false)
    {
      self::$error = "Failed executing database query (" . self::$connection->errno . ") " . self::$connection->error;
      return $failureValue;
    }

    // Transfer the result set of the last query
    if ($stmt->store_result() === false)
    {
      self::$error = "Failed executing database query (" . self::$connection->errno . ") " . self::$connection->error;
      return $failureValue;
    }

    // Handle result, upon SELECT queries return the data
    // Upon DELETE, UPDATE, and INSERT return the affected rows
    $result = null;
    if (strpos(strtoupper($query), "SELECT") === 0)
    {
      $row = self::bindResultArray($stmt);
      $i = 0;
      while($stmt->fetch())
      {
        $result[$i] = array_map(create_function('$a', 'return $a;'), $row);
        $i++;
      }
    }
    else
    {
      $result = $stmt->affected_rows;
    }

    // Cleanup at end
    $stmt->free_result();
    $stmt->close();

    return $result;
  }

  private static function bindResultArray($stmt)
  {
    $meta = $stmt->result_metadata();
    $result = array();

    while ($field = $meta->fetch_field())
    {
      $result[$field->name] = NULL;
      $params[] = &$result[$field->name];
    }

    call_user_func_array(array($stmt, "bind_result"), $params);

    return $result;
  }

  private static function refValues($arr)
  {
    $refs = array();

    foreach ($arr as $key => $value)
    {
      $refs[$key] = &$arr[$key];
    }

    return $refs;
  }
}

$mysql = new MySQL();