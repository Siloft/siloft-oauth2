# OAuth2

OAuth2 libaries for client and server.

## Setup

Configure MySQL database:

```sql
CREATE DATABASE oauth2;
USE oauth2;
CREATE TABLE `user` (`id` int(11) NOT NULL AUTO_INCREMENT PRIMARY KEY, `name` varchar(50) NOT NULL, `authorization` varchar(128) NOT NULL);
CREATE TABLE `token` (`id` int(11) NOT NULL PRIMARY KEY, `authorization` varchar(128) NOT NULL, `host` varchar(128) NOT NULL, `user_agent` varchar(128) NOT NULL, `expires` int(11) NOT NULL);
CREATE USER 'oauth2'@'localhost' IDENTIFIED BY 'oauth2';
GRANT ALL PRIVILEGES ON oauth2.* TO 'oauth2'@'localhost';
FLUSH PRIVILEGES;
```

## License

[OAuth2 Library](https://siloft.com/) is open-source and licensed under the [MIT License](./LICENSE.md).
