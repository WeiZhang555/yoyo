CREATE DATABASE yoyo_server;
USE yoyo_server;

DROP TABLE IF EXISTS users;
CREATE TABLE users(
	id INT AUTO_INCREMENT PRIMARY KEY,
	nick_name VARCHAR(20) UNIQUE,
	password VARCHAR(50),
	salt VARCHAR(50),
	email VARCHAR(50)
); 
