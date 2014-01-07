CREATE DATABASE yoyo_server;

USE yoyo_server;

DROP TABLE IF EXISTS users;
CREATE TABLE users(
	id INT AUTO_INCREMENT PRIMARY KEY,
	username VARCHAR(20) UNIQUE NOT NULL,
	password VARCHAR(30) NOT NULL,
	salt VARCHAR(50) NOT NULL,
	email VARCHAR(50) NOT NULL,
	cert_status INT DEFAULT 0
); 