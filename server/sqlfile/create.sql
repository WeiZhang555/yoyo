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

DROP TABLE IF EXISTS files;
CREATE TABLE files(
	sid INT NOT NULL,
	user_from VARCHAR(50) NOT NULL,
	user_to VARCHAR(50) NOT NULL,
	fileName VARCHAR(256) NOT NULL,
	Y INT NOT NULL,
	status INT NOT NULL DEFAULT 1,	/*1 means valid, 0 means invalid*/
	deleted INT NOT NULL DEFAULT 0 /*1 means deleted from client, vise verse 0*/
);
