CREATE DATABASE Sentinel.Auth
USE Sentinel.Auth

CREATE TABLE AccessTokens 
  (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), 
  ClientId VARCHAR(255) NOT NULL, 
  Ticket VARCHAR(MAX) NOT NULL, 
  Token VARCHAR(MAX) NOT NULL, 
  Subject NVARCHAR(255) NOT NULL, 
  RedirectUri NVARCHAR(2083), 
  Scope NVARCHAR(MAX), 
  ValidTo DATETIME2, 
  Created DATETIME2)

CREATE TABLE RefreshTokens 
  (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), 
  ClientId VARCHAR(255) NOT NULL, 
  Token VARCHAR(MAX) NOT NULL, 
  Subject NVARCHAR(255) NOT NULL, 
  RedirectUri NVARCHAR(2083), 
  Scope NVARCHAR(MAX),
  ValidTo DATETIME2, 
  Created DATETIME2)

CREATE TABLE AuthorizationCodes 
  (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), 
  ClientId VARCHAR(255) NOT NULL, 
  Ticket VARCHAR(MAX) NOT NULL, 
  Code VARCHAR(MAX) NOT NULL, 
  Subject NVARCHAR(255) NOT NULL, 
  Scope NVARCHAR(MAX), 
  RedirectUri NVARCHAR(2083), 
  ValidTo DATETIME2, Created DATETIME2)

CREATE NONCLUSTERED INDEX NCIX_AccessToken_AccessToken ON AccessTokens
	(ClientId ASC,
	Subject ASC,
	ValidTo ASC)
	INCLUDE (RedirectUri)

CREATE NONCLUSTERED INDEX NCIX_RefreshToken_RefreshToken ON RefreshTokens
	(ClientId ASC,
	Subject ASC,
	ValidTo ASC)
	INCLUDE (RedirectUri)

CREATE NONCLUSTERED INDEX NCIX_AuthorizationCode_AuthorizationCode ON AuthorizationCodes
	(ClientId ASC,
	Subject ASC,
	ValidTo ASC)
	INCLUDE (RedirectUri)
