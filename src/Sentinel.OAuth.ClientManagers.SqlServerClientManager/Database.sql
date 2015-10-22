CREATE DATABASE Sentinel.Auth
USE Sentinel.Auth

CREATE TABLE Clients 
  (Id bigint NOT NULL PRIMARY KEY IDENTITY(1,1), 
  ClientId VARCHAR(255) NOT NULL, 
  ClientSecret VARCHAR(MAX) NOT NULL, 
  RedirectUri NVARCHAR(2083), 
  Name NVARCHAR(255) NOT NULL,
  Enabled bit, 
  LastUsed DATETIMEOFFSET, 
  Created DATETIMEOFFSET)

CREATE NONCLUSTERED INDEX NCIX_Client_Client ON Clients
	(ClientId ASC,
	Name ASC,
	Enabled ASC)
	INCLUDE (RedirectUri)