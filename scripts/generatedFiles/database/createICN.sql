-- ******************************************************
-- IBM Content Navigator preparation script for SQLServer
-- ******************************************************
-- Usage:
-- Use sqlcmd command-line tool to execute the template file using -i option and
-- user with privileges to create databases and filegroups
-- sqlcmd -S serverName\instanceName -U dbaUser -P dbaPassword -i C:\createICNDB.sql

-- create IBM CONTENT NAVIGATOR database
CREATE DATABASE fnicn
GO
ALTER DATABASE fnicn SET READ_COMMITTED_SNAPSHOT ON
GO

-- create a SQL Server login account for the database user of each of the databases and update the master database to grant permission for XA transactions for the login account
USE master
GO
-- when using SQL authentication
CREATE LOGIN fnicn WITH PASSWORD='P@ssw0rd'
-- when using Windows authentication:
-- CREATE LOGIN [domain\user] FROM WINDOWS
GO
CREATE USER fnicn FOR LOGIN fnicn WITH DEFAULT_SCHEMA=fnicn
GO
EXEC sp_addrolemember N'SqlJDBCXAUser', N'fnicn';
GO

-- Creating users and schemas for IBM CONTENT NAVIGATOR database
USE fnicn
GO
CREATE USER fnicn FOR LOGIN fnicn WITH DEFAULT_SCHEMA=ICNDB
GO
CREATE SCHEMA ICNDB AUTHORIZATION fnicn
GO
EXEC sp_addrolemember 'db_ddladmin', fnicn;
GO
EXEC sp_addrolemember 'db_datareader', fnicn;
GO
EXEC sp_addrolemember 'db_datawriter', fnicn;
GO
