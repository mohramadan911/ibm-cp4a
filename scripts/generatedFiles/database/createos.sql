-- ************************************************************************
-- IBM FileNet Content Manager ObjectStore preparation script for SQLServer
-- ************************************************************************
-- Usage:
-- Use sqlcmd command-line tool to execute the template file using -i option and
-- user with privileges to create databases and filegroups
-- sqlcmd -S serverName\instanceName -U dbaUser -P dbaPassword -i C:\createOS1DB.sql


-- Create fnos object store database, update or remove FILENAME as per your database requirements.
-- Please make sure you change the drive and path to your MSSQL database.
CREATE DATABASE fnos
GO

USE master
GO

ALTER DATABASE fnos
ADD FILEGROUP fnosSA_DATA_FG;
GO

ALTER DATABASE fnos
ADD FILEGROUP fnosSA_IDX_FG;
GO

ALTER DATABASE fnos
ADD FILE
(
    NAME = fnos_DATA,
    FILENAME = 'E:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\fnos_DATA.mdf',
    SIZE = 400MB,
    FILEGROWTH = 128MB
)
GO

ALTER DATABASE fnos
ADD FILE
(
    NAME = fnosSA_DATA,
    FILENAME = 'E:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\fnosSA_DATA.ndf',
    SIZE = 300MB,
    FILEGROWTH = 128MB
)
TO FILEGROUP fnosSA_DATA_FG;
GO

ALTER DATABASE fnos
ADD FILE
(
    NAME = fnosSA_IDX,
    FILENAME = 'E:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\fnosSA_IDX.ndf',
    SIZE = 300MB,
    FILEGROWTH = 128MB
)
TO FILEGROUP fnosSA_IDX_FG;
GO

ALTER DATABASE fnos SET RECOVERY SIMPLE
GO

ALTER DATABASE fnos SET AUTO_CREATE_STATISTICS ON
GO

ALTER DATABASE fnos SET AUTO_UPDATE_STATISTICS ON
GO

ALTER DATABASE fnos SET READ_COMMITTED_SNAPSHOT ON
GO

-- create a SQL Server login account for the database user of each of the databases and update the master database to grant permission for XA transactions for the login account
USE master
GO
-- when using SQL authentication
CREATE LOGIN fnos WITH PASSWORD='P@ssw0rd'
-- when using Windows authentication:
-- CREATE LOGIN [domain\user] FROM WINDOWS
GO
CREATE USER fnos FOR LOGIN fnos WITH DEFAULT_SCHEMA=fnos
GO
EXEC sp_addrolemember N'SqlJDBCXAUser', N'fnos';
GO

-- Creating users and schemas for object store database
USE fnos
GO
CREATE USER fnos FOR LOGIN fnos WITH DEFAULT_SCHEMA=fnos
GO
CREATE SCHEMA fnos AUTHORIZATION fnos
GO
EXEC sp_addrolemember 'db_ddladmin', fnos;
GO
EXEC sp_addrolemember 'db_datareader', fnos;
GO
EXEC sp_addrolemember 'db_datawriter', fnos;
GO
