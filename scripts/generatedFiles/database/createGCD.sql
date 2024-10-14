-- ****************************************************************
-- IBM FileNet Content Manager GCD preparation script for SQLServer
-- ****************************************************************
-- Usage:
-- Use sqlcmd command-line tool to execute the template file using -i option and
-- user with privileges to create databases and filegroups
-- sqlcmd -S serverName\instanceName -U dbaUser -P dbaPassword -i C:\createGCDDB.sql

-- Create Content Platform Engine GCD database, update or remove FILENAME as per your database requirements.
-- Please make sure you change the drive and path to your MSSQL database.

CREATE DATABASE fngcd
GO

USE master
GO

ALTER DATABASE fngcd
ADD FILEGROUP fngcdSA_DATA_FG;
GO

ALTER DATABASE fngcd
ADD FILEGROUP fngcdSA_IDX_FG;
GO

ALTER DATABASE fngcd
ADD FILE
(
    NAME = fngcd_DATA,
    FILENAME = 'E:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\fngcd_DATA.mdf',
    SIZE = 400MB,
    FILEGROWTH = 128MB
)
GO

ALTER DATABASE fngcd
ADD FILE
(
    NAME = fngcdSA_DATA,
    FILENAME = 'E:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\fngcdSA_DATA.ndf',
    SIZE = 300MB,
    FILEGROWTH = 128MB
)
TO FILEGROUP fngcdSA_DATA_FG;
GO

ALTER DATABASE fngcd
ADD FILE
(
    NAME = fngcdSA_IDX,
    FILENAME = 'E:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\fngcdSA_IDX.ndf',
    SIZE = 300MB,
    FILEGROWTH = 128MB
)
TO FILEGROUP fngcdSA_IDX_FG;
GO

ALTER DATABASE fngcd SET RECOVERY SIMPLE
GO

ALTER DATABASE fngcd SET AUTO_CREATE_STATISTICS ON
GO

ALTER DATABASE fngcd SET AUTO_UPDATE_STATISTICS ON
GO

ALTER DATABASE fngcd SET READ_COMMITTED_SNAPSHOT ON
GO

-- create a SQL Server login account for the database user of each of the databases and update the master database to grant permission for XA transactions for the login account
USE master
GO
-- when using SQL authentication
CREATE LOGIN fngcd WITH PASSWORD='P@ssw0rd'
-- when using Windows authentication:
-- CREATE LOGIN [domain\user] FROM WINDOWS
GO
CREATE USER fngcd FOR LOGIN fngcd WITH DEFAULT_SCHEMA=fngcd
GO
EXEC sp_addrolemember N'SqlJDBCXAUser', N'fngcd';
GO

-- Creating users and schemas for Content Platform Engine GCD database
USE fngcd
GO
CREATE USER fngcd FOR LOGIN fngcd WITH DEFAULT_SCHEMA=fngcd
GO
CREATE SCHEMA fngcd AUTHORIZATION fngcd
GO
EXEC sp_addrolemember 'db_ddladmin', fngcd;
GO
EXEC sp_addrolemember 'db_datareader', fngcd;
GO
EXEC sp_addrolemember 'db_datawriter', fngcd;
GO
