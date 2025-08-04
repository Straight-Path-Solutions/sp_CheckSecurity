IF OBJECT_ID('dbo.sp_CheckSecurity') IS NULL
  EXEC ('CREATE PROCEDURE dbo.sp_CheckSecurity AS RETURN 0;');
GO


ALTER PROCEDURE dbo.sp_CheckSecurity
    @ShowHighOnly BIT = 0
	, @CheckLocalAdmin BIT = 0
    , @PreferredDBOwner NVARCHAR(255) = NULL
	, @Help BIT = 0

WITH RECOMPILE
AS
SET NOCOUNT ON;

DECLARE 
    @Version VARCHAR(10) = NULL
	, @VersionDate DATETIME = NULL

SELECT
    @Version = '1.1'
    , @VersionDate = '20240530';

/*
Changes in version 1.1 include:
    Added notation of version and version date
    Added check for Ad Hoc Distributed Queries
    Added check for Database Mail XPs
    Added check for Ole Automation Procedures
    Added check for number of error log files
    Added of @PreferredDBOwner parameter
    Added default for @PreferredDBOwner is "sa" (or whatever it was renamed to) if @PreferredDBOwner is NULL
    Updated "database owner not sa" check to "database owner not preferred owner"
    Added of check for IP address
    Added of check for Database Mail XPs
    Updated vulnerability level for securityadmin members
    Updated TRUSTWORTHY database check into two checks based on owner permission level
    Updated vulnerability level of role members in master databases
    Updated check for recent for product level including recent vulnerability updates (GDRs)
    Removed requirement to create sp_CheckSecurity in the master database
    Corrected some typos here and there
*/



SET NOCOUNT ON;

/* @Help = 1 */
IF @Help = 1 BEGIN
	PRINT '
/*
    sp_CheckSecurity from https://straightpathsql.com/
    	
    This script checks your SQL Server for several dozen possible vulnerabilities
    and gives you an order list with explanations and action items.
    
    Known limitations of this version:
    - sp_CheckSecurity only works Microsoft-supported versions of SQL Server, so 
    that means SQL Server 2014 or later.
    - sp_CheckSecurity will work with SQL Server version 2012, but it will skip
    a few checks. The results should still be valid and helpful, but you should
    really considering upgrading to a newer version by now.
    - If you attempt to execute sp_CheckSecurity on SQL Server 2008 R2 or older,
    then you will only receive an output message saying this will not run on your
    version. I''m sorry. No really, I''m sorry you have to support a version of
    SQL Server that old.
    - sp_CheckSecurity is designed only for database administrators, so the user
    must be a member of the sysadmin role to complete the checks.
    - If a database name has a question mark in it, then certain checks will fail
    due to the usage of sp_MSforeachdb.
    
    Parameters:
    @ShowHighOnly        1=Only high vulnerability items will be shown
                     0=All discovered vulnerabilities(DEFAULT)
    @CheckLocalAdmin 1=Check members of local Administrators
                     0=Do NOT check members of local Administrators(DEFAULT)
    @PreferredDBOwner (This can be whatever login you prefer to have as the owner
                       of your databases. By default, it will be the sa login
                       or whatever that login was renamed.)
    

    *** WARNING FOR @CheckLocalAdmin usage ***

    If you execute sp_CheckSecurity with @CheckLocalAdmin = 1, then sp_CheckSecurity
    will attempt to read and record the members of the BUILTIN\Administrators
    group. If BUILTIN\Administrators is not currently a member of the Logins,
    then sp_CheckSecurity will proceed with the following logic.
    
    1. BEGIN an explicit transaction.
    2. Add BUILTIN\Administrators as a Login.
    3. Read and record the members of BUILTIN\Administrators.
    4. ROLLBACK the transaction, removing BUILTIN\Administrators from Logins.
    
    If you have ANY database level triggers or other fun features enabled to track 
    the addition of members to Logins then you, dear user, assume any responsibility 
    for any subsequent action from this brief addition.
    
    Please don''t say we didn''t warn you.

    *** End of WARNING FOR @CheckLocalAdmin usage ***


    MIT License
    	
    Copyright for portions of sp_CheckSecurity are held by Microsoft as part of project
    tigertoolbox and are provided under the MIT license:
    https://github.com/Microsoft/tigertoolbox
    
    Copyright for portions of sp_CheckSecurity are also held by Brent Ozar Unlimited
    as part of sp_Blitz and are provided under the MIT license:
    https://github.com/BrentOzarULTD/SQL-Server-First-Responder-Kit/
    	
    All other copyrights for sp_CheckSecurity are held by Straight Path Solutions.
    
    Copyright 2024 Straight Path IT Solutions, LLC
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

*/';
	RETURN;
	END;  

/* check that user is in the sysadmin role */
IF IS_SRVROLEMEMBER ('sysadmin') = 0 BEGIN
	PRINT '
/*
    *** Executing user is NOT in the sysadmin role ***

    sp_CheckSecurity is designed only for database administrators, so the user
    must be a member of the sysadmin role to complete the checks.

	For more information about the limitations of sp_CheckSecurity, execute
    using @Help = 1

    *** EXECUTION ABORTED ***
    	   
*/';
	RETURN;
	END; 

DECLARE 
	@SQL NVARCHAR(4000)
	, @SQLVersion NVARCHAR(128)
	, @SQLVersionMajor DECIMAL(10,2)
	, @SQLVersionMinor DECIMAL(10,2)
	, @ComputerNamePhysicalNetBIOS NVARCHAR(128)
	, @ServerZeroName SYSNAME
	, @InstanceName NVARCHAR(128)
	, @Edition NVARCHAR(128);

IF OBJECT_ID('tempdb..#Results') IS NOT NULL
	DROP TABLE #Results;

CREATE TABLE #Results (
	VulnerabilityLevel TINYINT
	, Vulnerability VARCHAR(50)
	, Issue VARCHAR(50)
	, DatabaseName NVARCHAR(255)
	, Details NVARCHAR(4000)
	, ActionStep NVARCHAR(1000)
	, ReadMoreURL XML
	);

IF OBJECT_ID('tempdb..#SQLVersions') IS NOT NULL
	DROP TABLE #SQLVersions;

CREATE TABLE #SQLVersions (
	VersionName VARCHAR(10)
	, VersionNumber DECIMAL(10,2)
	);

INSERT #SQLVersions
VALUES
	('2008', 10)
	, ('2008 R2', 10.5)
	, ('2012', 11)
	, ('2014', 12)
	, ('2016', 13)
	, ('2017', 14)
	, ('2019', 15)
	, ('2022', 16);

/* SQL Server version */
SELECT @SQLVersion = CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128));

SELECT 
	@SQLVersionMajor = SUBSTRING(@SQLVersion, 1,CHARINDEX('.', @SQLVersion) + 1 )
	, @SQLVersionMinor = PARSENAME(CONVERT(varchar(32), @SQLVersion), 2);

/* check for unsupported version */	
IF @SQLVersionMajor < 10.5 BEGIN
	PRINT '
/*
    *** Unsupported SQL Server Version ***

    sp_CheckSecurity is supported only for execution on SQL Server 2012 and later.

	For more information about the limitations of sp_CheckSecurity, execute
    using @Help = 1

    *** EXECUTION ABORTED ***
    	   
*/';
	RETURN;
	END; 

SELECT
	@ComputerNamePhysicalNetBIOS = CAST(SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS NVARCHAR(128))
	, @InstanceName = CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR(128))
	, @Edition = CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128));


SELECT @ServerZeroName = [name]
FROM sys.servers
WHERE server_id = 0


/* name and version check */
INSERT #Results
SELECT 
	0
	, 'Information only'
	, ' SQL Server name and version'
	, NULL
	, COALESCE(@ComputerNamePhysicalNetBIOS,'')
	+ '\' + COALESCE(@InstanceName, '(default instance)')
	+ ', SQL Server ' + VersionName +  ' ' + @Edition
	, '(Information captured on ' + CONVERT(VARCHAR(100), GETDATE(), 101) + ' using version ' + @Version + ')'
	, ''
FROM #SQLVersions
WHERE VersionNumber = @SQLVersionMajor;


/* IP address */
INSERT #Results
SELECT 
	0
	, 'Information only'
	, 'SQL Server IP address'
	, NULL
	, 'The IP address for this SQL Server instance is ' + COALESCE(CONVERT(VARCHAR(15), CONNECTIONPROPERTY('local_net_address')), 'UNKNOWN')
	, 'Check to make sure is not an externally-facing server and this IP address cannot be reached outside your network.'
	, 'https://straightpathsql.com/cs/ip-address'


/* remote admin connections */
INSERT #Results
SELECT 
	0
	, 'Information only'
	, 'Remote admin connections'
	, NULL
	, 'Remote admin connections are currently ' 
	+  CASE value_in_use
		WHEN 1 THEN 'ENABLED.'
		ELSE 'DISABLED.'
		END
	, 'We recommend ''remote admin connections'' be ENABLED as a troubleshoting option for sysadmin role members.'
	, 'https://straightpathsql.com/cs/remote-admin-connections'
FROM sys.configurations
WHERE [name] = 'remote admin connections'


/* Database Mail XPs */
INSERT #Results
SELECT 
	0
	, 'Information only'
	, 'Database Mail XPs'
	, NULL
	, 'Database Mail XPs are currently ' 
	+  CASE value_in_use
		WHEN 1 THEN 'ENABLED.'
		ELSE 'DISABLED.'
		END
	, 'Enabling Database Mail XPs can be useful, but be aware if your instance is breached they could be used to initiate a Denial Of Service attack.'
	, 'https://straightpathsql.com/cs/database-mail-xps'
FROM sys.configurations
WHERE [name] = 'Database Mail XPs'




/* check for supported versions */
IF SERVERPROPERTY('EngineEdition') <> 8 /* Azure Managed Instances */ BEGIN
	IF @SQLVersionMajor < 12
	INSERT #Results
	SELECT 
		1
		, 'High - action required'
		, '*Unsupported version of SQL Server'
		, NULL
		, 'SQL Server ' +  VersionName + ' is no longer supported, so there will be no future security updates.'
		, 'Upgrade to SQL Server 2014 or higher.'
	    , 'https://straightpathsql.com/cs/unsupported-versions'
	FROM #SQLVersions
	WHERE VersionNumber = @SQLVersionMajor
	END

	
/* check for security update */
IF SERVERPROPERTY('EngineEdition') <> 8 /* Azure Managed Instances */ BEGIN
	IF (@SQLVersionMajor = 10 AND @SQLVersionMinor < 6814) OR
		(@SQLVersionMajor = 10.5 AND @SQLVersionMinor < 6785) OR
		(@SQLVersionMajor = 11 AND @SQLVersionMinor < 7512) OR
		(@SQLVersionMajor = 12 AND @SQLVersionMinor < 6449) OR
		(@SQLVersionMajor = 13 AND @SQLVersionMinor < 6435) OR
		(@SQLVersionMajor = 14 AND @SQLVersionMinor < 3465) OR
		(@SQLVersionMajor = 15 AND @SQLVersionMinor < 4360) OR
		(@SQLVersionMajor = 16 AND @SQLVersionMinor < 4120) 
	INSERT #Results
	SELECT 
		1
		, 'High - action required'
		, '*Security update available'
		, NULL
		, 'There is a security update available for SQL Server ' +  VersionName + '.'
		, 'Apply the most recent cumulative update or GDR for SQL Server ' +  VersionName + '.' 
	    , 'https://straightpathsql.com/cs/security-update'
	FROM #SQLVersions
	WHERE VersionNumber = @SQLVersionMajor
	END


/* check for encrypted databases */
INSERT #Results
SELECT
	0
	, 'Information only'
	, 'Encrypted database' 
	, NULL 
	, 'This instance has ' + CONVERT(VARCHAR(10), COUNT(database_id)) + ' encrypted databases using ' + key_algorithm + ' ' + CONVERT(VARCHAR(5), key_length) + '.'
	, 'Having encrypted databases is good, but make sure you have backed up your encryption keys to a secure location.'
    , 'https://straightpathsql.com/cs/encrypted-databases'
FROM sys.dm_database_encryption_keys
WHERE database_id > 4
GROUP BY 
	key_algorithm
	, key_length;


/* check for unencrypted databases */
INSERT #Results
SELECT
	0
	, 'Information only'
	, 'Unencrypted database'
	, NULL
	, 'This instance has ' + CONVERT(VARCHAR(10), COUNT(database_id)) + ' unencrypted databases.' 
	, 'Having unencrypted databases isn''t necessarily bad, but make sure you don''t need to have these user databases encrypted.'
    , 'https://straightpathsql.com/cs/unencrypted-databases'
FROM sys.databases d
WHERE database_id > 4
	AND NOT EXISTS (SELECT 1 from sys.dm_database_encryption_keys dek where d.database_id = dek.database_id);


/***** Login settings *****/

/* sa is enabled */
INSERT #Results
SELECT 
	1
	, 'High - action required'
	, 'Enabled sa account'
	, NULL
	, 'The sa account is enabled for connections. Hackers commonly use the [sa] account for malicious activity since it in the [sysadmin] role.'
	, 'Disable the sa account. Disabling only prevents sa from being used as a login for connections, as it can still own databases, jobs, etc.'
	, 'https://straightpathsql.com/cs/sa-login-enabled'
FROM sys.sql_logins
WHERE sid = 0x01
AND is_disabled = 0


/* local Administrators group members */
DECLARE @LocalAdmin TABLE (
	AccountName VARCHAR(1000)
	, AccountType VARCHAR(8)
	, AccountPrivilege VARCHAR(9)
	, MappedLoginName VARCHAR(1000)
	, PermissionPath VARCHAR(1000)
	);
 
 IF @CheckLocalAdmin = 1 BEGIN
	BEGIN TRAN
		IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE [name] = 'BUILTIN\Administrators')
			CREATE LOGIN [BUILTIN\Administrators] FROM WINDOWS WITH DEFAULT_DATABASE=[master];
 
		INSERT @LocalAdmin (AccountName, AccountType, AccountPrivilege, MappedLoginName, PermissionPath)
		EXEC xp_logininfo 'BUILTIN\Administrators', 'members'
 
		ROLLBACK

	INSERT #Results 
	SELECT  
		2
		, 'High - review required'
		, 'local Administrators'
		, NULL
		, 'The ' + AccountType + ' ' + AccountName + ' is in the local Administrator group. They can add themselves to the sysadmin role and then do anything in SQL Server, including dropping databases or changing other permissions.' 
		, 'Review all users and groups in the local Administrators group to verify they require these elevated permissions.' 
	    , 'https://straightpathsql.com/cs/local-administrators'
	FROM @LocalAdmin
	END


/* sysadmin members */
INSERT #Results
SELECT  
	2
	, 'High - review required'
	, 'sysadmin role members'
	, NULL
	, 'Login [' + l.name + '] is a sysadmin. They can do anything in SQL Server, including dropping databases or changing other permissions.' 
	, 'Review the list of logins and groups in the sysadmin role to verify the require for these elevated permissions.'
	, 'https://straightpathsql.com/cs/sysadmin'
FROM master.sys.syslogins l
WHERE l.sysadmin = 1
AND l.name <> SUSER_SNAME(0x01)
AND l.denylogin = 0
AND l.name NOT LIKE 'NT SERVICE\%'
AND l.name <> 'l_certSignSmDetach'; /* Added in SQL 2016 */


/* securityadmin members */
INSERT #Results
SELECT  
	2
	, 'High - review required'
	, 'Security Admins'  
	, NULL
	, 'Login [' + l.name + '] is a security admin. They can create other logins that do anything in SQL Server, including dropping databases or changing other permissions.' 
	, 'Review the list of logins and groups in the securityadmin role to verify the require for these elevated permissions.'
	, 'https://straightpathsql.com/cs/securityadmin'
FROM master.sys.syslogins l
WHERE l.securityadmin = 1
AND l.name <> SUSER_SNAME(0x01)
AND l.denylogin = 0;


/* CONTROL SERVER permissions */
INSERT #Results
SELECT  
	2
	, 'High - review required'
	,'Login Can Control Server' 
	, NULL
	, 'Login [' + pri.[name]+ '] has the CONTROL SERVER permission. They can do  anything in SQL Server, including dropping databases or changing permissions.'
	, 'Review the list of logins and groups with CONTROL SERVER permission to verify the require for these elevated permissions.'
	, 'https://straightpathsql.com/cs/control-server'
FROM sys.server_principals AS pri
WHERE pri.[principal_id] IN (
	SELECT p.[grantee_principal_id]
	FROM sys.server_permissions AS p
	WHERE p.[state] IN ( 'G', 'W' )
	AND p.[class] = 100
	AND p.[type] = 'CL' )
    AND pri.[name] NOT LIKE '##%##';


/* check for invalid Windows logins */
IF(OBJECT_ID('tempdb..#InvalidLogins') IS NOT NULL)
	BEGIN
		
	EXEC sp_executesql N'DROP TABLE #InvalidLogins;';
	
	END;
	
CREATE TABLE #InvalidLogins (
	LoginSID VARBINARY(85)
	, LoginName VARCHAR(256)
	);

INSERT INTO #InvalidLogins
EXEC sp_validatelogins;
                        
INSERT #Results
SELECT
	4
	, 'Low - action recommended'
	, 'Invalid login with Windows Authentication'
	, NULL
	, QUOTENAME(LoginName) + 'Is an invalid Windows user or group that is mapped to a SQL Server principal.'
	, 'Verify in the account no longer exists and carefully remove all SQL Server permissions.'
	, 'https://straightpathsql.com/cs/invalid-windows-login'
FROM #InvalidLogins
;


/* blank passwords */
INSERT #Results
SELECT --name,type_desc,create_date,modify_date,password_hash
	1
	, 'High - action required'
	, 'Password blank'
	, NULL
	, 'Login [' + name + '] has a blank password.'
	, 'Change the password to something more secure. Logins with blank passwords are the easy to hack.'
	, 'https://straightpathsql.com/cs/password-vulnerabilities'
FROM sys.sql_logins
WHERE PWDCOMPARE('',password_hash)=1;


/* password same as login */
INSERT #Results
SELECT --name,type_desc,create_date,modify_date,password_hash
	1
	, 'High - action required'
	,'Password is same as login'
	, NULL
	, 'Login [' + name + '] has a password that is the same as the login.'
	, 'Change the password to something more secure. Logins with matching passwords are easy to hack.'
	, 'https://straightpathsql.com/cs/password-vulnerabilities'
FROM sys.sql_logins
WHERE PWDCOMPARE(name,password_hash)=1;


/* passwords is password */
INSERT #Results
SELECT --name,type_desc,create_date,modify_date,password_hash
	1
	, 'High - action required'
	, 'Password is password'
	, NULL
	, 'Login [' + name + '] has a password that is the word "password".'
	, 'Change the password to this login to something more secure.'
	, 'https://straightpathsql.com/cs/password-vulnerabilities'
FROM sys.sql_logins
WHERE PWDCOMPARE('password',password_hash)=1;



/***** Instance settings *****/


/* CLR enabled */
INSERT #Results
SELECT  
	2
	, 'High - review required'
	, 'clr enabled'  
	, NULL
	, 'Having the ''clr enabled'' setting enabled allows for the execution of assemblies in the context of the SQL Server account.' 
	, CASE
		WHEN @SQLVersionMajor >= 14 THEN 'Starting with SQL Server 2017, use the configuration option ''clr strict security'' instead of ''clr enabled''.'
		ELSE 'A CLR assembly created with PERMISSION_SET = SAFE may be able to access external system resources, call unmanaged code, and acquire sysadmin privileges.' 
		END
    , 'https://straightpathsql.com/cs/clr-enabled'
FROM master.sys.configurations
WHERE [name] = 'clr enabled'
AND value_in_use = 1;


/* xp_cmdshell enabled */
INSERT #Results
SELECT  
	3
	, 'Potential - review recommended'
	, 'xp_cmdshell enabled'  
	, NULL
	, 'xp_cmdshell allows for the execution of operating system commands in the context of the SQL Server account by members of the sysadmin role.' 
	, 'If you do not have any code requiring xp_cmdshell, disable this configuration option.'
    , 'https://straightpathsql.com/cs/xp-cmdshell'
FROM master.sys.configurations
WHERE [name] = 'xp_cmdshell'
AND value_in_use = 1;


/* Ole Automation Procedures enabled */
INSERT #Results
SELECT  
	3
	, 'Potential - review recommended'
	, 'Ole Automation Procedures enabled'  
	, NULL
	, 'The ''Ole Automation Procedures'' configuration allows a call to create and execute functions in the context of SQL Server.' 
	, 'If you do not have any code requiring OLE Automation objects, disable this configuration option.'
    , 'https://straightpathsql.com/cs/ole-automation-procedures'
FROM master.sys.configurations
WHERE [name] = 'Ole Automation Procedures'
AND value_in_use = 1;


/* cross-database ownership chaining */
INSERT #Results
SELECT  
	2
	, 'High - review required'
	, 'Cross-database ownership chaining'  
	, NULL
	, 'Cross-database ownership chaining allows database owners and members of the db_ddladmin and db_owners database roles to create objects that are owned by other users.' 
	, 'Since enabling this setting allows certain users to create objects can potentially target objects in other databases, this configuration option should be enabled only at the database level.'
    , 'https://straightpathsql.com/cs/cross-db-ownership-chaining'
FROM master.sys.configurations
WHERE [name] = 'cross db ownership chaining'
AND value_in_use = 1;


/* ad hoc distributed queries */
INSERT #Results
SELECT 
	3
	, 'Potential - review recommended'
	, 'Ad Hoc Distributed Queries is enabled.'
	, NULL
	, 'Ad hoc distributed queries use the OPENROWSET and OPENDATASOURCE functions to connect to remote data sources that use OLE DB.' 
	, 'If a malicious user was able to utilize SQL injection, having this option enabled would allow them to read data files of their choosing.'
	, 'https://straightpathsql.com/cs/ad-hoc-distributed-queries'
FROM sys.configurations 
WHERE [name] = 'Ad Hoc Distributed Queries'
AND value_in_use = 1;


/* jobs owned by users */
INSERT #Results
SELECT
	3
	, 'Potential - review recommended'
	, 'SQL Agent jobs owned by users' 
	, NULL
	, 'Job [' + j.name + '] is owned by [' + SUSER_SNAME(j.owner_sid) + ']. If their login is disabled or not available due to Active Directory problems, the job will stop working.' 
	, 'Verify this login is the correct owner for the job. If possible, see if the job can be owned by sa.'
    , 'https://straightpathsql.com/cs/jobs-owned-by-users'
FROM msdb.dbo.sysjobs j
WHERE j.enabled = 1
AND SUSER_SNAME(j.owner_sid) <> SUSER_SNAME(0x01)
AND SUSER_SNAME(j.owner_sid) not like '##%';


/* stored procedures that run at startup */
INSERT #Results
SELECT
	3
	, 'Potential - review recommended'
	, 'Stored procedure run at Startup' 
	, NULL
	, 'Stored procedure [master].[' + r.SPECIFIC_SCHEMA + '].[' + r.SPECIFIC_NAME + '] runs automatically when SQL Server starts up.'
	, 'Verify you and your team know exactly what this stored procedure is doing, because if not then it could pose a security risk.' 
    , 'https://straightpathsql.com/cs/startup-stored-procedures'
FROM master.INFORMATION_SCHEMA.ROUTINES r
WHERE OBJECTPROPERTY(OBJECT_ID(ROUTINE_NAME), 'ExecIsStartup') = 1;


/* jobs that run at startup */
INSERT #Results
SELECT
	3
	, 'Potential - review recommended'
	, 'SQL Agent jobs set to run at Startup'  
	, NULL
	, 'Job [' + j.name + '] runs automatically when SQL Server Agent starts up.'
	, 'Verify you and your team know exactly what this job is doing, because it could pose a security risk.' 
    , 'https://straightpathsql.com/cs/startup-jobs'
FROM msdb.dbo.sysschedules s
JOIN msdb.dbo.sysjobschedules js ON s.schedule_id = js.schedule_id
JOIN msdb.dbo.sysjobs j ON js.job_id = j.job_id
WHERE s.freq_type = 64
	AND s.enabled = 1
	AND j.enabled = 1;


/* check for TDE certificate backup */
INSERT #Results
SELECT
	1
	, 'High - action required'
	, 'TDE certificate never backed up'
	, db_name(d.database_id)
	, 'The certificate ' + c.name + ' used to encrypt database ' + db_name(d.database_id) + ' has never been backed up'
	, 'Make a backup of your current certificate and store it in a secure location in case you need to restore this encrypted database.'
	, 'https://straightpathsql.com/cs/tde-certificate-no-backup'
FROM sys.certificates c 
INNER JOIN sys.dm_database_encryption_keys d 
	ON c.thumbprint = d.encryptor_thumbprint
WHERE c.pvt_key_last_backup_date IS NULL;

INSERT #Results
SELECT
	3
	, 'Potential - review recommended'
	, 'TDE certificate not backed up recently'
	, db_name(d.database_id)
	, 'The certificate ' + c.name + ' used to encrypt database ' + db_name(d.database_id) + ' has not been backed up since: ' + CAST(c.pvt_key_last_backup_date AS VARCHAR(100))
	, 'Make sure you have a recent backup of your certificate in a secure location in case you need to restore your encrypted database.'
	, 'https://straightpathsql.com/cs/tde-certificate-no-backup'
FROM sys.certificates c 
INNER JOIN sys.dm_database_encryption_keys d 
	ON c.thumbprint = d.encryptor_thumbprint
WHERE c.pvt_key_last_backup_date <= DATEADD(dd, -90, GETDATE());


/* check TDE certificate expiration dates */
INSERT #Results
SELECT
	3
	, 'Potential - review recommended'
	, 'TDE certificate set to expire'
	, db_name(d.database_id)
	, 'The certificate ' + c.name + ' used to encrypt database ' + db_name(d.database_id) + ' is set to expire on: ' + CAST(c.expiry_date AS VARCHAR(100))
	, 'Although you will still be able to backup or restore your encrypted database with an expired certificate, these should be changed regularly like passwords.'
	, 'https://straightpathsql.com/cs/tde-certificate-expiring'
FROM sys.certificates c 
INNER JOIN sys.dm_database_encryption_keys d 
	ON c.thumbprint = d.encryptor_thumbprint;


/* check for database backup certificate backup */
IF @SQLVersionMajor >= 12 BEGIN
	SET @SQL = '
	SELECT DISTINCT
		1
		, ''High - action required''
		, ''Database backup certificate never been backed up.''
		, b.[database_name]
		, ''The certificate '' + c.name + '' used to encrypt database backups for '' + b.[database_name] + '' has never been backed up.''
		, ''Make sure you have a recent backup of your certificate in a secure location in case you need to restore encrypted database backups.''
		, ''https://straightpathsql.com/cs/database-backup-certificate-no-backup''
	FROM sys.certificates c 
	INNER JOIN msdb.dbo.backupset b
		ON c.thumbprint = b.encryptor_thumbprint
	WHERE c.pvt_key_last_backup_date IS NULL';

	INSERT #Results
	EXEC sp_MSforeachdb @SQL


	SET @SQL = '
	SELECT DISTINCT
		1
		, ''High - action required''
		, ''Database backup certificate not backed up recently.''
		, b.[database_name]
		, ''The certificate '' + c.name + '' used to encrypt database backups for '' + b.[database_name] + '' has not been backed up since: '' + CAST(c.pvt_key_last_backup_date AS VARCHAR(100))
		, ''Make sure you have a recent backup of your certificate in a secure location in case you need to restore encrypted database backups.''
		, ''https://straightpathsql.com/cs/database-backup-certificate-no-backup''
	FROM sys.certificates c 
	INNER JOIN msdb.dbo.backupset b
		ON c.thumbprint = b.encryptor_thumbprint
	WHERE c.pvt_key_last_backup_date <= DATEADD(dd, -90, GETDATE());';

	INSERT #Results
	EXEC sp_MSforeachdb @SQL


/* check for database backup certificate expiration dates */
	SET @SQL = '
	SELECT DISTINCT
		1
		, ''High - action required''
		, ''Database backup certificate set to expire.''
		, b.[database_name]
		, ''The certificate '' + c.name + '' used to encrypt database '' + b.[database_name] + '' is set to expire on: '' + CAST(c.expiry_date AS VARCHAR(100))
		, ''You will not be able to backup or restore your encrypted database backups with an expired certificate, so these should be changed regularly like passwords.''
		, ''https://straightpathsql.com/cs/database-backup-expire''
	FROM sys.certificates c 
	INNER JOIN msdb.dbo.backupset b
		ON c.thumbprint = b.encryptor_thumbprint';

	INSERT #Results
	EXEC sp_MSforeachdb @SQL


	END

/* linked server check */
INSERT #Results
SELECT
	1
	, 'High - action required'
	, 'Linked Server configured with sa'
	, NULL
	, COALESCE(s.data_source, s.provider) + ' is configured as a linked server using sa, which allows any user to perform any action on the linked server.'
	, 'Change the security configuration of the linked server to use a more secure context.'
    , 'https://straightpathsql.com/cs/linked-server'
FROM sys.servers s
INNER JOIN sys.linked_logins l
 ON s.server_id = l.server_id
WHERE s.is_linked = 1
 AND l.remote_name = 'sa';

INSERT #Results
SELECT
	3
	, 'Potential - review recommended'
	, 'Linked Server' 
	, NULL
	, COALESCE(s.data_source, s.provider) + ' is configured as a linked server using the login ' +l.remote_name + '.'
	, 'Check the security configuration to make sure this login is not in the sysadmin role, which would allow any user to perform any action on the linked server.'
    , 'https://straightpathsql.com/cs/linked-server'
FROM sys.servers s
INNER JOIN sys.linked_logins l
 ON s.server_id = l.server_id
WHERE s.is_linked = 1
 AND l.remote_name IS NOT NULL
 AND l.remote_name <> 'sa';

INSERT #Results
SELECT
	3
	, 'Potential - review recommended'
	, 'Linked Server' 
	, NULL
	, COALESCE(s.data_source, s.provider) + ' is configured as a linked server with an unknown security context.'
	, 'Check the security configuration to make sure it isn''t connecting with a login that is in the sysadmin role, which would allow any user to perform any action on the linked server.'
    , 'https://straightpathsql.com/cs/linked-server'
FROM sys.servers s
INNER JOIN sys.linked_logins l
 ON s.server_id = l.server_id
WHERE s.is_linked = 1
 AND l.remote_name IS NULL;

 
/* endpoint check */
INSERT #Results
SELECT
	3
	, 'Potential - review recommended'
	, 'Endpoints owned by users' 
	, NULL
	, 'Endpoint ' + ep.[name] + ' is owned by ' + SUSER_NAME(ep.principal_id) + '. If the endpoint owner login is disabled or not available due to Active Directory problems, then high availability will stop working.'
	, 'Verify this is the correct owner of this endpoint, and if it is not then assign ownership to sa.'
    , 'https://straightpathsql.com/cs/endpoints-owned-by-users'
FROM sys.database_mirroring_endpoints ep
LEFT OUTER JOIN sys.dm_server_services s
 ON SUSER_NAME(ep.principal_id) = s.service_account
WHERE s.service_account IS NULL AND ep.principal_id <> 1;


/* check for audits */
INSERT #Results
SELECT
	3
	, 'Potential - review recommended'
	, 'SQL Server Audit running'
	, NULL
	, [name] + ' is a SQL Server Audit that is currently running.'
	, 'Verify this audit needs to be running, and if so any output files are in a secure directory.'
    , 'https://straightpathsql.com/cs/sql-server-audits'
FROM sys.dm_server_audit_status
WHERE status = 1
AND [name] NOT LIKE '%SQLBeacon%' /* for SQL Beacon */


/* database owner is not sa */
IF @PreferredDBOwner IS NULL
    SET @PreferredDBOwner = SUSER_SNAME(0x01);

INSERT #Results
SELECT
	4
	, 'Low - action recommended'
	, 'Database owner is not preferred owner'
	, [name]
	, 'The database ' + [name]
		+ ' is owned by ' + SUSER_SNAME(owner_sid) 
	, 'Verify this is the correct owner, because if this login is disabled or not available due to Active Directory problems then database accessability could be affected.'
    , 'https://straightpathsql.com/cs/database-owner-is-not-preferred-owner'
FROM sys.databases
WHERE (((SUSER_SNAME(owner_sid) <> SUSER_SNAME(0x01)) AND (name IN (N'master', N'model', N'msdb', N'tempdb')))
OR ((SUSER_SNAME(owner_sid) <> @PreferredDBOwner) AND (name NOT IN (N'master', N'model', N'msdb', N'tempdb'))))


/* database owner is unknown */
INSERT #Results
SELECT
	4
	, 'Low - action recommended'
	,  'Database Owner is Unknown'  
	, [name]
	, ( 'Database name: ' + [name] + '   '
		+ 'Owner name: ' + ISNULL(SUSER_SNAME(owner_sid),'~~ UNKNOWN ~~') ) AS Details
	, 'Assign an owner to this database, preferably sa if possible.'
    , 'https://straightpathsql.com/cs/database-owner-blank'
FROM sys.databases
WHERE SUSER_SNAME(owner_sid) is NULL



/* SQL Server service account */
INSERT #Results
SELECT 
	0
	, 'Information only'
	, 'Service account for SQL Server'
	, NULL
	, 'The SQL Server service is running with the account: ' + service_account
	, 'We recommend using managed service accounts if possible to reduce vulnerabilty.'
    , 'https://straightpathsql.com/cs/sql-server-service-account'
FROM sys.dm_server_services 
WHERE servicename like 'SQL Server (%'


/* SQL Agent service account */
INSERT #Results
SELECT
	0
	, 'Information only'
	, 'Service Account for SQL Agent'
	, NULL
	, 'The SQL Agent service is running with the account: ' + service_account
	, 'We recommend using managed service accounts if possible to reduce vulnerabilty.'
    , 'https://straightpathsql.com/cs/sql-server-service-account'
FROM sys.dm_server_services 
WHERE servicename like 'SQL Server Agent%'


/* Communication protocol */
INSERT #Results
SELECT 
	0
	, 'Information only'
	, 'Communication protocol'
	, NULL
	, 'The instance is using the ' + CONVERT(VARCHAR(20),CONNECTIONPROPERTY('net_transport')) + ' communication protocol' + CASE
		WHEN CONVERT(VARCHAR(10),CONNECTIONPROPERTY('net_transport')) = 'TCP' THEN ' on port ' + CONVERT(VARCHAR(10),CONNECTIONPROPERTY('local_tcp_port')) + '.'
		ELSE '.' END
	, 'If using the TCP protocol, port 1433 is the default.'
	, ''


/* Check that SQL Login Audit includes failed logins */
DECLARE @AuditValue int

EXEC master..xp_instance_regread 
    @RootKey='HKEY_LOCAL_MACHINE'
	, @Key='SOFTWARE\Microsoft\MSSQLServer\MSSQLServer'
	, @Value_Name='AuditLevel'
	, @Value = @AuditValue output

IF @AuditValue < 2
	INSERT #Results
	SELECT 
		1
		, 'High - action required'
		, 'No audit of failed logins'
		, NULL
		, 'There current SQL Login Audit settings do not include failed logins.'
		, 'SQL Error logs should capture failed login for review, since these may indicate hacking attempts.'
	    ,'https://straightpathsql.com/cs/login-audit-does-not-include-failed-logins'


/* Failed logins */
DECLARE @ErrorLog TABLE (
	LogDate DATETIME
	, ProcessInfo NVARCHAR(50) 
	, [Text] NVARCHAR(MAX)
    )
 
INSERT @ErrorLog
EXEC sp_readerrorlog 0, 1, 'Login failed'

DECLARE @FailedLogins bigint

SET @FailedLogins = (SELECT COUNT(*) FROM @ErrorLog)

IF @FailedLogins > 0
	INSERT #Results
	SELECT 
		2
		, 'High - review required'
		, 'Failed logins'
		, NULL
		, 'There have been at least ' + CONVERT(VARCHAR(10), @FailedLogins) + ' failed logins recently.'
		, 'Review the SQL Server error log for patterns of login failures or suspect IP addresses which may indicate hacking attempts.'
	    ,'https://straightpathsql.com/cs/failed-logins'


/* number of error logs */
DECLARE @NumErrorLogs INT;

EXEC master.sys.xp_instance_regread
    N'HKEY_LOCAL_MACHINE'
	, N'Software\Microsoft\MSSQLServer\MSSQLServer'
	, N'NumErrorLogs'
	, @NumErrorLogs OUTPUT;

IF (SELECT ISNULL(@NumErrorLogs, 12)) < 12 
	INSERT #Results
	SELECT 
		2
		, 'High - review required'
		, 'To few SQL Server error log files'
		, NULL
		, 'This instance is configured for only ' + CONVERT(VARCHAR(10), (ISNULL(@NumErrorLogs, -1))) + ' SQL Server error log files.'
		, 'We recommend having between 12 and 52 SQL Server error log files to review for patterns of login failures or suspect IP addresses which may indicate hacking attempts.'
	    , 'https://straightpathsql.com/cs/number-of-sql-server-error-log-files'


/* default trace disabled */


/***** Database settings *****/

/* TRUSTWORTHY setting check */
INSERT #Results
SELECT 
    1
    , 'High - action required'
	, 'TRUSTWORTHY database owned by sysadmin'
	, db_name(database_id)
	, 'The database ' + db_name(database_id) + ' has the TRUSTWORTHY setting enabled and is owned by a member of the sysadmin role.'
	, 'With TRUSTORWORTHY setting ON and a sysadmin database owner, any user can execute commands as a sysadmin.'
	, 'https://straightpathsql.com/cs/trustworthy-enabled'
FROM sys.databases
WHERE database_id > 4
    AND is_trustworthy_on = 1
    AND IS_SRVROLEMEMBER ('sysadmin', SUSER_SNAME(owner_sid)) = 1


INSERT #Results
SELECT 
	2
	, 'High - review required'
	, 'TRUSTWORTHY database'
	, db_name(database_id)
	, 'The database ' + db_name(database_id) + ' has the TRUSTWORTHY setting enabled.'
	, 'With this setting ON, any code in the database to be "trusted" in usage outside the context of the database.'
	, 'https://straightpathsql.com/cs/trustworthy-enabled'
FROM sys.databases
WHERE database_id > 4
    AND is_trustworthy_on = 1
    AND IS_SRVROLEMEMBER ('sysadmin', SUSER_SNAME(owner_sid)) = 0


/* db_owner role member */
SET @SQL = 'USE [?]; 
SELECT 3, ''Potential - review recommended'' 
, ''db_owner role member''
, DB_NAME()
, (''In ['' + DB_NAME() + ''], user ['' + u.name + '']  has the role ['' + g.name + ''].  This user can perform any function in this database including changing permissions for other users.'')
, ''Verify these elevated database permissions are required for this user.''
, ''https://straightpathsql.com/cs/db-owner''
FROM (SELECT memberuid = convert(int, member_principal_id), groupuid = convert(int, role_principal_id) FROM [?].sys.database_role_members) m inner join [?].dbo.sysusers u on m.memberuid = u.uid inner join sysusers g on m.groupuid = g.uid where u.name <> ''dbo'' and g.name in (''db_owner'') OPTION (RECOMPILE);';

INSERT #Results
EXEC sp_MSforeachdb @SQL

UPDATE #Results
SET
    VulnerabilityLevel = 1
	, Vulnerability = 'High - action required'
	, Issue = 'db_owner role member - system databases'
WHERE Issue = 'db_owner role member'
AND DatabaseName IN ('master','msdb')


/* unusual database permissions */
SET @SQL = 'USE [?]; 
SELECT 3, ''Potential - review recommended'' 
, ''Unusual database permissions''
, DB_NAME()
, (''In ['' + DB_NAME() + ''], user ['' + u.name + '']  has the role ['' + g.name + ''].  This is an unusual database role with elevated permissions, but it is redundant if this user is also in the db_owner role.'')
, ''Verify these elevated database permissions are required for this user.''
, ''https://straightpathsql.com/cs/unusual-database-permissions''
FROM (SELECT memberuid = convert(int, member_principal_id), groupuid = convert(int, role_principal_id) FROM [?].sys.database_role_members) m inner join [?].dbo.sysusers u on m.memberuid = u.uid inner join sysusers g on m.groupuid = g.uid where u.name <> ''dbo'' and g.name in (''db_accessadmin'' , ''db_securityadmin'' , ''db_ddladmin'') OPTION (RECOMPILE);';

INSERT #Results
EXEC sp_MSforeachdb @SQL

UPDATE #Results
SET
    VulnerabilityLevel = 1
	, Vulnerability = 'High - action required'
	, Issue = 'Unusual database permissions - system databases'
WHERE Issue = 'Unusual database permissions'
AND DatabaseName IN ('master','msdb')


/* find roles within roles in each database */
SET @SQL = '
USE [?]
IF DB_Name() NOT IN (''tempdb'') BEGIN
SELECT 3, ''Potential - review recommended'' 
, ''Roles within roles''
, db_name() as [DatabaseName]
, ''The role ['' + user_name(roles.member_principal_id) + ''] is a member of the role ['' + user_name(roles.role_principal_id)
 + '']. Including roles in other roles can lead to unintended privilege escalation.''
, ''Remove ['' + user_name(roles.member_principal_id) + ''] from the role ['' + user_name(roles.role_principal_id) + ''] and explicitly assign it required permissions''
, ''https://straightpathsql.com/cs/database-roles-within-roles''
FROM sys.database_role_members AS roles, sys.database_principals users
WHERE roles.member_principal_id = users.principal_id
AND user_name(roles.member_principal_id) <> ''RSExecRole''
AND ( roles.role_principal_id >= 16384 AND roles.role_principal_id <= 16393)
AND users.type = ''R''
END'


INSERT #Results
EXEC sp_MSforeachdb @SQL


/* find orphan user in each database */
SET @SQL = '
USE [?]
IF DB_Name() NOT IN (''tempdb'') BEGIN
SELECT 4, ''Low - action recommended'' 
, ''Orphaned user''
, db_name() as [DatabaseName]
, ''The database user ['' + [NAME] + ''] is orphaned, meaning it has no corresponding login at the instance level.''
, ''Reconnect the user to an existing login using sp_change_users_login, or drop the user.''
, ''https://straightpathsql.com/cs/orphaned-users''
FROM sys.database_principals
WHERE sid NOT IN (SELECT sid FROM sys.server_principals)
AND type = ''S''
AND principal_id != 2
AND DATALENGTH(sid) <= 28'
+ CASE 
	WHEN @SQLVersionMajor >= 12 THEN ' AND authentication_type_desc = ''INSTANCE'''
	END
+ ' END'



INSERT #Results
EXEC sp_MSforeachdb @SQL


/* database owner is different from owner in master */ -- has issues with mistmatched collation
SET @SQL = '
USE [?]
IF DB_Name() NOT IN (''tempdb'') BEGIN
SELECT 4, ''Low - action recommended'' 
, ''Database owner discrepancy''
, db_name() as [DatabaseName]
, ''The database owner ['' + dbprs.name COLLATE SQL_Latin1_General_CP1_CI_AS + ''] is different than the owner listed in master ['' + ssp.name COLLATE SQL_Latin1_General_CP1_CI_AS + ''].''
, ''Use sp_changedbowner to set the database owner to the correct login.''
, ''https://straightpathsql.com/cs/database-owner-discrepancy''
FROM   sys.database_principals AS dbprs
INNER JOIN sys.databases AS dbs
 ON dbprs.sid != dbs.owner_sid 
JOIN sys.server_principals ssp
 ON dbs.owner_sid = ssp.sid 
WHERE dbs.database_id = Db_id()
AND dbprs.principal_id = 1
END'

INSERT #Results
EXEC sp_MSforeachdb @SQL



/* explicit permissions granted to the Public role */
IF @SQLVersionMajor >= 12 BEGIN
	DECLARE @DB_Name sysname

	DECLARE public_cursor CURSOR FOR
		SELECT name 
		FROM master.sys.databases
		WHERE database_id > 4 AND state = 0
		AND [name] not in (
			SELECT adc.database_name
			FROM sys.availability_replicas AS ar
		   JOIN sys.availability_databases_cluster adc ON adc.group_id = ar.group_id
			WHERE ar.secondary_role_allow_connections = 0
		   AND ar.replica_server_name = @@SERVERNAME
		   AND sys.fn_hadr_is_primary_replica(adc.database_name) = 0 
			)

	OPEN public_cursor 
	FETCH NEXT FROM public_cursor INTO @DB_Name 

	WHILE @@FETCH_STATUS = 0 
	BEGIN 

	SET @SQL = 'USE ' + QUOTENAME(@DB_Name) + '; ' +
	'SELECT 2, ''High - review required''
	, ''Public permissions''
	, db_name() as [DatabaseName]
	, ''The [public] role has been granted the permission ['' + per.permission_name + ''] on the object [''
	+ CASE
	WHEN per.class = 0 THEN db_name()
	WHEN per.class = 3 THEN schema_name(major_id)
	WHEN per.class = 4 THEN printarget.NAME
	WHEN per.class = 5 THEN asm.NAME
	WHEN per.class = 6 THEN type_name(major_id)
	WHEN per.class = 10 THEN xmlsc.NAME
	WHEN per.class = 15 THEN msgt.NAME COLLATE DATABASE_DEFAULT
	WHEN per.class = 16 THEN svcc.NAME COLLATE DATABASE_DEFAULT
	WHEN per.class = 17 THEN svcs.NAME COLLATE DATABASE_DEFAULT
	WHEN per.class = 18 THEN rsb.NAME COLLATE DATABASE_DEFAULT
	WHEN per.class = 19 THEN rts.NAME COLLATE DATABASE_DEFAULT
	WHEN per.class = 23 THEN ftc.NAME
	WHEN per.class = 24 THEN sym.NAME
	WHEN per.class = 25 THEN crt.NAME
	WHEN per.class = 26 THEN asym.NAME
	END + ''].''
	, ''Because these permissions are available to anyone who can connect to your instance, they should be revoked and granted to users, groups, or roles other than public.''
	, ''https://straightpathsql.com/cs/explicit-permissions-for-public''
	FROM sys.database_permissions AS per
	LEFT JOIN sys.database_principals AS prin ON per.grantee_principal_id = prin.principal_id
	LEFT JOIN sys.assemblies AS asm ON per.major_id = asm.assembly_id
	LEFT JOIN sys.xml_schema_collections AS xmlsc ON per.major_id = xmlsc.xml_collection_id
	LEFT JOIN sys.service_message_types AS msgt ON per.major_id = msgt.message_type_id
	LEFT JOIN sys.service_contracts AS svcc ON per.major_id = svcc.service_contract_id
	LEFT JOIN sys.services AS svcs ON per.major_id = svcs.service_id
	LEFT JOIN sys.remote_service_bindings AS rsb ON per.major_id = rsb.remote_service_binding_id
	LEFT JOIN sys.routes AS rts ON per.major_id = rts.route_id
	LEFT JOIN sys.database_principals AS printarget ON per.major_id = printarget.principal_id
	LEFT JOIN sys.symmetric_keys AS sym ON per.major_id = sym.symmetric_key_id
	LEFT JOIN sys.asymmetric_keys AS asym ON per.major_id = asym.asymmetric_key_id
	LEFT JOIN sys.certificates AS crt ON per.major_id = crt.certificate_id
	LEFT JOIN sys.fulltext_catalogs AS ftc ON per.major_id = ftc.fulltext_catalog_id
	WHERE per.grantee_principal_id = DATABASE_PRINCIPAL_ID(''public'')
		AND class != 1 -- Object or Columns (class = 1) are handled by VA1054 and have different remediation syntax
		AND [state] IN (''G'',''W'')
		AND NOT (
			per.class = 0
			AND prin.NAME = ''public''
			AND per.major_id = 0
			AND per.minor_id = 0
			AND permission_name IN (
				''VIEW ANY COLUMN ENCRYPTION KEY DEFINITION''
				,''VIEW ANY COLUMN MASTER KEY DEFINITION''
				)
			)'
		
		INSERT #Results
		EXEC sp_executesql @SQL 

		/* iterate the cursor to the next database name */
		FETCH NEXT FROM public_cursor INTO @DB_Name 
	END 
	CLOSE public_cursor;
	DEALLOCATE public_cursor;
	END;

/* results */
IF @ShowHighOnly = 1
    SELECT
        VulnerabilityLevel 
        , Vulnerability
        , Issue
        , DatabaseName
        , Details
        , ActionStep
		, ReadMoreURL
    FROM #Results 
    WHERE VulnerabilityLevel <= 2
    ORDER BY 1, 2, 3, 4, 5

IF @ShowHighOnly = 0
    SELECT
        VulnerabilityLevel 
        , Vulnerability
        , Issue
        , DatabaseName
        , Details
        , ActionStep
		, ReadMoreURL
    FROM #Results 
    ORDER BY 1, 2, 3, 4, 5
    

