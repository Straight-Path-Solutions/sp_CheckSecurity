# sp_CheckSecurity
Hello, and welcome to the GitHub repository for sp_CheckSecurity! This is a free tool from [Straight Path Solutions](https://straightpathsql.com/) for SQL Server Database Administrators (or people who play DBA at their organization) to use for detecting security vulnerabilities and discrepancies in their SQL Server instances.

# Why would you use sp_CheckSecurity?

Here at Straight Path Solutions, we're big fans of community tools like [sp_WhoIsActive](https://github.com/amachanic/sp_whoisactive/releases), [Brent Ozar's First Responder's Kit](https://github.com/BrentOzarULTD/SQL-Server-First-Responder-Kit/releases), and [Erik Darling's suite of helpful stored procedures](https://github.com/erikdarlingdata/DarlingData). As database administrators who are constantly looking at new clients and new servers, we wished there was a tool to quickly give an overview of any potential security issues. We didn't find one, so we made one.

# What does sp_CheckSecurity do?

Maybe you have some scripts you found on the internet to check some security settings or look for odd permissions. Or maybe you don't. Well, here's what sp_CheckSecurity checks.<p>

  **Instance information** <br>
	• Server and instance name<br>
	• Communication protocol<br>
	• Encrypted databases<br>
	• Remote dedicated admin connections<br>
	• Security update available<br>
	• SQL Server service accounts<br>
	• Unencrypted databases<br>
	• Unsupported versions and builds<br>
<br>
**Instance logins and permissions** <br>
	• CONTROL SERVER permissions<br>
	• Enabled sa login<br>
	• Invalid Windows login<br>
	• Local Administrators group members<br>
	• Password vulnerabilities<br>
	• securityadmin role members<br>
	• sysadmin role members<br>
<br>
**Instance settings**<br>
	• CLR enabled<br>
	• Cross-database ownership chaining<br>
	• Database backup certificate expiration date<br>
	• Database owner is not sa<br>
	• Database owner is unknown<br>
	• Endpoint ownership<br>
	• Failed logins<br>
	• Linked server<br>
	• Recent database backup certificate backup<br>
	• Recent TDE certificate backup<br>
	• SQL Agent jobs owned by users<br>
	• SQL Agent jobs that run at startup<br>
	• SQL Login Audit does not include failed logins<br>
	• SQL Server Audits in use<br>
	• Stored procedures that run at startup<br>
	• TDE certificate expiration date<br>
	• xp_cmdshell enabled<br>
<br>
**Database settings and permissions**<br>
	• Database owner is different from owner in master<br>
	• Database roles within roles<br>
	• db_owner role members<br>
	• Explicit permissions granted to the public role<br>
	• Orphaned users<br>
	• TRUSTWORTHY database<br>
	• Unusual database permissions<p>

After completing all these checks, you will get a single result set with any issues found, ordered by vulnerability level. Each row will identify what we found, why it is a (potential) issue, what our recommendation for resolving the issue is, and a link for more information about the issue.


# How do I use it?
 
Execute the script to create sp_CheckSecurity in the database of your choice, although we would recommend the master so you can call it from the context of any database.
<p>
Although you can simply execute it as is, there are currently three parameters.<p>
  
**@help** - the default is 0, but setting this to 1 will return some helpful information about sp_CheckSecurity and its usage in case you aren't able to read this web page.<p>

**@ShowHighOnly** - the default is 0, which returns all findings. If you only want to focus on the most important findings, you can reduce the result set by setting this to 1.<p>

**@PreferredDBOwner** - the default is 'sa', but use this parameter if you have a preferred server principal that you want as the owner of databases.<p>

**@CheckLocalAdmin** - the default is 0, which does not check the members of the local Windows Administrators group. Because this is a powerful group, we recommend setting this to 1 to determine who is in the local Administrators group, however…<p>

### *** WARNING ***<p>

 If you execute sp_CheckSecurity with @CheckLocalAdmin = 1, then sp_CheckSecurity will attempt to read and record the members of the BUILTIN\Administrators group. If BUILTIN\Administrators is not currently a member of the Logins, then sp_CheckSecurity will proceed with the following logic.
<p>
    1. BEGIN an explicit transaction.<br>
    2. Add BUILTIN\Administrators as a Login.<br>
    3. Read and record the members of BUILTIN\Administrators.<br>
    4. ROLLBACK the transaction, removing BUILTIN\Administrators from Logins.<br>
<p>
We note this because if you have ANY database level triggers or other fun features enabled to track the addition of members to Logins then you, dear user, assume any responsibility for any subsequent action from this brief addition. Please don't say we didn't warn you.

# What do the Vulnerability Levels mean?

**0 - Information only**. This is stuff you should know about your instances like version and service account used, but if you don't know it…well, now you do.<p>

**1 - High vulnerability requiring action**. These are the issues that could most likely lead to your company being front page news for all the wrong reasons. If your instances have any results at this level then we recommend cancelling that 3-martini lunch and instead huddling with your team to figure out when to address these issues.<p>

**2 - High vulnerability to review**. These include settings and assigned permissions you should review soon, if not immediately. These findings may not necessarily indicate a clear vulnerability, but we've found unexpected vulnerabilities in these categories at many, many clients.<p>

**3 - Potential vulnerability to review**. These are configurations or assigned permissions you may be using that could lead to problems for users. Or maybe they're just required for your applications. Either way, we recommend reviewing these to make sure these are correct.<p>

**4 – Low vulnerability with recommended action**. These are typically security inconsistencies that should be addressed. They aren't likely to cause problems, but you should clean up the mess.

# What are the requirements to use sp_CheckSecurity?

There are two requirements.<p>

**1. You need to be in the sysadmin role**. This tool is designed to be used by administrators only, as they are the only ones who can address many of the vulnerabilities and discrepancies that could be found. If you aren't in the sysadmin role, this isn't the stored procedure you're looking for.<p>

**2. Your SQL Server instance needs to be using SQL Server 2012 or higher**. If you are using an earlier version, execution of the stored procedure will be aborted because some of the DMVs used don't exist in earlier versions. 
<p></p>

