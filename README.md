# Magpi #

*Wide Area SQL Injection Scanner* 

This script can be used to scan a web application for SQL Injection vulnerabilities.

## Usage: ##
                                                 
    $> php magpi.php inputfile outputfile

Where inputfile is the name of any text file that contains a list of URLs to scan,
one URL per line, and outputfile is the name of the log file to write results to.
You can call these files whatever you like so long as the order is correct,
input file, then output file. e.g.                                             

    $> php magpi.php url-list.txt results.txt        

Typically, you would generate the URL list from a spider script, which would
extrapolate a list of URLs from a web application, given an entry point,
or you can compile the list manually. 

The log file will record the URL and URL parameter in which it finds a vulnerability,
and also any data that it manages to retrieve. This can help guage the seriousness of
pre-existing vulnerabilities in  live systems. The script will attempt to dig down to
the level of individual records in user tables.

## Limitations:    

This script is intended for a quick evaluation of a web application, and therefore
does support blind-sql injection techniques, boolean blind nor time-based blind,
though this may be a future feature.    
 
The script indended to scan applications built on a LAMP stack only, and probably
won't work on applications built using PostgreSQL, MSSQL, Oracle or other.

## Disclaimer: ##

This software is intended for use in quickly testing, discovering, and guaging SQL   
injection vulnerabilities in web applications. It is freely available under the GNU
AFFERO GPL license http://www.gnu.org/licenses/agpl.txt. Use this at your own risk!  
The creator of this software assumes no liability or responsibility for any damages,
or criminal liability, incurred from the use of this software.    

Do not use this tool against targets that you do not own, or have prior consent to
attack. To do so is illegal!

