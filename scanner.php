<?php

class scanner
{
	/**
     * Overrides various PHP settings to allow script to run properly
     *
     * @access public
     * @return void
     */
    public function __construct()
    {
        ini_set('display_errors', true);
        ignore_user_abort(true);
        set_time_limit(0);
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
    public function startScan($inputFile, $potentialList, $logFile)
    {
        @mkdir('logs');

        // write time of scan to log file...
        $handle = fopen($logFile, 'a+');

        if (!$handle) {
            die("\nCouldn't open file $logFile");
        }
        
        fwrite($handle, "\nRunning Scan on input file: $inputFile at ".date('Y-m-d H:i:s')."\n\n");

        fclose($handle);

        print($this->getBanner());

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

        // iterate through potential targets...
        foreach ($potentialList as $url) {
            if (!$lastScanned || $url == $lastScanned) {
                $ignoreFlag = false;
                //continue;
            } elseif ($ignoreFlag) {
                //continue;
            }
            $this->scanUrl($url, $logFile, $swapFile, $lastScanned);
            $i++;
        }

        fclose($swapFile);

        echo "\n\nFinished Scan\n\n";

        if (PHP_SAPI !== 'cli') {
            echo "</pre></body></html>";
        }
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
    public function updateLogs($logFile, $data, $mode)
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
     * Initiates a HTTP request to a given URL, and return the response body
     *
     * @access Public
     * @param String The URL to send the HTTP request to
     * @return String The body of the HTTP response
     * @todo Create alternative ways to make request when php-curl is not available
     */
    public function runQuery($url)
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
     * Converts a string to its hexadecimal representation
     *
     * @access Public
     * @param String The string to be converted
     * @return String The hexadecimal encoded string
     */
    public static function strToHex($string)
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
    public function binary_search($injectionPoint, array $testRange, $first, $last, $compare)
    {
        $lo = $first;
        $hi = $last - 1;

        while ($lo <= $hi) {
            $mid = (int)(($hi - $lo) / 2) + $lo;
            $cmp = call_user_func($compare, $this, $injectionPoint, $mid);

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
     * Runs a query against the target site to deteremine if the given column number
     * throws an error when used with 'order by'
     *
     * @access Public
     * @param String The URL to hit, the injection point is indicated with an apostrophe
     * @param Integer The column number to try to sort by
     * @return Boolean Returns true if an error is on the page, indicating we have exceed the number of columns available
     */
    public static function cmp($scan, $injectionPoint, $columnNumber)
    {
        $testUrl = $scan->getColumnCount($injectionPoint, $columnNumber);

        return $scan->checkError($testUrl);
    }

    /**
     * Generates a random string
     *
     * @access Public
     * @param Integer The length of the random string to generate
     * @return String A random sequence of alphanumeric characters
     */
    public function randomString($strLen = 32)
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
    public function getBanner()
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
}