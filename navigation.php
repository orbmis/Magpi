<?php

class navigation
{

	/**
     * Prints out Menu options
     * @access public
     * @return String Menu options
     */
    public static function printMenu()
    {
    	$banner = self::getBanner();

        $options = array('SQL Injection (error-based)', 'Heartbleed', 'Shellshock', 'LFI / RFI', 'CLRF / Response Splitting', 'XSS (Reflective / DOM based)');

		$menu = "\n\nPlease Select an Attack vector:\n";

        for ($i=1; $i<=count($options); $i++) {
            $menu .= "\n\t$i.{$options[$i-1]}";
        }

		echo $banner.$menu."\n\nmagpi> ";

        $userChoice = trim(fgets(STDIN));

        return $userChoice;
    }

    /**
     * Processes menu selection
     * @access public
     * @param Integer The user's menu selection
     * @return Void
     */
    public static function processMenuSelection($selectionId)
    {
        $modules = array('sqliscan', 'heartbleed', 'shellshock', 'lfi', 'clrf', 'xss');

        return $modules[$selectionId - 1];
    }

	/**
     * Returns our script banner, which is dislayed when the script runs.
     * @access public
     * @return String Our ascii-art banner
     */
    public static function getBanner()
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