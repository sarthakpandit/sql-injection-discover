<?php

exit( main() );

function main( ) {	

	$gsi0com_sql_injection_discover = new gsi0com_sql_injection_discover();	
	
	$opts = getopt("i:e:t:h::");
	$opts['default'] = null;
	
	foreach( array_keys($opts) as $opt ) switch($opt){
		case 'i':
			//inyections
			$inyections        = @$opts['i'];
			if(empty($inyections)or(!isset($inyections))) die("gsi0com_sql_injection_discover: Invalid command arguments (option 'i' (Inyections) requires a value)\n");

			//errors
			$errors        = @$opts['e'];
			if(empty($errors)or(!isset($errors))) die("gsi0com_sql_injection_discover: Invalid command arguments (option 'e' (Errors) requires a value)\n");
			
			//target
			$target       = @$opts['t'];
			if(empty($target)or(!isset($target))) die("gsi0com_sql_injection_discover: Invalid command arguments (option 't' (target) requires a value)\n");
				
	
			// Use this comodin {inyectme}	
			$gsi0com_sql_injection_discover->setTargetUrl($target);
			$gsi0com_sql_injection_discover->setSqliDorks($inyections);
			$gsi0com_sql_injection_discover->setSqliErrors($errors);
			
			$gsi0com_sql_injection_discover->start();
			 
			break;
		case 'h':
		default:
			$gsi0com_sql_injection_discover->printHelp();
			exit(1);
			break;
	}
	
	
}

//Set namespace if is necesary

/**
 * @package    gsi0.om_sql_injection_discover
 * @copyright  Copyright @JamesJara (c) 2010-2014 Grupo de Seguridad informatica Costa RIca. (http://gsi0com)
 * @license    FREE FOR EVERYBODY
 */
class gsi0com_sql_injection_discover {
	###############################################################################################################
	#   Author:james jara
	#   Date:  26/08/2012
	#   Version 0.1
	#
	#   #############   #############    ##
	#   ##              ##               ##
	#   ##              ##
	#   ##              #############    ##
	#   ##     ######              ##    ##
	#   ##         ##   ##         ##    ##
	#   ##         ##   ##         ##    ##
	#   #############   #############    ##
	#   gsicr-gsi0com_sql_injection_discover is a small tool that allows a single inyection of sql code,
	#   if is successful the result is saved in a log
	#
	#   Usage:
	#   php gsi0.com_sql_injection_discover.php -i<inyections> -e<errors> -t<target url>
	###############################################################################################################
	
	
	//=============Some LOG modes==================
    const log_info  = "Info";
    const log_error = "Error";
    const log_debug = "Debug";
    const log_always = "Always";
	
	//=============1.Set variables==================
	private static $instance;
	
	protected 	$debug 		= null,
				$target_url = null,
				$dorks_path	= null,
				$errors_path= null;
	
	//=============2.Set constructors==================
	/**
	 * Create a singleton 
	 *
	 * @return self object instance
	 */
	public static function getInstance(){
		if(!self::$instance){
			return self::$instance = new self();
		}
		return self::$instance; 
	}
	
	/**
	 * Initiate the object class_prototype
	 */
	public function __construct(){ }
	
	public function printHelp(){
		echo "gsi0.com_sql_injection_discover 1.0 (Mon 20th 2012).
   Usage: gsi0.com_sql_injection_discover.php
  
	gsi0com_sql_injection_discover is a small tool that allows a single inyection of sql code,
	if is successful the result is saved in a log
				
   Required:
    -i <inyections>     full path to the file with inyection list
    -e <errors>     	full path to the file with errors list
    -t <target url>     Url target with inyection TAG
				
   Options:
	
    -h                Print this help.
\n";
	}
	
	//=============3.Set setters and getters==================
	/**
	 * Set the debug mode
	 *
	 * @param  boolean will show debug information if set to true, else will not show anything
	 */
	public function setDebug($value ){
		$this->debug = (($value==true) ? true : false);
	}
	
	/**
	 * Function to print log information
	 *
	 * @param  $msg			Message to display
	 * @param  $severity	The kind of Log 
	 */
	private function _log( $msg , $severity ) {
		$string =  sprintf( "[%s]\t[%s] : %s \n", $severity, date('c') , $msg );
		if( ($this->debug==true) or ( $severity == self::log_always) ) {
			echo $string;
		}
	}
	
	/**
	 * Function to write only log errors
	 *
	 * @param  $msg		Message to write
	 */
	private function write_Log_error( $msg ){
		$error_log_path = date('y_d_m').'.log';
		if(!$this->writeToFile( $error_log_path, $msg."\n" , true )){
			echo " CRITICAL ERROR Error writing log error. \n";
			die();
		}
	}
	
	/**
	 * Function to write a msg to a specific file
	 *
	 * @param  $path		Path of the target file, using fopen(W)
	 * @param  $data		Msg to write
	 * @param  $appened		if is true will appened the data to the end of  the file
	 */
	public function writeToFile( $path , $data , $appened = false ){
		$mode = ( ($appened==true) ? 'a' : 'w' );
		if(is_writable(dirname($path))){
			$handle = fopen( $path  , $mode);
			if (!$handle){
				$this->write_Log_error("Cant open the file $path ");
				$this->_log("Cant open the file $path ", 'Error' );
				return false;
			}
			if (!fwrite($handle,$data)) {
				$this->write_Log_error("Cannot write the file $path ");
				$this->_log("Cannot write the file $path ", 'Error' );
				exit; //in this case should stop the program
			} else {
				fclose( $handle );
				return true;
			}
		}
	}

	//=============4.Set OUR basic functions here==================
	
	//Curl Requests
	/**
	 * 
	 * @param String $url
	 * @return will return an array with errors and content
	 */
	private function execute_http( $url )
	{
		$useragent = array('Mozilla','Opera','www.gsi0com','Microsoft Internet Explorer','ia_archiver','jamesjara');
		$os = array('Windows','Windows XP','Linux','Windows NT','Windows 2000','OSX');
		$agent = $useragent[rand(0,3)].'/'.rand(1,8).'.'.rand(0,9).' ('.$os[rand(0,5)].' '.rand(1,7).'.'.rand(0,9).'; en-US;)';
		$ip = rand(161,254).'.'.rand(160,200).'.'.rand(50,120).'.'.rand(5,99);
	
		$options = array(

				CURLOPT_URL			   => $url,
				CURLOPT_RETURNTRANSFER => true,     // return web page
				CURLOPT_HEADER         => true,    // don't return headers
				CURLOPT_FOLLOWLOCATION => false,     // follow redirects
				//CURLOPT_ENCODING       => "",       // handle all encodings
				CURLOPT_USERAGENT      => $agent, 	// who am i
				CURLOPT_AUTOREFERER    => true,     // set referer on redirect
				CURLOPT_CONNECTTIMEOUT => 120,      // timeout on connect
				CURLOPT_TIMEOUT        => 120,      // timeout on response
				//CURLOPT_MAXREDIRS      => 1 ,      // stop after 10 redirects
				CURLOPT_COOKIEJAR      => "cookie.txt",
				CURLOPT_HTTPHEADER, array("REMOTE_ADDR: $ip", "X_FORWARDED_FOR: $ip" , "gsi0com: $ip", "HTTP_X_FORWARDED_FOR: $ip")
		);
		$ch      = curl_init( );
		curl_setopt_array( $ch, $options );
		$content = curl_exec( $ch );
		$err     = curl_errno( $ch );
		$errmsg  = curl_error( $ch );
		$header  = curl_getinfo( $ch );
		curl_close( $ch );
		$header['errno']   = $err;
		$header['errmsg']  = $errmsg;
		$header['content'] = strtolower($content);
		return $header;	
	}
	
	/**
	 * Set the URL variable to target host, remember add a comodin {inyectme} to inject the code there
	 *
	 * @param  String
	 */
	public function setTargetUrl($value){
		if(empty($value)) throw new Exception(' Set Target URL var first ');
		$this->target_url = $value;
	}
	
	/**
	 * Return the URL variable  of the target host
	 *
	 */
	private function getTargetUrl(){
		return $this->target_url ;
	}
	
	/**
	 * Set the path to tge dork sql injection file
	 *
	 * @param  String
	 */
	public function setSqliDorks($value){
		if(empty($value)) throw new Exception(' Set the path to the  Dorks injection file  var first ');
		$this->dorks_path = $value;
	}
	
	/**
	 * Return the path to tge dork sql injection file
	 *
	 */
	private function getSqliDorks(){
		return $this->dorks_path ;
	}
	
	/**
	 * Set the path to the errors sql injection file
	 *
	 * @param  String
	 */
	public function setSqliErrors($value){
		if(empty($value)) throw new Exception(' Set the path to the  Errors injection file  var first ');
		$this->errors_path = $value;
	}
	
	/**
	 * Return the path to tge errors sql injection file
	 *
	 */
	private function getSqliErrors(){
		return $this->errors_path ;
	}


	/**
	 * Return array with all sql injection dorks
	 *
	 */
	private function loadSqlInejctionDorksList(){
		if(!file_exists($this->getSqliDorks()))  throw new Exception( sprintf(' error , check the file %s ',$this->getSqliDorks()));
		$read_file	=	fopen( $this->getSqliDorks() , 'r');
		$dorks = null;
		while(!feof($read_file)){
			$dorks[] = trim( fgets($read_file) );
		}
		fclose($read_file);
		return $dorks ;
	}
	
	/**
	 * Return array with all sql injection posible errors
	 *
	 */
	private function loadSqlInejctionErrorsList(){
		if(!file_exists($this->getSqliErrors()))  throw new Exception( sprintf(' error , check the file %s ',$this->getSqliErrors()));
		$read_file	=	fopen( $this->getSqliErrors() , 'r');
		$errors = null;
		while(!feof($read_file)){
			$errors[] = strtolower(trim( fgets($read_file) ));
		}
		fclose($read_file);
		return $errors ;
	}
	
	
	//=============5.Set main function==================
	/**
	 * Call this function to execute your program logic.
	 *
	 */
	public function start() {
		echo "==== welcome gsi0.com ARMY by @jamesjara , wait.. the pentesting is starting... \n";

		if(empty($this->errors_path)) throw new Exception(' Set the path to the  Errors injection file  var first ');
		if(empty($this->dorks_path)) throw new Exception(' Set the path to the  Dorks injection file  var first ');
		if( preg_match('{inyectme}', $this->getTargetUrl() )==false  ) throw new Exception(' Set the {inyectme} tag first , ej: jamesjara.com/name={inyectme} ');

		$SQLI_dorks	=	$this->loadSqlInejctionDorksList();
		$SQLI_erros	=	$this->loadSqlInejctionErrorsList();
		$count 		= 0;		
		$count_pos 	= 0;		
		$resulty = 'negative';		
		//For each SQL INJECTION DORK , print and log the result only if is positive
		foreach($SQLI_dorks as $dork){
			echo sprintf("<><><> - - Executing new dork #%s - [%s] \n",$count,$dork);	
			$result = $this->execute_http( str_ireplace('{inyectme}', $dork  , $this->getTargetUrl() ));
			//Todo -> performance here
			foreach ($SQLI_erros as $erros){
				if (  stripos($result['content'] ,  $erros )  !== false ){
					$doc	=  " ======================================================= \n";
					$doc	.= " ======================================================= \n";
					$doc	.= " ======================================================= \n";
					$doc	.= " =======================NEW VULNERABILITY=============== \n";
					$doc	.= " === Target Url: 	[".$this->getTargetUrl()."] \n";
					$doc	.= " === Executed Dork: [$dork] \n";
					$doc	.= " === Error triggered: [$erros] \n";
					$doc	.= " === Body Response: [".$result['content']."] \n";
					$doc	.= " ======================================================= \n";
					$doc	.= " ======================================================= \n";
					$doc	.= " ======================================================= \n";
					$doc	.= " ======================================================= \n";
					$target	= parse_url($this->getTargetUrl());			
					$this->writeToFile( date('y-m-d').'_'.str_ireplace("/", '_', $target['path'] ).'.txt' , $doc , true);
					$resulty = 'positive, check the log for more details';
					$count_pos++;
				}
			}			
			echo sprintf("<><><><><> - - - - - Result: %s \n",$resulty);
			$count++;
		}
		echo "======================================== \n";
		echo "==== #$count_pos injections founded ... \n";
		echo "==== welcome gsi0.com ARMY by @jamesjara , pentesting FINISHED ,check results.txt ... \n";		
	}
	
}