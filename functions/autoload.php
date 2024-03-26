<?php

/**
 * @debugging functions -------------------
 */
ini_set('display_errors', 1);
error_reporting(E_ALL ^ E_NOTICE ^ E_STRICT ^ E_DEPRECATED ^E_WARNING);

// set custom error handler
set_error_handler ('MyErrHandler');
// function
function MyErrHandler ($errno, $errstr, $errfile, $errline) {
	throw new exception ($errstr);
}

/**
 * Classes autoloading
 */

// class files
require( dirname(__FILE__) . '/classes/class.API_result.php' );	// Class to handle API results
require( dirname(__FILE__) . '/classes/class.API.php' );		// Class to handle API calls

// autoload classes
$API_result	= new API_result ();
$API		= new API ($API_result);