<?php

/**
 * @debugging functions -------------------
 */
if(@$debugging===true)
ini_set('display_errors', 1);
else
ini_set('display_errors', 0);
error_reporting(E_ALL ^ E_NOTICE ^ E_DEPRECATED ^ E_WARNING);

// set custom error handler
set_error_handler ('MyErrHandler');
// function
function MyErrHandler ($errno, $errstr, $errfile, $errline) {
	throw new Exception ($errstr);
}

/**
 * Classes autoloading
 */

// class files
require( dirname(__FILE__) . '/classes/class.API_result.php' );	// Class to handle API results
require( dirname(__FILE__) . '/classes/class.API.php' );		// Class to handle API calls

// restore error handler
restore_error_handler();

// autoload classes
$API_result	= new API_result ();
$API		= new API ($API_result);
