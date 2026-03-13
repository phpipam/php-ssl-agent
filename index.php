<?php

/**
 *
 * This is a php-ssl scanning agent API
 *
 * It takes json input, scans for :
 * 	- hostname 	: ip or hostname
 *  - ports 	: ports to scan in order
 *
 *
 * Response will be standard http codes:
 *
 *  - 200 OK 	: Certificate fetched ok
 *
 * For 200 it will contain also data json field:
 * 	- data:
 *  	- hostname:
 *   	- cert
 */


// api
try {
	# functions and classes loader
	require(dirname(__FILE__).'/functions/autoload.php');
	# version
	require(dirname(__FILE__).'/version.php');
	# allowed hosts
	require(dirname(__FILE__).'/config.php');

	var_dump($version);

	# register permitted hosts
	$API->register_hosts ($permitted_direct_hosts);
	$API->register_hosts_proxied ($permitted_proxied_hosts);
	$API->register_trusted_proxies ($permitted_trusted_proxies);
	$API->allow_private_ips ($scan_private_ips ?? false);

	# validate requesting host
	$API->validate_requesting_host ();

	# execute
	$API->scan ();
	# print
	$API_result->set_success (true);
	# version
	$API_result->add_version ($version);

	# print result
	print $API_result->show ($API->get_result());
} catch (Exception $e) {
	// set code
	if ($API_result->get_code()===200) {
		$API_result->set_code (500);
	}
	// set result
	$err_result = [
		"success" => false,
		"code"    => $API_result->get_code (),
		"error"   => $e->getMessage ()
	];
	// add ip if API class is correctly loaded
	if (isset($API)) {
		$err_result['ip'] = $API->resolve_ip ($API->hostname);
	}
	// output result
	echo $API_result->show ($err_result);
}

exit();
