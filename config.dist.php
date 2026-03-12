<?php

/**
 * Hosts permitted to make API calls
 *
 * 	Direct hosts
 */
$permitted_direct_hosts = [
				"localhost"           => "127.0.0.1"
				];

/**
 * Hosts permitted to make API calls
 *
 * 	Proxied hosts / XFF
 */
$permitted_proxied_hosts = [
				];

/**
 * Trusted reverse proxy IPs
 *
 * 	If REMOTE_ADDR matches one of these IPs the agent will additionally
 * 	validate the X-Forwarded-For header against $permitted_proxied_hosts.
 * 	List only IPs of known reverse proxies here.
 */
$permitted_trusted_proxies = [
				// "172.16.20.10"
				];
