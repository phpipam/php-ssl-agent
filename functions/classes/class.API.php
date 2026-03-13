<?php

/**
 *
 * SSL calls processing
 *
 */
class API  {

	/**
	 * Array of permitted hosts. Loaded via autoload.php
	 * @var array
	 */
	protected $hosts_direct = [];

	/**
	 * Array of permitted hosts. Loaded via autoload.php
	 * @var array
	 */
	protected $hosts_proxied = [];

	/**
	 * Array of trusted reverse proxy IPs. Loaded via autoload.php
	 * @var array
	 */
	protected $trusted_proxies = [];

	/**
	 * Requested hostname
	 * @var string
	 */
	public $hostname = "";

	/**
	 * Requested ports to scan
	 * @var string
	 */
	protected $ports = "";

	/**
	 * Stream
	 * @var bool
	 */
	protected $stream = false;

	/**
	 * Stream options
	 * @var array
	 */
	protected $stream_options = [];

	/**
	 * Wait for 2 secons before giving up
	 * @var int
	 */
	protected $timeout = 2;

	/**
	 * Maximum number of ports to scan per request
	 * @var int
	 */
	protected $max_ports = 10;

	/**
	 * Whether scanning private/reserved IP ranges is permitted
	 * @var bool
	 */
	protected $allow_private_ips = false;

	/**
	 * Scan result
	 * @var array
	 */
	protected $certificate = false;

	/**
	 * Result handler
	 * @var object
	 */
	protected $API_result;




	/**
	 * Constructor
	 * @method __construct
	 * @param  string $API_result
	 */
	public function __construct ($API_result = "") {
		// Save API result
		$this->API_result = $API_result;
		// process request, save params
		$this->process_request ();
	}

	/**
	 * Process incoming request and create input parameters
	 *
	 *
	 * We expect:
	 * 	- last GET parameter to be json, this we use for processing
	 *
	 * @method process_request
	 * @return void
	 */
	private function process_request () {
		// explode to parameters
		$tmp = array_values(array_filter(explode("/", $_SERVER['REQUEST_URI'])));

		// save hostname
		$this->hostname = $tmp[count($tmp)-2];
		// save ports
		$this->ports = explode(",", str_replace(";",",",$tmp[count($tmp)-1]));

		// first validate hostname / ip address
		if ($this->validate_hostname()===false && $this->validate_ip_address()===false) {
			$this->throw_exception (400, "Invalid hostname or IP address");
		}
		// validate ports
		if ($this->validate_ports()===false) {
			$this->throw_exception (400, "Invalid ports");
		}
	}

	/**
	 * Register all allowed hosts
	 * @method register_hosts
	 * @param  array $hosts
	 * @return void
	 */
	public function register_hosts ($hosts = []) {
		if (is_array($hosts)) {
			$this->hosts_direct = $hosts;
		}
	}

	/**
	 * Register all allowed proxied hosts
	 * @method register_hosts_proxied
	 * @param  array $hosts
	 * @return void
	 */
	public function register_hosts_proxied ($hosts = []) {
		if (is_array($hosts)) {
			$this->hosts_proxied = $hosts;
		}
	}

	/**
	 * Register trusted reverse proxy IPs
	 * @method register_trusted_proxies
	 * @param  array $proxies
	 * @return void
	 */
	public function register_trusted_proxies ($proxies = []) {
		if (is_array($proxies)) {
			$this->trusted_proxies = $proxies;
		}
	}

	/**
	 * Allow or deny scanning of private and reserved IP ranges
	 * @method allow_private_ips
	 * @param  bool $allow
	 * @return void
	 */
	public function allow_private_ips ($allow = false) {
		if (is_bool($allow)) {
			$this->allow_private_ips = $allow;
		}
	}

	/**
	 * Make sure host is allowed to access API
	 * @method validate_requesting_host
	 * @return void
	 */
	public function validate_requesting_host () {
		// check direct hosts
		if (!in_array($_SERVER['REMOTE_ADDR'], $this->hosts_direct)) {
			$this->throw_exception (401, "Host not permitted to access API !");
		}
		// if request comes from a trusted proxy, also validate the X-Forwarded-For header
		if (in_array($_SERVER['REMOTE_ADDR'], $this->trusted_proxies)) {
			// take only the first IP from a potentially comma-separated XFF value
			$xff = isset($_SERVER['HTTP_X_FORWARDED_FOR'])
				? trim(explode(",", $_SERVER['HTTP_X_FORWARDED_FOR'])[0])
				: "";
			if (!filter_var($xff, FILTER_VALIDATE_IP) || !in_array($xff, $this->hosts_proxied)) {
				$this->throw_exception (401, "Proxied host not permitted to access API !");
			}
		}
	}

	/**
	 * Validate IP
	 * @method validate_ip_address
	 * @return bool
	 */
	private function validate_ip_address () {
		if (!filter_var($this->hostname, FILTER_VALIDATE_IP)) {
			return false;
		}
		// ok
		return true;
	}

	/**
	 * Check whether an IP is private or reserved (SSRF protection)
	 * @method is_private_ip
	 * @param  string $ip
	 * @return bool
	 */
	private function is_private_ip ($ip) {
		return filter_var($ip, FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		) === false;
	}

	/**
	 * Validate hostname
	 * @method validate_hostname
	 * @return bool
	 */
	private function validate_hostname () {
		// invalid
		if (!filter_var($this->hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
			return false;
		}elseif (strlen($this->hostname)==0) {
			return false;
		}
		// ok
		return true;
	}

	/**
	 * Validate requested ports for scanning
	 * @method validate_ports
	 * @return bool
	 */
	private function validate_ports () {
		// check
		if (!is_array($this->ports))	{ return false; }
		// null
		if (count($this->ports)==0)	{ return false; }
		// limit number of ports to prevent abuse
		if (count($this->ports) > $this->max_ports) { return false; }
		// check each port
		foreach ($this->ports as $p) {
			if (!is_numeric($p))			{ return false; }
			$port = (int) $p;
			if ($port < 1 || $port > 65535)	{ return false; }
		}
		return true;
	}

	/**
	 * Throw exception on error
	 *
	 * @method throw_exception
	 * @param  int $code
	 * @param  string $text
	 * @return void
	 */
	private function throw_exception ($code = 500, $text = "") {
		// set code
		$this->API_result->set_code ($code);
		// throw exc
		throw new Exception ($text);
	}

	/**
	 * Return result
	 * @method get_result
	 * @return array
	 */
	public function get_result () {
		// do we have any result ?
		if ($this->certificate===false) {
			$this->API_result->set_code (404);
			// resolve ip
			return [
				"success" => false,
				"ip"      => $this->resolve_ip($this->hostname)
			];
		}
		// ok
		else {
			return $this->certificate;
		}
	}




	/**
	 * Execute check
	 *
	 * @method scan
	 * @return void
	 */
	public function scan () {
		// block SSRF: reject private and reserved IP ranges unless explicitly allowed
		if (!$this->allow_private_ips && $this->validate_ip_address()===true && $this->is_private_ip($this->hostname)) {
			$this->throw_exception (400, "Scanning private or reserved IP addresses is not permitted");
		}
		//set stream options
		$this->set_stream_options ();
		// init stream
		$this->init_stream ();

		// time
		$execution_time = date("Y-m-d H:i:s");

		// execute
		$this->execute_scan ($execution_time);
	}

	/**
	 *
	 * SSL cert fetching
	 *
	 */
	private function set_stream_options () {
		// ssl options
		$this->stream_options['ssl'] = [
				'capture_peer_cert_chain' => true,
				'capture_peer_cert'       => true,
				'allow_self_signed'		  => true,
				'verify_peer'             => false,
				'verify_peer_name'        => false,
				'capath'				  => '/etc/ssl/certs'
		];
	}

	/**
	 * Create stream
	 * @method init_stream
	 * @return void
	 */
	private function init_stream () {
		$this->stream = stream_context_create ($this->stream_options);
	}

	/**
	 * Error handler used during stream_socket_client to suppress PHP warnings
	 * @method php_error_handler
	 * @param  int $errno
	 * @param  string $errstr
	 * @return void
	 */
	private function php_error_handler ($errno = 0, $errstr = "") {
		//$this->errors[] = "Unable to establish connection to host (err $errno : $errstr)";
	}

	/**
	 * Go through requested ports and execute scan
	 * @method execute_scan
	 * @param  string $execution_time
	 * @return void
	 */
	private function execute_scan ($execution_time) {
		// loop through ports
		foreach ($this->ports as $p) {
			// stream_socket_client may create PHP WARNINGS before socket is created and $errstr is set - also if it cannot connect to port, we ignore that !
			set_error_handler([$this, 'php_error_handler']);
			// connect and get result
			$client = stream_socket_client("ssl://".$this->hostname.":".$p, $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $this->stream);
			// restore error handler after each attempt
			restore_error_handler();
			// process result
			$certificate = $this->process_fetch_result ($errno, $errstr, $execution_time, $p, $client);
			// if not false quit, we found something
			if ($certificate!==false) {
				$this->certificate = $certificate;
				break;
			}
		}
	}

	/**
	 * We got some result from scan, process it
	 * @method process_fetch_result
	 * @param  int $errno
	 * @param  string $errstr
	 * @param  string $execution_time
	 * @param  string $port
	 * @param  resource|bool $client
	 * @return array|bool
	 */
	private function process_fetch_result ($errno, $errstr, $execution_time, $port, $client) {
		// check if connection failed with an error message
		if (strlen($errstr) > 0) {
			$this->throw_exception (500, $errstr);
		}
		// check if connection failed silently
		if ($client === false) {
			$this->throw_exception (500, "Unable to connect to host");
		}
		// ok - get stream params
		$cont = stream_context_get_params($this->stream);

		// metadata - TLS version
		$metadata = stream_get_meta_data($client);

		// get cert and export it
		$peer_cert       = $cont["options"]["ssl"]["peer_certificate"];
		$peer_cert_chain = $cont["options"]["ssl"]["peer_certificate_chain"];

		if (openssl_x509_export($peer_cert, $certinfo) === false) {
			$this->throw_exception (401, "Could not fetch peer certificate");
		}
		else {
			// chain
			$certinfo_chain = "";
			foreach ($peer_cert_chain as $int_cert) {
				if (openssl_x509_export($int_cert, $output) !== false)
				    $certinfo_chain .= $output;
			}
			// parse
			$peer_cert_parsed = openssl_x509_parse($peer_cert);
			$valid_to = date("Y-m-d H:i:s", $peer_cert_parsed['validTo_time_t']);
			// return
			return [
				"success"     => true,
				"serial"      => $peer_cert_parsed['serialNumber'],
				"certificate" => trim($certinfo),
				"chain" 	  => trim($certinfo_chain),
				"expires"	  => $valid_to,
				"created"	  => $execution_time,
				"port"		  => $port,
				"ip" 		  => $this->resolve_ip($this->hostname),
				"tls_proto"   => isset($metadata['crypto']['cipher_version'])
								 ? $metadata['crypto']['cipher_version']
								 : null
			];
		}
	}

	/**
	 * Resolves IP from hostname
	 * @method resolve_ip
	 * @param  string $hostname
	 * @return string
	 */
	public function resolve_ip ($hostname = "") {
		$ip = gethostbyname($hostname);
		return $ip==$hostname ? $hostname : $ip;
	}
}
