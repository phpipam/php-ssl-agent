<?php

/**
 *
 * Class to process result from API
 *
 */
class API_result {

	/**
	 * Time start measuring
	 * @var int
	 */
	private $starttime = 0;

	/**
	 * List of http response codes
	 * @var array
	 */
	private $errors = [
					// ok
					200 => "OK",
					201 => "Created",
					202 => "Accepted",
					204 => "No Content",
					// client errors
					400 => "Bad Request",
					401 => "Unauthorized",
					403 => "Forbidden",
					404 => "Not Found",
					405 => "Method Not Allowed",
					409 => "Conflict",
					415 => "Unsupported Media Type",
					// server errors
					500 => "Internal Server Error",
					501 => "Not Implemented",
					503 => "Service Unavailable",
					505 => "HTTP Version Not Supported"
	];

	/**
	 * Success flag
	 * @var bool
	 */
	private $success = false;

	/**
	 * Result code
	 * @var int
	 */
	private $code = 200;

	/**
	 * Database
	 * @var resource
	 */
	protected $Database;




	/**
	 * Constructor
	 * @method __construct
	 */
	public function __construct () {
		// start time count
		$this->starttime = microtime(true);
	}

	/**
	 * Sets success
	 * @method set_success
	 * @param  bool $success
	 */
	public function set_success ($success = false) {
		if (is_bool($success)) {
			$this->success = $success;
		}
	}

	/**
	 * Sets result code
	 * @method set_code
	 * @param  int $code
	 */
	public function set_code ($code = 200) {
		if (is_numeric($code)) {
			$this->code = $code;
		}
	}

	/**
	 * Returns result code
	 * @method get_code
	 * @return int
	 */
	public function get_code () {
		return $this->code;
	}

	/**
	 * Show result
	 * @method show
	 * @param  string $result
	 * @param  bool $skip_header
	 * @return json
	 */
	public function show ($result = "", $skip_header = false) {
		// init array
		$result_ins = [
					"success"    => $this->success,
					"code"       => $this->code,
					"result"     => $result,
					"time"    	 => round(microtime(true) - $this->starttime, 3)." s"
					];
		// set header
		if($skip_header===false) {
			$this->set_header ();
		}
		// return result
		return json_encode($result_ins, JSON_UNESCAPED_UNICODE)."\n";
	}

	/**
	 * Sets http header
	 * @method set_header
	 */
	private function set_header () {
		$description = isset($this->errors[$this->code])
			? $this->errors[$this->code]
			: "Unknown";
		header("Content-Type: application/json; charset=UTF-8");
		header("HTTP/1.1 ".$this->code." ".$description);
		header("X-Content-Type-Options: nosniff");
		header("X-Frame-Options: DENY");
		header("Cache-Control: no-store");
	}
}