<?php

/**
 * This file defines the ManageSieve class.
 */
class ManageSieve {
	private $remote_address;
	private $socket;

	public $response;
	public $scripts;
	public $active_script;

	/**
	 * Constructor for the ManageSieve class.
	 */
	public function __construct($hostname, $port, $sasl_mechanism, $username, $password) {
		$this->remote_address = 'tcp://' . $hostname . ':' . $port;

		$this->socket = stream_socket_client($this->remote_address);
		if (!$this->socket) {
			throw new Exception('Connecting to ManageSieve socket failed.');
		}

		stream_set_timeout($this->socket, 15);

		/* Read the intial banner. */
		$this->get_response();

		$this->send_line('STARTTLS');
		$this->get_response();

		if (!stream_socket_enable_crypto($this->socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
			throw new Exception('STARTTLS negotiation failed.');
		}

		/* Get the updated banner now that we are using TLS. */
		$this->get_response();

		$this->authenticate($sasl_mechanism, $username, $password);

		/* Populate $scripts and $active_script. */
		$this->list_scripts();
	}

	private function check_response() {
		$response_array = explode(' ', $this->response);
		if (($response_array[0] == 'NO') || ($response_array[0] == 'BYE')) {
			array_shift($response_array);
			throw new Exception(implode(' ', $response_array));
		}
	}

	/**
	 * A function to abstract away the details of receiving data from the server.
	 * This function populates the $response variable. TODO: write better docs here.
	 */
	private function get_response() {
		$this->response = fread($this->socket, 1024);
		$this->check_response();
		return $this->response;
	}

	/**
	 * A function to abstract away the details of sending data to the server.
	 * This way, we ensure the proper CRLF sequence is always sent, and we
	 * allow fwrite to be swapped out with something else if the need arises.
	 */
	private function send_line($line) {
		fwrite($this->socket, "${line}\r\n");
	}

	/**
	 * Authenticate the user via their chosen SASL authentication mechanism.
	 * An exception will be thrown if the server does not support the chosen
	 * mechanism or if the user's credentials are incorrect.
	 */
	private function authenticate($sasl_mechanism, $username, $password) {
		switch ($sasl_mechanism) {
			case 'PLAIN':
				$auth_string = base64_encode("\0${username}\0${password}");
				$this->send_line("AUTHENTICATE \"PLAIN\" \"${auth_string}\"");
				$this->get_response();
				break;
			case 'LOGIN':
				$this->send_line('AUTHENTICATE "LOGIN"');
				$this->get_response();
				$auth_string = '"' . base64_encode($username) . '"';
				$this->send_line($auth_string);
				$this->get_response();
				$auth_string = '"' . base64_encode($password) . '"';
				$this->send_line($auth_string);
				$this->get_response();
				break;
			default:
				throw new Exception('"Unsupported authentication mechanism."');
		}
	}

	/**
	 * This function implements the LISTSCRIPTS command.
	 */
	public function list_scripts() {
		$this->send_line('LISTSCRIPTS');
		$this->get_response();
		/* Split the response into an array of strings. */
		$this->scripts = preg_split('/\r\n/', $this->response);
		/* Remove any empty strings from the array. */
		$this->scripts = array_filter($this->scripts);
		/* Remove the 'OK' response the ManageSieve server returns along with the script names. */
		array_pop($this->scripts);
		/* Get the active script (if there is one). */
		$this->active_script = implode(array_filter($this->scripts, function($i) { return preg_match('/ \bACTIVE\b$/i', $i); }));
		/* Finally, clean up both $scripts and $active_script. */
		$this->scripts = preg_replace('/ \bACTIVE\b$/i', '', $this->scripts);
		$this->active_script = preg_replace('/ \bACTIVE\b$/i', '', $this->active_script);
	}

	/**
	 * This function implements the SETACTIVE command.
	 */
	public function set_active($script) {
		$this->send_line("SETACTIVE \"${script}\"");
		$this->get_response();
		$this->list_scripts();
	}

	/**
	 * This function implements the GETSCRIPT command.
	 */
	public function get_script($script) {
		$this->send_line("GETSCRIPT \"${script}\"");
		$this->get_response();
	}

	/**
	 * Destructor for the ManageSieve class. A LOGOUT command is politely
	 * issued to the server to close the connection before the socket is shut down.
	 */
	public function __destruct() {
		$this->send_line('LOGOUT');
		$this->get_response();
		stream_socket_shutdown($this->socket, STREAM_SHUT_RDWR);
	}
}
