<?php

/**
 * This file defines the ManageSieve class.
 */
class ManageSieve {
	private $remote_address;
	private $socket;

	public $response;
	public $status;
	public $verbose_status;
	public $error;
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
	}

	private function check_status() {
		/* Split raw response data into an array of lines. */
		$response_lines = preg_split('/\r\n/', $this->response);
		/* Filter out any empty strings. */
		$response_lines = array_filter($response_lines);

		/* The last line of the response should contain a valid status code. */
		$response_status_array = explode(' ', end($response_lines));
		$this->status = $response_status_array[0];

		/* The rest of the line should contain a verbose status message. */
		array_shift($response_status_array);
		$this->verbose_status = implode(' ', $response_status_array);

		/* All client queries are replied to with either an OK, NO, or BYE response. */
		switch ($this->status) {
			case 'OK':
				$this->error = false;
				break;
			case 'NO':
				$this->error = true;
				break;
			case 'BYE':
				/* If the server returns 'BYE' we cannot proceed. */
				throw new Exception('Server closed the connection.');
			default:
				throw new Exception("Server replied with unknown status {$this->status}.");
		}
	}

	/**
	 * A function to abstract away the details of receiving data from the server.
	 * This function populates the $response variable. TODO: write better docs here.
	 */
	private function get_response() {
		$this->response = fread($this->socket, 1024);
		$this->check_status();
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
