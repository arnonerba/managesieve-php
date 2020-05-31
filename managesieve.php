<?php

/**
 * ManageSieve-PHP
 *
 * A PHP client for ManageSieve (RFC 5804). Releases and additional information can be found at
 * https://github.com/arnonerba/managesieve-php.
 *
 * @author arnonerba
 * @package ManageSieve-PHP
 * @version 1.0.0
 */
class ManageSieve {
	private $socket;
	/**
	 * @var string $response       Processed version of the data received from the ManageSieve server
	 * @var string $status         Succinct response code (OK, NO, BYE) that the last command produced
	 * @var string $verbose_status Extra information that came after the response code found in $status
	 * @var bool   $error          Boolean that indicates whether or not the last command was successful
	 * @var array  $scripts        Array of Sieve scripts (names only) that the user has on the server
	 * @var string $active_script  Name of the user's active Sieve script (if one exists)
	 */
	public $response, $status, $verbose_status, $error, $scripts, $active_script;

	/**
	 * Constructor for the ManageSieve class. If it encounters an unrecoverable error it will
	 * throw an exception.
	 *
	 * @param string $hostname       FQDN of the ManageSieve server
	 * @param int    $port           Port the ManageSieve service is running on (generally 4190)
	 * @param string $sasl_mechanism The desired SASL mechanism (i.e. PLAIN, LOGIN)
	 * @param string $username       User to authenticate as
	 * @param string $password       Password of the user $username
	 */
	public function __construct($hostname, $port, $sasl_mechanism, $username, $password) {
		$this->socket = stream_socket_client("tcp://{$hostname}:{$port}");
		if (!$this->socket) {
			throw new Exception('Failed to connect to ManageSieve server.');
		}

		/* Read the intial banner. */
		$this->get_response();

		$this->starttls();

		/* Get the updated banner now that we are using TLS. */
		$this->get_response();

		$this->authenticate($sasl_mechanism, $username, $password);
	}

	/**
	 * Parse the status line returned by the server. This function should only be called from
	 * get_response(). If it encounters an unrecoverable error it will throw an exception. If
	 * successful it will set $status, $verbose_status, and $error.
	 *
	 * @param string $status_line The first line of a possibly multi-line status response
	 */
	private function check_status($status_line) {
		/* The status line should start with a valid status code. */
		$status_line_array = explode(' ', $status_line);
		$this->status = $status_line_array[0];

		/* The rest of the line should contain a verbose status message. */
		array_shift($status_line_array);
		$this->verbose_status = implode(' ', $status_line_array);

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
				throw new Exception("Server replied with unknown status ({$this->status}).");
		}

		/* Some commands return extra verbose status lines. The number of chars to read is enclosed in braces. */
		$start = strpos($this->verbose_status, '{');
		$end = strpos($this->verbose_status, '}');
		if (($start !== false) && ($end !== false)) {
			$length = substr($this->verbose_status, $start + 1, $end - $start - 1);
			unset($this->verbose_status);
			for ($i = 0; $i < $length; $i++) {
				$this->verbose_status .= fgetc($this->socket);
			}
		}
	}

	/**
	 * Get data from the server. This function normalizes line endings and sets $response. The
	 * response is read in a line-by-line fashion so that lengthy responses can be fully captured.
	 */
	private function get_response() {
		/* Ignore various responses that the SASL login routines return. */
		$blacklisted_responses = array('""', '"VXNlcm5hbWU6"', '"UGFzc3dvcmQ6"');
		$line = rtrim(fgets($this->socket), "\r\n");
		if (in_array($line, $blacklisted_responses)) {
			return;
		}

		/* All client queries are replied to with either an OK, NO, or BYE response. */
		while((substr($line, 0, 2) != 'OK') && (substr($line, 0, 2) != 'NO') && (substr($line, 0, 3) != 'BYE')) {
			$response_lines[] = $line;
			$line = rtrim(fgets($this->socket), "\r\n");
		}
		$response_lines[] = $line;

		/* Send the last line of the response data to check_status() for processing. */
		$this->check_status(array_pop($response_lines));
		/* Reconstruct the cleaned response with normalized line breaks. */
		$this->response = implode(PHP_EOL, $response_lines);
	}

	/**
	 * Send data to the server. This function ensures that the required CRLF sequence is always
	 * sent. It also calls get_response() to immediately receive and process the server's response.
	 *
	 * @param string $line The line of text to send to the server
	 */
	private function send_line($line) {
		fwrite($this->socket, "{$line}\r\n");
		$this->get_response();
	}

	/**
	 * Authenticate the user via their chosen SASL authentication mechanism. An exception will
	 * be thrown if the server (or client) does not support the chosen mechanism or if the users'
	 * credentials are incorrect.
	 *
	 * @param string $sasl_mechanism The desired SASL mechanism (i.e. PLAIN, LOGIN)
	 * @param string $username       User to authenticate as
	 * @param string $password       Password of the user $username
	 */
	private function authenticate($sasl_mechanism, $username, $password) {
		switch ($sasl_mechanism) {
			case 'PLAIN':
				$base64_string = base64_encode("\0{$username}\0{$password}");
				$this->send_line("AUTHENTICATE \"PLAIN\" \"{$base64_string}\"");
				if ($this->error) {
					throw new Exception('Bad credentials or server does not support PLAIN.');
				}
				break;
			case 'LOGIN':
				$this->send_line('AUTHENTICATE "LOGIN"');
				$base64_string = base64_encode($username);
				$this->send_line("\"{$base64_string}\"");
				$base64_string = base64_encode($password);
				$this->send_line("\"{$base64_string}\"");
				if ($this->error) {
					throw new Exception('Bad credentials or server does not support LOGIN.');
				}
				break;
			default:
				throw new Exception('Chosen SASL authentication mechanism is unsupported.');
		}
	}

	/**
	 * This function implements the STARTTLS command and negotiates a TLS connection. If it
	 * fails to negotiate a secure connection it will throw an exception.
	 */
	private function starttls() {
		/* PHP 5.6 redefined the CRYPTO_METHOD_* constants. */
		if (defined('STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT')) {
			$crypto_type = STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
		} else {
			$crypto_type = STREAM_CRYPTO_METHOD_TLS_CLIENT;
		}

		$this->send_line('STARTTLS');
		if ($this->error) {
			throw new Exception('Server does not support STARTTLS.');
		}

		if (!stream_socket_enable_crypto($this->socket, true, $crypto_type)) {
			throw new Exception('STARTTLS negotiation failed.');
		}
	}

	/**
	 * This function implements the CAPABILITY command.
	 */
	public function capability() {
		$this->send_line('CAPABILITY');
	}

	/**
	 * This function implements the HAVESPACE command.
	 *
	 * @param string $script The name of a Sieve script
	 * @param int    $length Length of the Sieve script referenced by $script
	 */
	public function have_space($script, $length) {
		$this->send_line("HAVESPACE \"{$script}\" {$length}");
	}

	/**
	 * This function implements the PUTSCRIPT command.
	 *
	 * @param string $script  The name of a Sieve script to upload
	 * @param string $content A Sieve script to upload to the server as $script
	 */
	public function put_script($script, $content) {
		$length = strlen($content);
		$this->have_space($script, $length);
		if (!$this->error) {
			$this->send_line("PUTSCRIPT \"{$script}\" {{$length}+}\r\n{$content}");
		}
	}

	/**
	 * This function implements the LISTSCRIPTS command. If successful it will set $scripts
	 * and $active_script.
	 */
	public function list_scripts() {
		$this->send_line('LISTSCRIPTS');
		if (!$this->error) {
			/* Split the response into an array of strings. */
			$this->scripts = explode(PHP_EOL, $this->response);
			/* Get the active script (if there is one). */
			$this->active_script = implode(array_filter($this->scripts, function($i) { return preg_match('/ \bACTIVE\b$/i', $i); }));
			/* Clean up both $scripts and $active_script. */
			$this->scripts = array_map(function($i) { return trim($i, '"'); }, preg_replace('/ \bACTIVE\b$/i', '', $this->scripts));
			$this->active_script = trim(preg_replace('/ \bACTIVE\b$/i', '', $this->active_script), '"');
		}
	}

	/**
	 * This function implements the SETACTIVE command.
	 *
	 * @param string $script The name of a Sieve script to make active
	 */
	public function set_active($script) {
		$this->send_line("SETACTIVE \"{$script}\"");
	}

	/**
	 * This function implements the GETSCRIPT command.
	 *
	 * @param string $script The name of a Sieve script to retrieve
	 *
	 * @return string The content of the specified Sieve script
	 */
	public function get_script($script) {
		$this->send_line("GETSCRIPT \"{$script}\"");
		/* Return everything except for the script length tag that appears on the first line of the response. */
		return substr($this->response, strpos($this->response, PHP_EOL) + 1);
	}

	/*
	 * This function implements the DELETESCRIPT command.
	 *
	 * @param string $script The name of a Sieve script to delete
	 */
	public function delete_script($script) {
		$this->send_line("DELETESCRIPT \"{$script}\"");
	}

	/*
	 * This function implements the RENAMESCRIPT command.
	 *
	 * @param string $old_script The name of an existing Sieve script to rename
	 * @param string $new_script The desired new name of $old_script
	 */
	public function rename_script($old_script, $new_script) {
		$this->send_line("RENAMESCRIPT \"{$old_script}\" \"{$new_script}\"");
	}

	/*
	 * This function implements the CHECKSCRIPT command.
	 *
	 * @param string $content A Sieve script to check for syntax errors
	 */
	public function check_script($content) {
		$length = strlen($content);
		$this->send_line("CHECKSCRIPT {{$length}+}\r\n{$content}");
	}

	/**
	 * This function implements the NOOP command.
	 */
	public function noop($tag) {
		if ($tag) {
			$this->send_line("NOOP \"{$tag}\"");
		} else {
			$this->send_line('NOOP');
		}
	}

	/**
	 * Destructor for the ManageSieve class. Per the RFC, a LOGOUT command is issued to the server
	 * to close the connection before the socket is shut down.
	 */
	public function __destruct() {
		$this->send_line('LOGOUT');
		stream_socket_shutdown($this->socket, STREAM_SHUT_RDWR);
	}
}
