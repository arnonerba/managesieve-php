# ManageSieve-PHP
An unfinished PHP client for ManageSieve ([RFC 5804](https://tools.ietf.org/html/rfc5804)). This project is loosely based on Dan Ellis's PHP 4-era project, [sieve-php](http://sieve-php.sourceforge.net/). It is also inspired by [ProtonMail/libsieve-php](https://github.com/ProtonMail/libsieve-php) and [zambodaniel/managesieve](https://github.com/zambodaniel/managesieve).

## Usage

## Examples

## Limitations
- Server-side `STARTTLS` support is required. Unencrypted connections are not supported.
- Currently, `PLAIN` and `LOGIN` are the only supported SASL authentication mechanisms.
- The project has only been tested with the Dovecot (Pigeonhole) ManageSieve server.
