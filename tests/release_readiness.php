<?php

/* Local IPS integration assertions. This file is never included in the release archive. */

$root = rtrim( (string) getenv( 'FF_IPS_ROOT' ), '/' );
if ( $root === '' || !is_file( $root . '/init.php' ) )
{
	fwrite( STDERR, "Set FF_IPS_ROOT to a local IPS installation.\n" );
	exit( 2 );
}

require $root . '/init.php';

use IPS\forumfortress\Api\Client;
use IPS\Db;
use IPS\Settings;

$original = [
	'ff_api_key' => (string) Settings::i()->ff_api_key,
	'ff_trusted_proxies' => (string) Settings::i()->ff_trusted_proxies,
];
$serverOriginal = [
	'REMOTE_ADDR' => $_SERVER['REMOTE_ADDR'] ?? NULL,
	'HTTP_X_FORWARDED_FOR' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? NULL,
];
$failures = [];
$diagnosticKeyId = md5( 'ff_release_diagnostic_' . bin2hex( random_bytes( 8 ) ) );

$assert = static function ( bool $condition, string $message ) use ( &$failures ): void {
	if ( !$condition )
	{
		$failures[] = $message;
	}
};

try
{
	$plaintext = 'ff_release_readiness_secret';
	Settings::i()->changeValues( [ 'ff_api_key' => $plaintext ] );
	$assert( Client::apiKey() === $plaintext, 'plaintext credential was not readable during migration' );
	$stored = (string) Settings::i()->ff_api_key;
	$assert( $stored !== $plaintext, 'credential remained plaintext in IPS settings' );
	$assert( str_starts_with( $stored, '[!AES' ), 'credential is not stored as an IPS encryption tag' );
	$assert( Client::apiKey() === $plaintext, 'encrypted credential did not round-trip' );
	$assert( Client::controlBaseUrl() === 'https://fortress.ffapi.net', 'control service URL is not fixed to the canonical plugin ingress' );

	foreach ( [
		'https://api.ffapi.net',
		'https://fortress.ffapi.net',
	] as $validUrl )
	{
		try
		{
			Client::validateConfiguredBaseUrl( $validUrl );
		}
		catch ( Throwable $e )
		{
			$failures[] = 'valid endpoint rejected: ' . $validUrl;
		}
	}
	foreach ( [
		'http://api.ffapi.net',
		'http://example.com',
		'http://127.0.0.1:18081',
		'http://192.168.50.10:8080',
		'https://user:password@example.com',
		'https://example.com/?token=secret',
	] as $invalidUrl )
	{
		$rejected = FALSE;
		try
		{
			Client::validateConfiguredBaseUrl( $invalidUrl );
		}
		catch ( DomainException $e )
		{
			$rejected = TRUE;
		}
		$assert( $rejected, 'unsafe endpoint accepted: ' . $invalidUrl );
	}

	Settings::i()->changeValues( [ 'ff_trusted_proxies' => '' ] );
	$_SERVER['REMOTE_ADDR'] = '198.51.100.20';
	$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.40';
	$assert( Client::clientIp() === '198.51.100.20', 'public forwarding header was trusted' );

	Settings::i()->changeValues( [ 'ff_trusted_proxies' => '10.0.0.0/8, 192.168.0.0/16' ] );
	$_SERVER['REMOTE_ADDR'] = '10.0.0.4';
	$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.40, 192.168.1.5';
	$assert( Client::clientIp() === '203.0.113.40', 'trusted proxy chain resolved the wrong client IP' );
	$diagnosticBefore = Client::unprotectedWriteApiClientCount();
	Db::i()->insert( 'core_api_keys', [
		'api_id' => $diagnosticKeyId,
		'api_permissions' => json_encode( [
			'forums/topics/POSTindex' => [ 'access' => TRUE, 'log' => FALSE ],
		] ),
		'api_allowed_ips' => '127.0.0.1',
	] );
	$assert( Client::unprotectedWriteApiClientCount() === $diagnosticBefore + 1, 'write API diagnostic did not detect a REST mutator' );
}
finally
{
	Db::i()->delete( 'core_api_keys', [ 'api_id=?', $diagnosticKeyId ] );
	Settings::i()->changeValues( $original );
	foreach ( $serverOriginal as $key => $value )
	{
		if ( $value === NULL )
		{
			unset( $_SERVER[ $key ] );
		}
		else
		{
			$_SERVER[ $key ] = $value;
		}
	}
}

if ( $failures )
{
	foreach ( $failures as $failure )
	{
		fwrite( STDERR, 'FAIL: ' . $failure . "\n" );
	}
	exit( 1 );
}

echo "Forum Fortress IPS release-readiness assertions: OK\n";
