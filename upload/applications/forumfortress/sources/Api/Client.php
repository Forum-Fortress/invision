<?php

namespace IPS\forumfortress\Api;

require_once __DIR__ . '/FfApiResilience.php';

use IPS\Application;
use IPS\core\Approval;
use IPS\Db;
use IPS\Log;
use IPS\Request;
use IPS\Settings;
use IPS\Text\Encrypt;
use Throwable;
use function array_map;
use function array_unique;
use function bin2hex;
use function array_values;
use function explode;
use function gmdate;
use function in_array;
use function is_array;
use function is_int;
use function json_decode;
use function json_encode;
use function ksort;
use function max;
use function mb_strpos;
use function microtime;
use function min;
use function parse_url;
use function preg_match_all;
use function random_bytes;
use function register_shutdown_function;
use function round;
use function rtrim;
use function sha1;
use function strtolower;
use function strtoupper;
use function time;
use function trim;
use function usort;
use function mb_substr;
use function method_exists;
use function strcmp;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class Client
{
	public const PLATFORM = 'invision';
	public const PLUGIN_VERSION = '1.4.0';
	public const CONTROL_PLANE_BASE_URL = 'https://fortress.ffapi.net';
	/** Minimum seconds between full hourly sync runs (task + HTTP traffic share this gate). */
	protected const HOURLY_SYNC_MIN_INTERVAL = 540;
	protected const STANDARD_HEARTBEAT_INTERVAL_SECONDS = 3600;
	protected const PRO_HEARTBEAT_INTERVAL_SECONDS = 600;
	protected const ENDPOINT_REFRESH_REQUEST_MAX_DELAY_SECONDS = 60;
	protected const CONNECTION_TEST_TIMEOUT_SECONDS = 2;
	protected const CONNECTION_TEST_TOTAL_BUDGET_SECONDS = 5;
	protected const PLAN_REFRESH_SECONDS = 86400;
	protected const MODERATION_SYNC_SECONDS = 600;
	protected const MODERATION_SYNC_TIMEOUT_SECONDS = 20;
	protected const MAX_API_RESPONSE_BYTES = 1048576;

	protected static bool $moderationSyncInProgress = FALSE;

	protected static bool $lastCheckHadTimeout = FALSE;

	/** @var array<string, mixed>|null */
	protected static ?array $pendingRegisterResult = NULL;
	protected static bool $registerCheckAttempted = FALSE;
	/** @var array<int, bool> */
	protected static array $processedRegistrations = [];
	/** @var array<string, array{response: ?array, timed_out: bool}> */
	protected static array $contentCheckCache = [];
	/** @var array<int, array{response: array<string, mixed>, endpoint: string, reason: string, new: bool, transitioned: bool}> */
	protected static array $pendingContentHolds = [];
	/** Exact portal URL returned by the authenticated control plane in this request. */
	protected static ?string $authenticatedPortalUrl = NULL;
	protected static bool $memberMutationInProgress = FALSE;
	protected static bool $apiKeyMigrationAttempted = FALSE;
	protected static bool $bootstrapTokenMigrationAttempted = FALSE;
	protected static bool $apiKeyDecryptionFailureLogged = FALSE;
	/** @var array<int, bool> */
	protected static array $deferredRegistrationDeletes = [];

	public static function isEnabled(): bool
	{
		return (bool) Settings::i()->ff_enabled;
	}

	/**
	 * Return the Forum Fortress credential in plaintext for an outbound request.
	 * Existing plaintext values are migrated once to IPS authenticated encryption.
	 */
	public static function apiKey(): string
	{
		$stored = trim( (string) ( Settings::i()->ff_api_key ?? '' ) );
		if ( $stored === '' )
		{
			return '';
		}

		if ( str_starts_with( $stored, '[!AES' ) )
		{
			try
			{
				return trim( Encrypt::fromTag( $stored )->decrypt() );
			}
			catch ( Throwable $e )
			{
				if ( !static::$apiKeyDecryptionFailureLogged )
				{
					static::$apiKeyDecryptionFailureLogged = TRUE;
					Log::log( 'Forum Fortress could not decrypt its stored API credential. Reconnect the site from the settings page.', 'forumfortress' );
				}
				return '';
			}
		}

		if ( !static::$apiKeyMigrationAttempted )
		{
			static::$apiKeyMigrationAttempted = TRUE;
			try
			{
				Settings::i()->changeValues( [ 'ff_api_key' => static::encryptApiKeyForStorage( $stored ) ] );
			}
			catch ( Throwable $e )
			{
				Log::log( 'Forum Fortress could not migrate its API credential to encrypted storage.', 'forumfortress' );
			}
		}

		return $stored;
	}

	/** Store a credential using the encryption facility provided by IPS. */
	public static function encryptApiKeyForStorage( string $apiKey ): string
	{
		return static::encryptSecretForStorage( $apiKey );
	}

	/** Encrypt a control-plane bearer credential using the IPS site key. */
	public static function encryptSecretForStorage( string $value ): string
	{
		$value = trim( $value );
		return $value === '' ? '' : Encrypt::fromPlaintext( $value )->tag();
	}

	/** Return the short-lived, domain-bound first-install authorization. */
	protected static function bootstrapToken(): string
	{
		$stored = trim( (string) ( Settings::i()->ff_bootstrap_token ?? '' ) );
		if ( $stored === '' )
		{
			return '';
		}
		if ( str_starts_with( $stored, '[!AES' ) )
		{
			try
			{
				return trim( Encrypt::fromTag( $stored )->decrypt() );
			}
			catch ( Throwable $e )
			{
				return '';
			}
		}
		if ( !static::$bootstrapTokenMigrationAttempted )
		{
			static::$bootstrapTokenMigrationAttempted = TRUE;
			try
			{
				Settings::i()->changeValues( [ 'ff_bootstrap_token' => static::encryptSecretForStorage( $stored ) ] );
			}
			catch ( Throwable $e )
			{
			}
		}
		return $stored;
	}

	public static function apiKeyIsEncrypted(): bool
	{
		$stored = trim( (string) ( Settings::i()->ff_api_key ?? '' ) );
		return $stored === '' || str_starts_with( $stored, '[!AES' );
	}

	public static function baseUrl(): string
	{
		return \FfApiResilience::apiBaseUrlForRegion( static::apiRegion() );
	}

	protected static function apiRegion(): string
	{
		$stored = trim( (string) ( Settings::i()->ff_api_region ?? '' ) );
		return \FfApiResilience::normaliseApiRegion( $stored !== '' ? $stored : \FfApiResilience::apiRegionFromLegacyBaseUrl( (string) ( Settings::i()->ff_api_base_url ?? '' ) ) );
	}

	protected static function allowGlobalEmergencyFallback(): bool
	{
		return !empty( Settings::i()->ff_allow_global_fallback );
	}

	public static function controlBaseUrl(): string
	{
		return static::CONTROL_PLANE_BASE_URL;
	}

	protected static function hotFailoverApiBaseUrl(): string
	{
		$manual = static::normaliseBaseUrl( static::baseUrl() );
		$control = static::normaliseBaseUrl( static::controlBaseUrl() );
		$candidate = static::normaliseBaseUrl( \FfApiResilience::hotFailoverApiBaseUrl( $manual, $control ) );
		if ( $candidate === '' || $candidate === $manual || $candidate === $control )
		{
			return $candidate;
		}

		$candidateHost = strtolower( (string) parse_url( $candidate, PHP_URL_HOST ) );
		foreach ( [ $manual, $control ] as $configured )
		{
			$configuredHost = strtolower( (string) parse_url( $configured, PHP_URL_HOST ) );
			if ( $configuredHost === '' )
			{
				continue;
			}
			if (
				( $configuredHost === 'ffapi.net' || str_ends_with( $configuredHost, '.ffapi.net' ) )
				&& ( $candidateHost === 'ffapi.net' || str_ends_with( $candidateHost, '.ffapi.net' ) )
			)
			{
				return $candidate;
			}
			if ( str_starts_with( $configuredHost, 'control.' ) && $candidateHost === 'api.' . substr( $configuredHost, 8 ) )
			{
				return $candidate;
			}
		}

		/* A custom/on-premises configuration must not silently escape to the
		 * public Forum Fortress service when its own endpoint is unavailable. */
		return '';
	}

	/** @return list<string> */
	protected static function edgeBasesFromState(): array
	{
		$state = static::loadEndpointState();
		$endpointList = is_array( $state['endpoints'] ?? NULL ) ? $state['endpoints'] : [];
		$edges = [];
		foreach ( $endpointList as $row )
		{
			$base = static::normaliseBaseUrl( (string) $row );
			if ( static::isTrustedEndpointBase( $base ) )
			{
				$edges[] = $base;
			}
		}

		return $edges;
	}

	/** @return list<string> */
	protected static function bootstrapBasesOrdered(): array
	{
		return \FfApiResilience::regionLockedCheckBases(
			static::apiRegion(),
			static::allowGlobalEmergencyFallback()
		);
	}

	/** @return list<string> */
	protected static function catalogFetchBases(): array
	{
		return static::bootstrapBasesOrdered();
	}

	/** @return list<string> */
	protected static function controlPlaneRequestBases(): array
	{
		return static::bootstrapBasesOrdered();
	}

	/**
	 * @param list<string> $endpoints
	 * @return list<string>
	 */
	protected static function normalisedEndpointList( array $endpoints ): array
	{
		$normalised = array_values( array_unique( array_map( static fn( $u ) => static::normaliseBaseUrl( (string) $u ), $endpoints ) ) );
		$normalised = array_values( array_filter( $normalised, static fn( $u ) => $u !== '' && static::isTrustedEndpointBase( $u ) ) );
		sort( $normalised );

		return $normalised;
	}

	/**
	 * @param list<string> $previous
	 * @param list<string> $next
	 */
	protected static function endpointCatalogChanged( array $previous, array $next ): bool
	{
		return static::normalisedEndpointList( $previous ) !== static::normalisedEndpointList( $next );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	protected static function invalidateEndpointHealthState( array &$state ): void
	{
		$state['last_health_at'] = 0;
		$state['health_day'] = '';
	}

	protected static function fetchNodeEndpointsCatalog( bool $force = FALSE, ?int $timeoutOverride = NULL ): bool
	{
		$state = static::loadEndpointState();
		$state['endpoints'] = static::bootstrapBasesOrdered();
		$state['catalog_fetched_at'] = 0;
		unset( $state['endpoint_meta'], $state['control_check_fallback'] );
		static::saveEndpointState( $state );

		return TRUE;
	}

	public static function refreshEndpointCatalogIfStale(): bool
	{
		if ( !static::isEnabled() || static::normaliseBaseUrl( static::baseUrl() ) === '' )
		{
			return TRUE;
		}

		return static::fetchNodeEndpointsCatalog( FALSE );
	}

	protected static function maybeRefreshEndpointCatalogAfterCheckIn( string $requestPath ): void
	{
		if ( !\FfApiResilience::shouldRefreshEndpointCatalogOnCheckIn( $requestPath ) )
		{
			return;
		}

		static::refreshEndpointCatalogIfStale();
	}

	protected static function isCatalogBackupRole( ?string $role ): bool
	{
		$role = strtolower( trim( (string) $role ) );

		return in_array( $role, [ 'backup', 'control-fallback', 'control' ], TRUE );
	}

	protected static function isCatalogBackupEndpointUrl( string $baseUrl, ?string $role = NULL ): bool
	{
		if ( static::isCatalogBackupRole( $role ) )
		{
			return TRUE;
		}
		$control = static::normaliseBaseUrl( static::controlBaseUrl() );

		return $control !== '' && static::normaliseBaseUrl( $baseUrl ) === $control;
	}

	protected static function isSharedApiRoundRobinBase( string $baseUrl ): bool
	{
		$manual = static::normaliseBaseUrl( static::baseUrl() );
		$baseUrl = static::normaliseBaseUrl( $baseUrl );
		if ( $manual === '' || $baseUrl !== $manual )
		{
			return FALSE;
		}
		$host = parse_url( $manual, PHP_URL_HOST );

		return is_string( $host ) && strpos( strtolower( $host ), 'api.' ) === 0;
	}

	protected static function normaliseBaseUrl( string $value ): string
	{
		$value = rtrim( trim( $value ), '/' );
		$parts = parse_url( $value );
		if (
			!is_array( $parts )
			|| strtolower( (string) ( $parts['scheme'] ?? '' ) ) !== 'https'
			|| trim( (string) ( $parts['host'] ?? '' ) ) === ''
			|| isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['query'] )
			|| isset( $parts['fragment'] )
		)
		{
			return '';
		}

		return $value;
	}

	public static function validateConfiguredBaseUrl( string $value ): void
	{
		$value = trim( $value );
		if ( $value === '' )
		{
			return;
		}
		$parts = parse_url( $value );
		if (
			!is_array( $parts )
			|| strtolower( (string) ( $parts['scheme'] ?? '' ) ) !== 'https'
			|| trim( (string) ( $parts['host'] ?? '' ) ) === ''
			|| isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['query'] )
			|| isset( $parts['fragment'] )
		)
		{
			throw new \DomainException( 'forumfortress_invalid_base_url' );
		}
		if ( !static::endpointTransportIsSafe( $parts ) )
		{
			throw new \DomainException( 'forumfortress_insecure_base_url' );
		}
	}

	public static function validatePreferredEndpoint( string $preferred, string $apiBase, string $controlBase ): void
	{
		$preferred = static::normaliseBaseUrl( $preferred );
		if ( $preferred === '' )
		{
			return;
		}
		static::validateConfiguredBaseUrl( $preferred );
		$candidate = parse_url( $preferred );
		if ( !is_array( $candidate ) )
		{
			throw new \DomainException( 'forumfortress_invalid_preferred_endpoint' );
		}
		$candidateHost = strtolower( trim( (string) ( $candidate['host'] ?? '' ) ) );

		foreach ( [ $apiBase, $controlBase ] as $configured )
		{
			$parts = parse_url( static::normaliseBaseUrl( $configured ) );
			if ( !is_array( $parts ) )
			{
				continue;
			}
			$host = strtolower( trim( (string) ( $parts['host'] ?? '' ) ) );
			if (
				$candidateHost === $host
				&& strtolower( (string) ( $candidate['scheme'] ?? '' ) ) === strtolower( (string) ( $parts['scheme'] ?? '' ) )
				&& static::effectiveEndpointPort( $candidate ) === static::effectiveEndpointPort( $parts )
			)
			{
				return;
			}
			if (
				( $host === 'ffapi.net' || str_ends_with( $host, '.ffapi.net' ) )
				&& ( $candidateHost === 'ffapi.net' || str_ends_with( $candidateHost, '.ffapi.net' ) )
				&& strtolower( (string) ( $candidate['scheme'] ?? '' ) ) === 'https'
				&& static::effectiveEndpointPort( $candidate ) === 443
			)
			{
				return;
			}
		}

		throw new \DomainException( 'forumfortress_invalid_preferred_endpoint' );
	}

	/**
	 * Portal launch responses contain a bearer token in the query string. Never
	 * send that token to an arbitrary origin supplied by an API response.
	 */
	public static function isTrustedPortalUrl( string $value ): bool
	{
		$value = trim( $value );
		if ( $value === '' || filter_var( $value, FILTER_VALIDATE_URL ) === FALSE )
		{
			return FALSE;
		}
		$parts = parse_url( $value );
		if (
			!is_array( $parts )
			|| strtolower( (string) ( $parts['scheme'] ?? '' ) ) !== 'https'
			|| trim( (string) ( $parts['host'] ?? '' ) ) === ''
			|| isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['fragment'] )
			|| !static::endpointTransportIsSafe( $parts )
		)
		{
			return FALSE;
		}

		$scheme = strtolower( (string) $parts['scheme'] );
		$host = strtolower( trim( (string) $parts['host'] ) );
		$path = '/' . ltrim( (string) ( $parts['path'] ?? '' ), '/' );
		$query = [];
		parse_str( (string) ( $parts['query'] ?? '' ), $query );
		if (
			rtrim( $path, '/' ) === '/access'
			&& isset( $query['token'] )
			&& is_string( $query['token'] )
			&& trim( $query['token'] ) !== ''
		)
		{
			$expectedHosts = static::expectedPortalHosts();
			if (
				static::effectiveEndpointPort( $parts ) === 443
				&& $scheme === 'https'
				&& static::matchesExpectedPortalHost( $host, $expectedHosts )
			)
			{
				return TRUE;
			}

			/* A custom/on-prem origin is accepted only when this exact bearer URL was
			 * returned by portalLaunch() over the authenticated API transport during
			 * the current request. Arbitrary caller-supplied HTTPS URLs remain denied. */
			if (
				static::$authenticatedPortalUrl !== NULL
				&& hash_equals( static::$authenticatedPortalUrl, $value )
			)
			{
				return TRUE;
			}
		}

		if (
			$scheme !== 'http'
		)
		{
			return FALSE;
		}

		/* Exact-origin exceptions support the configured private development API
		 * and the local IPS lifecycle fixture without trusting a public redirect. */
		foreach ( [ static::baseUrl(), static::controlBaseUrl(), (string) ( Settings::i()->base_url ?? '' ) ] as $configured )
		{
			$configuredParts = parse_url( static::normaliseBaseUrl( $configured ) );
			if ( !is_array( $configuredParts ) || !static::endpointTransportIsSafe( $configuredParts ) )
			{
				continue;
			}
			if (
				$host === strtolower( trim( (string) ( $configuredParts['host'] ?? '' ) ) )
				&& $scheme === strtolower( (string) ( $configuredParts['scheme'] ?? '' ) )
				&& static::effectiveEndpointPort( $parts ) === static::effectiveEndpointPort( $configuredParts )
			)
			{
				return TRUE;
			}
		}

		return FALSE;
	}

	protected static function expectedPortalHosts(): array
	{
		$hosts = [];
		foreach ( [ static::normaliseBaseUrl( static::baseUrl() ), static::normaliseBaseUrl( static::controlBaseUrl() ) ] as $base )
		{
			$host = static::normalisePortalHostFromBase( $base );
			if ( $host !== '' )
			{
				$hosts[] = $host;
			}
		}
		return array_values( array_unique( $hosts ) );
	}

	protected static function normalisePortalHostFromBase( string $base ): string
	{
		if ( $base === '' )
		{
			return '';
		}
		$parts = parse_url( $base );
		if ( !is_array( $parts ) )
		{
			return '';
		}
		$host = strtolower( trim( (string) ( $parts['host'] ?? '' ) ) );
		if ( $host === '' )
		{
			return '';
		}
		if ( strpos( $host, 'api.' ) === 0 )
		{
			return substr( $host, 4 );
		}
		if ( strpos( $host, 'control.' ) === 0 )
		{
			return 'portal.' . substr( $host, 8 );
		}
		if ( $host === 'fortress.ffapi.net' )
		{
			return 'portal.ffapi.net';
		}
		return $host;
	}

	protected static function matchesExpectedPortalHost( string $host, array $expectedHosts ): bool
	{
		if ( $host === '' )
		{
			return FALSE;
		}
		foreach ( $expectedHosts as $expected )
		{
			if ( $host === strtolower( trim( (string) $expected ) ) )
			{
				return TRUE;
			}
		}
		return FALSE;
	}

	/** Every plugin endpoint uses TLS, including local and private origins. */
	protected static function endpointTransportIsSafe( array $parts ): bool
	{
		return strtolower( trim( (string) ( $parts['scheme'] ?? '' ) ) ) === 'https';
	}

	protected static function effectiveEndpointPort( array $parts ): int
	{
		if ( isset( $parts['port'] ) )
		{
			return (int) $parts['port'];
		}

		return strtolower( (string) ( $parts['scheme'] ?? '' ) ) === 'https' ? 443 : 80;
	}

	/** Catalog entries are untrusted input and must not become arbitrary SSRF targets. */
	protected static function isTrustedEndpointBase( string $baseUrl ): bool
	{
		$parts = parse_url( static::normaliseBaseUrl( $baseUrl ) );
		if ( !is_array( $parts ) || strtolower( (string) ( $parts['scheme'] ?? '' ) ) !== 'https' )
		{
			return FALSE;
		}
		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) || isset( $parts['query'] ) || isset( $parts['fragment'] ) )
		{
			return FALSE;
		}
		if ( !static::endpointTransportIsSafe( $parts ) )
		{
			return FALSE;
		}
		$host = strtolower( trim( (string) ( $parts['host'] ?? '' ) ) );
		if ( $host === '' )
		{
			return FALSE;
		}

		foreach ( [ static::baseUrl(), static::controlBaseUrl(), static::hotFailoverApiBaseUrl() ] as $configured )
		{
			$configuredParts = parse_url( static::normaliseBaseUrl( $configured ) );
			if ( !is_array( $configuredParts ) )
			{
				continue;
			}
			$configuredHost = strtolower( trim( (string) ( $configuredParts['host'] ?? '' ) ) );
			if (
				$configuredHost !== ''
				&& $host === $configuredHost
				&& strtolower( (string) ( $parts['scheme'] ?? '' ) ) === strtolower( (string) ( $configuredParts['scheme'] ?? '' ) )
				&& static::effectiveEndpointPort( $parts ) === static::effectiveEndpointPort( $configuredParts )
			)
			{
				return TRUE;
			}
			if ( $configuredHost === 'ffapi.net' || str_ends_with( $configuredHost, '.ffapi.net' ) )
			{
				if (
					( $host === 'ffapi.net' || str_ends_with( $host, '.ffapi.net' ) )
					&& strtolower( (string) ( $parts['scheme'] ?? '' ) ) === 'https'
					&& static::effectiveEndpointPort( $parts ) === 443
				)
				{
					return TRUE;
				}
			}
		}

		return FALSE;
	}

	public static function forumDomain(): string
	{
		$base = Settings::i()->base_url;
		$host = parse_url( (string) $base, PHP_URL_HOST );

		if ( $host )
		{
			return \FfApiResilience::normaliseDomain( static::stripHostPort( (string) $host ) );
		}

		$fallback = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';

		return \FfApiResilience::normaliseDomain( static::stripHostPort( (string) $fallback ) );
	}

	/**
	 * Resolve the client IP without trusting public forwarding headers. XFF is
	 * used only when REMOTE_ADDR matches an explicitly configured proxy/CIDR.
	 */
	public static function clientIp(): string
	{
		$remote = trim( (string) ( $_SERVER['REMOTE_ADDR'] ?? '' ) );
		if ( filter_var( $remote, FILTER_VALIDATE_IP ) === FALSE )
		{
			return '0.0.0.0';
		}
		$trusted = array_values( array_filter( array_map( 'trim', explode( ',', (string) ( Settings::i()->ff_trusted_proxies ?? '' ) ) ) ) );
		if ( !$trusted || !static::ipMatchesAnyRange( $remote, $trusted ) )
		{
			return $remote;
		}

		$chain = [];
		foreach ( explode( ',', (string) ( $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '' ) ) as $candidate )
		{
			$candidate = trim( $candidate );
			if ( filter_var( $candidate, FILTER_VALIDATE_IP ) !== FALSE )
			{
				$chain[] = $candidate;
			}
		}
		$chain[] = $remote;
		for ( $index = count( $chain ) - 1; $index >= 0; $index-- )
		{
			if ( !static::ipMatchesAnyRange( $chain[ $index ], $trusted ) )
			{
				return $chain[ $index ];
			}
		}
		return $chain[0] ?? $remote;
	}

	public static function validateTrustedProxies( string $value ): void
	{
		foreach ( array_filter( array_map( 'trim', explode( ',', $value ) ) ) as $range )
		{
			[ $network, $prefix ] = array_pad( explode( '/', $range, 2 ), 2, NULL );
			$packed = @inet_pton( trim( (string) $network ) );
			$maximum = $packed === FALSE ? 0 : strlen( $packed ) * 8;
			if (
				$packed === FALSE
				|| ( $prefix !== NULL && ( !ctype_digit( $prefix ) || (int) $prefix > $maximum ) )
			)
			{
				throw new \DomainException( 'forumfortress_invalid_trusted_proxy' );
			}
		}
	}

	/** @param list<string> $ranges */
	protected static function ipMatchesAnyRange( string $ip, array $ranges ): bool
	{
		$packedIp = @inet_pton( $ip );
		if ( $packedIp === FALSE )
		{
			return FALSE;
		}
		foreach ( $ranges as $range )
		{
			[ $network, $prefix ] = array_pad( explode( '/', $range, 2 ), 2, NULL );
			$packedNetwork = @inet_pton( trim( (string) $network ) );
			if ( $packedNetwork === FALSE || strlen( $packedNetwork ) !== strlen( $packedIp ) )
			{
				continue;
			}
			$bits = $prefix === NULL ? strlen( $packedIp ) * 8 : (int) $prefix;
			if ( $bits < 0 || $bits > strlen( $packedIp ) * 8 )
			{
				continue;
			}
			$bytes = intdiv( $bits, 8 );
			$remainder = $bits % 8;
			if ( substr( $packedIp, 0, $bytes ) !== substr( $packedNetwork, 0, $bytes ) )
			{
				continue;
			}
			if ( $remainder > 0 )
			{
				$mask = ( 0xFF << ( 8 - $remainder ) ) & 0xFF;
				if ( ( ord( $packedIp[ $bytes ] ) & $mask ) !== ( ord( $packedNetwork[ $bytes ] ) & $mask ) )
				{
					continue;
				}
			}
			return TRUE;
		}
		return FALSE;
	}

	protected static function bootstrapDomain(): string
	{
		$state = static::loadEndpointState();
		$canonical = trim( (string) ( $state['offline_canonical_domain'] ?? '' ) );

		return $canonical !== '' ? $canonical : static::forumDomain();
	}

	protected static function isOfflineApiKey(): bool
	{
		return \FfApiResilience::isOfflineBootstrapKey( static::apiKey(), NULL );
	}

	/**
	 * Align domain with forum_domains / API validation (no :port on host; IPv6 bracket hosts supported).
	 */
	protected static function stripHostPort( string $host ): string
	{
		$host = trim( $host );
		if ( $host === '' || mb_strpos( $host, ':' ) === FALSE )
		{
			return $host;
		}
		if ( isset( $host[0] ) && $host[0] === '[' )
		{
			$end = mb_strpos( $host, ']:' );
			if ( $end !== FALSE )
			{
				return strtolower( substr( $host, 1, $end - 1 ) );
			}

			return strtolower( $host );
		}
		$parsed = parse_url( 'http://' . $host );
		if ( !empty( $parsed['host'] ) )
		{
			return strtolower( (string) $parsed['host'] );
		}

		return strtolower( $host );
	}

	public static function bootstrapIfNeeded(): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}
		if ( static::apiKey() !== '' )
		{
			if ( trim( (string) Settings::i()->ff_site_id ) === '' )
			{
				return static::siteStatus( self::CONNECTION_TEST_TIMEOUT_SECONDS );
			}
			return NULL;
		}

		if ( !static::bootstrapBasesOrdered() )
		{
			return NULL;
		}

		$timeout = max( 1, (int) Settings::i()->ff_timeout );
		$result = static::tryBootstrapAcrossBases( static::bootstrapBasesOrdered(), $timeout );

		if ( $result )
		{
			$response = $result['data'];
			$usedBase = $result['base'];
			static::persistIdentity( $response, $usedBase );
			/* The authorization is single-use. Remove its encrypted local copy as
			 * soon as the authenticated site credential has been persisted. */
			Settings::i()->changeValues( [ 'ff_bootstrap_token' => '' ] );
			$state = static::loadEndpointState();
			$state['last_responded'] = $usedBase;
			$state['last_responded_node'] = $result['node_header'];
			$state['last_response_at'] = time();
			static::saveEndpointState( $state );

			return $response;
		}

		return NULL;
	}

	/**
	 * @param list<string> $bases
	 * @return array{data: array<string, mixed>, base: string, node_header: string}|null
	 */
	protected static function tryBootstrapAcrossBases( array $bases, int $timeout ): ?array
	{
		$offlineMigration = static::isOfflineApiKey();
		$endpointState = $offlineMigration ? static::loadEndpointState() : [];
		$payload = [
			'domain' => static::bootstrapDomain(),
			'platform' => static::PLATFORM,
			'platform_version' => Application::load( 'core' )->version,
			'plugin_version' => static::PLUGIN_VERSION,
			'bootstrap_token' => static::bootstrapToken() ?: NULL,
			'api_key' => static::apiKey() ?: NULL,
			'offline_issuer_node_id' => $offlineMigration
				? ( trim( (string) ( $endpointState['issuer_node_id'] ?? '' ) ) ?: NULL )
				: NULL,
			'offline_site_id' => $offlineMigration
				? ( trim( (string) Settings::i()->ff_site_id ) ?: NULL )
				: NULL,
		];
		foreach ( $bases as $base )
		{
			$raw = static::rawRequest( 'POST', (string) $base, '/v1/site/bootstrap', $payload, $timeout );
			$status = (int) ( $raw['status'] ?? 0 );
			$data = is_array( $raw['data'] ?? NULL ) ? $raw['data'] : NULL;
			if ( $status >= 200 && $status < 300 && is_array( $data ) && !empty( $data['api_key'] ) )
			{
				return [
					'data' => $data,
					'base' => static::normaliseBaseUrl( (string) $base ),
					'node_header' => trim( (string) ( $raw['node_header'] ?? '' ) ),
				];
			}
		}

		return NULL;
	}

	public static function ensureIdentity(): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		$key = static::apiKey();
		$siteId = trim( (string) Settings::i()->ff_site_id );

		if ( $key === '' )
		{
			$boot = static::bootstrapIfNeeded();
			if ( $boot !== NULL && !empty( $boot['api_key'] ) )
			{
				static::refreshEndpointCatalogAndHealth( TRUE, self::CONNECTION_TEST_TIMEOUT_SECONDS );
			}
			return $boot;
		}

		if ( $siteId === '' )
		{
			return static::siteStatus( self::CONNECTION_TEST_TIMEOUT_SECONDS );
		}

		static::refreshEndpointCatalogAndHealth( FALSE, self::CONNECTION_TEST_TIMEOUT_SECONDS );

		return NULL;
	}

	/**
	 * @return array{data: array<string, mixed>, base: string, node_header: string}|null
	 */
	protected static function tryOfflineFailoverRebootstrap( ?int $timeoutOverride = NULL ): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}
		$state = static::loadEndpointState();
		$bases = !empty( $state['offline_pinned'] )
			? \FfApiResilience::offlineRebootstrapBases(
				$state,
				static::controlBaseUrl(),
				static::hotFailoverApiBaseUrl(),
				static::edgeBasesFromState(),
				static::baseUrl()
			)
			: static::bootstrapBasesOrdered();
		$result = static::tryBootstrapAcrossBases(
			$bases,
			max( 1, $timeoutOverride ?? (int) Settings::i()->ff_timeout )
		);
		if ( !$result )
		{
			return NULL;
		}

		static::persistIdentity( $result['data'], $result['base'] );
		$state = static::loadEndpointState();
		$state['last_responded'] = $result['base'];
		$state['last_responded_node'] = $result['node_header'];
		$state['last_response_at'] = time();
		static::saveEndpointState( $state );

		return $result;
	}

	public static function maybeMigrateFromOfflineBootstrap(): void
	{
		if ( !static::isEnabled() || !static::isOfflineApiKey() )
		{
			return;
		}
		$state = static::loadEndpointState();
		if ( !\FfApiResilience::shouldRebootstrapOfflineNow( $state ) )
		{
			return;
		}

		if ( static::tryOfflineFailoverRebootstrap() )
		{
			return;
		}

		/* A failed migration must retain the working regional key and route pin. */
		$state = static::loadEndpointState();
		if ( !empty( $state['offline_pinned'] ) )
		{
			$state['offline_rebootstrap_at'] = time() + 600;
			static::saveEndpointState( $state );
		}
	}

	public static function checkRegisterFromRequest(): ?array
	{
		static::bootstrapIfNeeded();

		$username = (string) Request::i()->username;
		$email = (string) Request::i()->email_address;
		$payload = [
			'ip' => static::clientIp(),
			'username' => $username,
			'email' => $email,
			'email_domain' => static::emailDomain( $email ),
			'user_agent' => (string) ( Request::i()->userAgent() ?? '' ),
			'account_age_seconds' => 0,
			'post_count' => 0,
			'content' => NULL,
			'links' => [],
		];

		return static::checkRegisterPayload( $payload );
	}

	public static function checkRegisterPayload( array $payload ): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		static::$registerCheckAttempted = TRUE;
		static::$lastCheckHadTimeout = FALSE;
		$prepared = static::withCheckRequestId( static::preparePayload( $payload ) );
		$timeout = max( 1, min( 30, (int) Settings::i()->ff_timeout ) );

		$response = static::request( 'POST', '/v1/check/register', $prepared, $timeout );
		if ( is_array( $response ) && !static::hasDefinitiveCheckDecision( $response ) && strtoupper( (string) ( $response['status_code'] ?? '' ) ) !== 'ABOVELIMIT' )
		{
			$response = NULL;
		}
		static::$pendingRegisterResult = [
			'response' => $response,
			'payload' => $prepared,
			'timed_out' => static::$lastCheckHadTimeout,
		];
		if ( is_array( $response ) )
		{
			static::maybeRefreshEndpointCatalogAfterCheckIn( '/v1/check/register' );
		}

		return $response;
	}

	public static function lastCheckHadTimeout(): bool
	{
		return static::$lastCheckHadTimeout;
	}

	/**
	 * Finish the check after IPS has assigned the member ID. This also covers
	 * social/OAuth account creation, which bypasses the registration form.
	 */
	public static function completeRegistrationCheck( \IPS\Member $member ): void
	{
		$memberId = (int) $member->member_id;
		if ( !static::isEnabled() || $memberId <= 0 || isset( static::$processedRegistrations[ $memberId ] ) )
		{
			return;
		}
		static::$processedRegistrations[ $memberId ] = TRUE;

		$result = static::$pendingRegisterResult;
		static::$pendingRegisterResult = NULL;
		if ( !static::$registerCheckAttempted || !is_array( $result ) )
		{
			$payload = static::memberCheckPayload( $member );
			$response = static::checkRegisterPayload( $payload );
			$result = static::$pendingRegisterResult ?? [
				'response' => $response,
				'payload' => $payload,
				'timed_out' => static::$lastCheckHadTimeout,
			];
			static::$pendingRegisterResult = NULL;
		}

		$response = is_array( $result['response'] ?? NULL ) ? $result['response'] : NULL;
		$timedOut = !empty( $result['timed_out'] );
		$decision = strtolower( trim( (string) ( $response['decision'] ?? '' ) ) );
		$statusCode = strtoupper( trim( (string) ( $response['status_code'] ?? '' ) ) );

		/* A definitive API decision always outranks availability policy from an
		 * earlier failed endpoint in the same failover pass. */
		if ( $decision === 'block' )
		{
			static::applyBlockedRegistrationAction( $member, $response, 'Forum Fortress block: registration rejected' );
			return;
		}
		if ( $timedOut && Settings::i()->ff_fail_open )
		{
			static::reportRegister( $member );
			return;
		}
		if ( ( $response === NULL || $statusCode === 'ABOVELIMIT' ) && !Settings::i()->ff_fail_open )
		{
			static::applyBlockedRegistrationAction( $member, $response ?? [], 'Forum Fortress unavailable: registration rejected' );
			return;
		}

		static::reportRegister( $member );
	}

	/**
	 * @param array<string, mixed> $response
	 */
	public static function registrationBlockAction(): string
	{
		$action = strtolower( trim( (string) ( Settings::i()->ff_registration_block_action ?? 'reject' ) ) );
		return in_array( $action, [ 'reject', 'delete' ], TRUE ) ? $action : 'reject';
	}

	/** @param array<string, mixed> $response */
	protected static function applyBlockedRegistrationAction( \IPS\Member $member, array $response, string $reason ): void
	{
		if ( static::registrationBlockAction() === 'delete' )
		{
			static::deleteBlockedRegistration( $member );
			return;
		}
		if ( !static::holdMemberForReview( $member, $response, $reason, TRUE ) )
		{
			/* A rejected account must never become active merely because the
			 * native validation hold failed. Deletion is the safe final fallback. */
			try
			{
				static::deleteBlockedRegistration( $member );
			}
			catch ( Throwable $e )
			{
				Log::log( 'Forum Fortress could not enforce a blocked registration after validation-hold failure.', 'forumfortress' );
			}
		}
	}

	/** Delete a blocked registration without allowing an OAuth login to finish. */
	protected static function deleteBlockedRegistration( \IPS\Member $member ): void
	{
		$requestUri = (string) ( $_SERVER['REQUEST_URI'] ?? '' );
		/* IPS first accepts the friendly callback and then redirects to its native
		 * login processor, where the member is actually created. Recognize both
		 * requests so a blocked OAuth account never reaches an authenticated
		 * response. The code parameter distinguishes OAuth from other login forms. */
		$isOAuthRegistration = str_contains( $requestUri, '/oauth/callback/' )
			|| ( str_contains( $requestUri, '_processLogin=' ) && str_contains( $requestUri, 'code=' ) );
		if ( $isOAuthRegistration )
		{
			/* The native exception prevents an authenticated response. IPS catches it
			 * inside the login handler and can still write link/history/device rows,
			 * so also clean anything it writes after the native member deletion. */
			static::deleteMemberAfterRegistrationCompletes( $member );
			$member->delete();
			throw new \IPS\Login\Exception(
				'forumfortress_registration_blocked',
				\IPS\Login\Exception::REGISTRATION_DENIED_BY_SPAM_SERVICE,
				NULL,
				$member
			);
		}

		static::deleteMemberAfterRegistrationCompletes( $member );
	}

	/**
	 * IPS fires onCreateAccount from Member::save(), before an OAuth handler has
	 * written its login link, history and device records. Deleting synchronously
	 * leaves those later writes orphaned. Defer the native member deletion until
	 * the request has finished building the account so IPS can clean all related
	 * records in one lifecycle operation before the redirect is followed.
	 */
	protected static function deleteMemberAfterRegistrationCompletes( \IPS\Member $member ): void
	{
		$memberId = (int) $member->member_id;
		if ( $memberId <= 0 || isset( static::$deferredRegistrationDeletes[ $memberId ] ) )
		{
			return;
		}
		static::$deferredRegistrationDeletes[ $memberId ] = TRUE;

		register_shutdown_function( static function () use ( $memberId ): void {
			try
			{
				if ( (int) Db::i()->select( 'COUNT(*)', 'core_members', [ 'member_id=?', $memberId ] )->first() )
				{
					$memberToDelete = \IPS\Member::load( $memberId );
					if ( (int) $memberToDelete->member_id === $memberId )
					{
						$memberToDelete->delete();
					}
				}
				if ( !(int) Db::i()->select( 'COUNT(*)', 'core_members', [ 'member_id=?', $memberId ] )->first() )
				{
					static::cleanupOrphanedRegistrationRows( $memberId );
				}
				else
				{
					Log::log( 'Forum Fortress could not delete a blocked registration after account creation completed.', 'forumfortress' );
				}
			}
			catch ( Throwable $e )
			{
				Log::log( 'Forum Fortress could not finish deleting a blocked registration.', 'forumfortress' );
			}
		} );
	}

	/** Remove account-creation metadata written after a blocked member was deleted. */
	protected static function cleanupOrphanedRegistrationRows( int $memberId ): void
	{
		$memberTables = [
			[ 'core_pfields_content', 'member_id' ],
			[ 'core_login_links', 'token_member' ],
			[ 'core_member_history', 'log_member' ],
			[ 'core_members_known_devices', 'member_id' ],
			[ 'core_members_known_ip_addresses', 'member_id' ],
			[ 'core_members_logins', 'member_id' ],
			[ 'core_sessions', 'member_id' ],
		];
		foreach ( $memberTables as [ $table, $column ] )
		{
			try
			{
				Db::i()->delete( $table, [ "{$column}=?", $memberId ] );
			}
			catch ( Throwable $e )
			{
				Log::log( "Forum Fortress could not remove blocked-registration metadata from {$table}.", 'forumfortress' );
			}
		}
		static::deleteOwnedMemberValidationRows( $memberId );
	}

	public static function holdMemberForReview( \IPS\Member $member, array $response, string $reason = 'Forum Fortress block: review required', bool $registrationRejected = FALSE ): bool
	{
		if ( !$member->member_id )
		{
			return FALSE;
		}
		$decisionId = (int) ( $response['decision_id'] ?? 0 );
		$decisionReference = (string) ( $response['decision_reference'] ?? '' );
		/* IC5's approval queue accepts Content and Clubs, not Member. Rejected
		 * registrations belong in the native validating-members workflow. Profile
		 * checks already remove the rejected field value and do not manufacture a
		 * second registration for an established member. */
		if ( !$registrationRejected )
		{
			Log::log( 'Forum Fortress removed a blocked member profile value.', 'forumfortress' );
			return TRUE;
		}

		$restrictionApplied = FALSE;
		$banApplied = FALSE;
		$held = [
			'member' => TRUE,
			'name' => (string) $member->name,
			'title' => 'Registration rejected (Forum Fortress)',
			'content' => '',
			'forum_fortress' => [
				'decision_id' => $decisionId > 0 ? $decisionId : NULL,
				'decision_reference' => $decisionReference !== '' ? $decisionReference : NULL,
				'moderation_state' => 'registration_rejected',
				'restriction_applied' => $restrictionApplied,
				'ban_applied' => $banApplied,
				'endpoint' => 'register',
				'public_reason' => $reason,
				'check_payload' => is_array( $response['check_payload'] ?? NULL ) ? $response['check_payload'] : NULL,
			],
		];

		try
		{
			/* This in-memory override is consumed later in the same IC5 registration
			 * request by Member::postRegistration(); it is not persisted globally. */
			Settings::i()->reg_auth_type = 'admin';
			$memberId = (int) $member->member_id;
			register_shutdown_function( static function () use ( $memberId, $held ): void {
				try
				{
					static::upsertNativeMemberValidationHold( $memberId, $held );
				}
				catch ( Throwable $e )
				{
					Log::log( 'Forum Fortress could not finalize a rejected registration hold.', 'forumfortress' );
				}
			} );
			return TRUE;
		}
		catch ( Throwable $e )
		{
			Log::log( 'Forum Fortress could not hold registration for review: ' . $e->getMessage(), 'forumfortress' );
			return FALSE;
		}
	}

	/** @param array<string, mixed> $held */
	protected static function upsertNativeMemberValidationHold( int $memberId, array $held ): bool
	{
		if ( $memberId <= 0 || !(int) Db::i()->select( 'COUNT(*)', 'core_members', [ 'member_id=?', $memberId ] )->first() )
		{
			return FALSE;
		}

		$member = \IPS\Member::load( $memberId );
		static::$memberMutationInProgress = TRUE;
		try
		{
			$member->members_bitoptions['validating'] = TRUE;
			$member->save();
		}
		finally
		{
			static::$memberMutationInProgress = FALSE;
		}

		$extra = json_encode( $held, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE );
		if ( !is_string( $extra ) )
		{
			throw new \RuntimeException( 'Unable to encode Forum Fortress validation metadata' );
		}
		$rows = iterator_to_array( Db::i()->select( '*', 'core_validating', [
			'member_id=? AND new_reg=?',
			$memberId,
			1,
		], 'entry_date DESC' ), FALSE );
		if ( isset( $rows[0]['vid'] ) )
		{
			Db::i()->update( 'core_validating', [
				'spam_flag' => 2,
				'user_verified' => 1,
				'do_not_delete' => 1,
				'extra' => $extra,
			], [ 'vid=? AND member_id=?', (string) $rows[0]['vid'], $memberId ] );
			return TRUE;
		}

		$plainSecurityKey = bin2hex( random_bytes( 32 ) );
		Db::i()->insert( 'core_validating', [
			'vid' => bin2hex( random_bytes( 16 ) ),
			'member_id' => $memberId,
			'entry_date' => time(),
			'new_reg' => 1,
			'ip_address' => trim( (string) $member->ip_address ) ?: static::clientIp(),
			'spam_flag' => 2,
			'user_verified' => 1,
			'email_sent' => NULL,
			'do_not_delete' => 1,
			'extra' => $extra,
			'security_key' => Encrypt::fromPlaintext( $plainSecurityKey )->tag(),
		] );
		return TRUE;
	}

	/** @return array<string, mixed>|null */
	protected static function ownedMemberValidationMetadata( array $row ): ?array
	{
		if ( (int) ( $row['spam_flag'] ?? 0 ) !== 2 || (int) ( $row['new_reg'] ?? 0 ) !== 1 )
		{
			return NULL;
		}
		$extra = json_decode( (string) ( $row['extra'] ?? '' ), TRUE );
		return is_array( $extra['forum_fortress'] ?? NULL ) ? $extra : NULL;
	}

	protected static function deleteOwnedMemberValidationRows( int $memberId ): void
	{
		if ( $memberId <= 0 )
		{
			return;
		}
		try
		{
			foreach ( Db::i()->select( '*', 'core_validating', [ 'member_id=?', $memberId ] ) as $row )
			{
				if ( static::ownedMemberValidationMetadata( $row ) !== NULL )
				{
					Db::i()->delete( 'core_validating', [ 'vid=? AND member_id=?', (string) $row['vid'], $memberId ] );
				}
			}
		}
		catch ( Throwable $e )
		{
			Log::log( 'Forum Fortress could not remove owned validation metadata.', 'forumfortress' );
		}
	}

	/** @return array<string, mixed> */
	protected static function memberCheckPayload( \IPS\Member $member ): array
	{
		$email = trim( (string) $member->email );
		return [
			'ip' => static::clientIp(),
			'username' => (string) $member->name,
			'email' => $email,
			'email_domain' => static::emailDomain( $email ),
			'user_agent' => (string) ( Request::i()->userAgent() ?? '' ),
			'account_age_seconds' => max( 0, time() - (int) $member->joined ),
			'post_count' => (int) $member->member_posts,
			'content' => NULL,
			'links' => [],
		];
	}

	/**
	 * @param array<string, mixed> $response
	 */
	public static function holdContentForReview( object $content, array $response, string $endpoint, string $reason, bool $wasNew ): bool
	{
		$idColumn = $content::$databaseColumnId ?? NULL;
		$contentId = is_string( $idColumn ) ? (int) $content->$idColumn : 0;
		if ( $contentId <= 0 )
		{
			return FALSE;
		}
		$class = get_class( $content );
		if ( static::mapApprovalClassToType( $class ) === NULL )
		{
			return FALSE;
		}

		$approval = NULL;
		$approvalCreated = FALSE;
		try
		{
			$title = method_exists( $content, 'mapped' ) ? (string) $content->mapped( 'title' ) : '';
			$body = method_exists( $content, 'content' ) ? (string) $content->content() : '';
			$author = method_exists( $content, 'author' ) ? $content->author() : NULL;
			$held = [
				'name' => is_object( $author ) ? (string) $author->name : '',
				'title' => $title,
				'content' => $body,
				'forum_fortress' => [
					'decision_id' => (int) ( $response['decision_id'] ?? 0 ) ?: NULL,
					'decision_reference' => trim( (string) ( $response['decision_reference'] ?? '' ) ) ?: NULL,
					'decision_state' => 'block',
					'endpoint' => $endpoint,
					'public_reason' => $reason,
					'content_was_new' => $wasNew,
					'check_payload' => is_array( $response['check_payload'] ?? NULL ) ? $response['check_payload'] : NULL,
				],
			];

			try
			{
				$approval = Approval::loadFromContent( $class, $contentId );
				$existingHeld = is_array( $approval->held_data ) ? $approval->held_data : [];
				if ( !is_array( $existingHeld['forum_fortress'] ?? NULL ) )
				{
					/* Preserve both the state and queue row owned by the existing
					 * IC5 moderation source. Calling hide() would delete that row. */
					return TRUE;
				}
				$held = array_replace_recursive( $existingHeld, $held );
				/* Once content was born pending, later blocked edits must not erase
				 * that provenance: its eventual approval still needs IC5's native
				 * first-approval lifecycle. */
				$held['forum_fortress']['content_was_new'] =
					!empty( $existingHeld['forum_fortress']['content_was_new'] ) || $wasNew;
			}
			catch ( \OutOfRangeException $e )
			{
				$approval = new Approval;
				$approval->content_class = $class;
				$approval->content_id = $contentId;
				$approvalCreated = TRUE;
			}
			/* The event preflight must persist IC5's pending state before create/edit
			 * side effects run. A post-save flip leaks notifications and makes a later
			 * unhide repeat first-approval accounting. */
			if ( !method_exists( $content, 'hidden' ) || (int) $content->hidden() !== 1 )
			{
				throw new \RuntimeException( 'Content was not staged in native pending-approval state' );
			}
			$approval->held_reason = 'forum_fortress';
			$approval->held_data = $held;
			$approval->save();
			return TRUE;
		}
		catch ( Throwable $e )
		{
			Log::log( 'Forum Fortress could not hold content for review: ' . $e->getMessage(), 'forumfortress' );
			if ( $approvalCreated && $approval instanceof Approval && (int) $approval->id > 0 )
			{
				try
				{
					$approval->delete();
				}
				catch ( Throwable $cleanupError )
				{
				}
			}
			if ( method_exists( $content, 'delete' ) )
			{
				try
				{
					$content->delete();
					Log::log( 'Forum Fortress deleted blocked content because it could not be hidden safely.', 'forumfortress' );
				}
				catch ( Throwable $fallbackError )
				{
					Log::log( 'Forum Fortress could not enforce a post-save content block.', 'forumfortress' );
				}
			}
			return FALSE;
		}
	}

	/** @param array<string, mixed> $response */
	protected static function stageContentPendingApproval( object $content, array $response, string $endpoint, string $reason, bool $new ): bool
	{
		if ( !method_exists( $content, 'hidden' ) )
		{
			return FALSE;
		}
		$originalState = (int) $content->hidden();
		$transitioned = $originalState === 0;
		$columnMap = is_array( $content::$databaseColumnMap ?? NULL ) ? $content::$databaseColumnMap : [];
		if ( $transitioned && isset( $columnMap['approved'] ) )
		{
			$column = (string) $columnMap['approved'];
			$content->$column = 0;
		}
		elseif ( $transitioned && isset( $columnMap['hidden'] ) )
		{
			$column = (string) $columnMap['hidden'];
			$content->$column = 1;
		}
		elseif ( $transitioned || $originalState !== 1 )
		{
			return FALSE;
		}

		static::$pendingContentHolds[ \spl_object_id( $content ) ] = [
			'response' => $response,
			'endpoint' => $endpoint,
			'reason' => $reason,
			'new' => $new,
			'transitioned' => $transitioned,
		];
		return TRUE;
	}

	protected static function reconcileStagedContentAccounting( object $content, bool $wasNew ): void
	{
		try
		{
			$item = $content instanceof \IPS\Content\Comment ? $content->item() : $content;
			if ( method_exists( $item, 'resyncCommentCounts' ) )
			{
				$item->resyncCommentCounts();
			}
			if ( method_exists( $item, 'resyncLastComment' ) )
			{
				$item->resyncLastComment();
			}
			if ( method_exists( $item, 'save' ) )
			{
				$item->save();
			}
			$container = method_exists( $item, 'container' ) ? $item->container() : NULL;
			if ( is_object( $container ) )
			{
				if ( method_exists( $container, 'resetCommentCounts' ) )
				{
					$container->resetCommentCounts();
				}
				if ( method_exists( $container, 'setLastComment' ) )
				{
					$container->setLastComment();
				}
				if ( method_exists( $container, 'save' ) )
				{
					$container->save();
				}
			}

			$author = method_exists( $content, 'author' ) ? $content->author() : NULL;
			$decrementPostCount = FALSE;
			/* createItem() runs before IC5 fires the topic before-create event. A
			 * new first-comment topic has not incremented the author's post count:
			 * Topic::incrementPostCount() is false and Comment::create() sees the
			 * staged pending parent. Native unhide() supplies that first increment.
			 * Existing visible content, however, was already accounted and must be
			 * removed while its edit is pending. */
			if ( !$wasNew && is_object( $author ) && (int) ( $author->member_id ?? 0 ) > 0 && is_object( $container ) )
			{
				if ( $content instanceof \IPS\Content\Comment )
				{
					$class = get_class( $content );
					$decrementPostCount = $class::incrementPostCount( $container );
				}
				elseif ( $content instanceof \IPS\Content\Item && isset( $content::$commentClass ) )
				{
					$itemClass = get_class( $content );
					$commentClass = $content::$commentClass;
					$decrementPostCount = ( $itemClass::$firstCommentRequired && $commentClass::incrementPostCount( $container ) )
						|| $itemClass::incrementPostCount( $container );
				}
			}
			if ( $decrementPostCount && (int) $author->member_posts > 0 )
			{
				$author->member_posts--;
				$author->save();
			}
			static::syncDerivedContentVisibility( $content, FALSE );

			$indexContent = $content;
			if ( $content instanceof \IPS\Content\Item && $content::$firstCommentRequired && method_exists( $content, 'firstComment' ) )
			{
				$indexContent = $content->firstComment();
			}
			\IPS\Content\Search\Index::i()->index( $indexContent );
		}
		catch ( Throwable $e )
		{
			Log::log( 'Forum Fortress could not complete the native pending-content transition: ' . $e->getMessage(), 'forumfortress' );
			throw $e;
		}
	}

	/**
	 * IPS exposes profile updates after save. We therefore clear a rejected
	 * signature/custom field where possible and hold the account for review.
	 *
	 * @param array<string, mixed> $changes
	 */
	public static function checkProfileUpdate( \IPS\Member $member, array $changes ): void
	{
		if ( !static::isEnabled() || static::$memberMutationInProgress || static::$moderationSyncInProgress )
		{
			return;
		}
		$signature = isset( $changes['signature'] ) ? trim( (string) $changes['signature'] ) : '';
		$profileParts = [];
		foreach ( $changes as $key => $value )
		{
			$key = (string) $key;
			if ( $key === 'signature' || $key === 'member_id' || !is_scalar( $value ) )
			{
				continue;
			}
			if ( in_array( $key, [ 'name', 'member_title', 'website', 'location', 'interests' ], TRUE ) || preg_match( '/^field_[0-9]+$/', $key ) )
			{
				$value = trim( (string) $value );
				if ( $value !== '' )
				{
					$profileParts[] = $value;
				}
			}
		}

		$checks = [];
		if ( $signature !== '' )
		{
			$checks['signature_edit'] = $signature;
		}
		if ( $profileParts )
		{
			$checks['profile_edit'] = implode( "\n", $profileParts );
		}

		foreach ( $checks as $endpoint => $text )
		{
			$payload = static::contentCheckPayload( $member, $text );
			$response = static::checkContent( $endpoint, $payload );
			$decision = strtolower( trim( (string) ( $response['decision'] ?? '' ) ) );
			if ( $decision === 'allow' || ( $response === NULL && Settings::i()->ff_fail_open ) )
			{
				continue;
			}
			if ( $decision === 'block' || ( $response === NULL && !Settings::i()->ff_fail_open ) )
			{
				static::$memberMutationInProgress = TRUE;
				try
				{
					if ( $endpoint === 'signature_edit' )
					{
						$member->signature = '';
						$member->save();
					}
					foreach ( $changes as $key => $value )
					{
						if ( $endpoint === 'profile_edit' && preg_match( '/^field_[0-9]+$/', (string) $key ) )
						{
							Db::i()->update( 'core_pfields_content', [ (string) $key => '' ], [ 'member_id=?', (int) $member->member_id ] );
						}
					}
				}
				finally
				{
					static::$memberMutationInProgress = FALSE;
				}
				$response = $response ?? [];
				$response['check_payload'] = $payload;
				static::holdMemberForReview( $member, $response, 'Forum Fortress profile block: review required' );
				return;
			}
		}
	}

	public static function reportMemberVerdict( \IPS\Member $member, string $verdict ): void
	{
		if ( !static::isEnabled() || static::$moderationSyncInProgress || !$member->member_id )
		{
			return;
		}
		$verdict = strtolower( trim( $verdict ) );
		if ( !in_array( $verdict, [ 'moderation', 'ham' ], TRUE ) )
		{
			return;
		}
		if ( $verdict === 'ham' && !( Settings::i()->ff_send_ham ?? TRUE ) )
		{
			return;
		}
		$email = trim( (string) $member->email );
		static::request( 'POST', '/v1/report/' . $verdict, static::preparePayload( [
			'forum_id' => NULL,
			'username' => (string) $member->name,
			'email_domain' => static::emailDomain( $email ),
			'ip' => (string) $member->ip_address,
			'links' => [],
			'payload' => [
				'source' => 'invision_member_moderation',
				'member_id' => (int) $member->member_id,
			],
		] ) );
	}

	public static function cleanupMemberApprovalOnDelete( \IPS\Member $member ): void
	{
		static::deleteOwnedMemberValidationRows( (int) $member->member_id );
	}

	public static function reportRegister( \IPS\Member $member ): void
	{
		if ( !static::isEnabled() or !$member->member_id )
		{
			return;
		}

		static::bootstrapIfNeeded();

		$email = trim( (string) $member->email );
		$payload = [
			'forum_id' => NULL,
			'username' => (string) $member->name,
			'email_domain' => static::emailDomain( $email ),
			'ip' => static::clientIp(),
			'links' => [],
			'payload' => [
				'source' => 'invision_registration',
				'member_id' => $member->member_id,
			],
		];

		static::request( 'POST', '/v1/report/register', static::preparePayload( $payload ) );
	}

	public static function hourlySync(): bool
	{
		if ( !static::isEnabled() )
		{
			return TRUE;
		}

		$gateState = static::loadEndpointState();
		$lastHourly = (int) ( $gateState['hourly_sync_last_at'] ?? 0 );
		if ( $lastHourly > 0 && ( time() - $lastHourly ) < self::HOURLY_SYNC_MIN_INTERVAL )
		{
			return TRUE;
		}
		$gateState['hourly_sync_last_at'] = time();
		static::saveEndpointState( $gateState );
		$succeeded = TRUE;

		try
		{
			static::bootstrapIfNeeded();
		}
		catch ( Throwable $e )
		{
			$succeeded = FALSE;
		}

		try
		{
			static::maybeMigrateFromOfflineBootstrap();
		}
		catch ( Throwable $e )
		{
			$succeeded = FALSE;
		}

		try
		{
			if ( static::shouldRunDailyTask( 'plugin_release_last_at' ) )
			{
				static::pluginRelease();
				static::markDailyTaskRun( 'plugin_release_last_at' );
			}
		}
		catch ( Throwable $e )
		{
			$succeeded = FALSE;
		}

		$heartbeatState = static::loadEndpointState();
		$lastHeartbeat = max(
			(int) ( $heartbeatState['last_site_ping_at'] ?? 0 ),
			(int) ( $heartbeatState['last_site_ping_attempt_at'] ?? 0 )
		);
		$plan = strtolower( trim( (string) ( $heartbeatState['plan_name'] ?? '' ) ) );
		$heartbeatInterval = in_array( $plan, [ 'pro', 'multimod' ], TRUE )
			? self::PRO_HEARTBEAT_INTERVAL_SECONDS
			: self::STANDARD_HEARTBEAT_INTERVAL_SECONDS;
		if ( $lastHeartbeat <= 0 || ( time() - $lastHeartbeat ) >= $heartbeatInterval )
		{
			$heartbeatState['last_site_ping_attempt_at'] = time();
			static::saveEndpointState( $heartbeatState );
			try
			{
				if ( static::sitePing( self::CONNECTION_TEST_TIMEOUT_SECONDS ) === NULL )
				{
					$succeeded = FALSE;
				}
			}
			catch ( Throwable $e )
			{
				$succeeded = FALSE;
			}
		}

		try
		{
			static::refreshPlanCacheIfStale( TRUE );
		}
		catch ( Throwable $e )
		{
			$succeeded = FALSE;
		}

		try
		{
			if ( !static::runModerationSyncCycle( TRUE ) )
			{
				$succeeded = FALSE;
			}
		}
		catch ( Throwable $e )
		{
			$succeeded = FALSE;
		}
		return $succeeded;
	}

	/** Run scheduled recovery from normal community traffic as well as tasks. */
	public static function trafficTick(): void
	{
		if ( !static::isEnabled() )
		{
			return;
		}
		$state = static::loadEndpointState();
		if ( isset( $state['ff_timeout_pending'] ) )
		{
			unset( $state['ff_timeout_pending'] );
			static::saveEndpointState( $state );
		}
		static::ensureIdentity();
		static::hourlySync();
		static::runModerationSyncCycle( FALSE );
	}

	public static function sitePing( ?int $timeoutOverride = null ): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		$siteId = trim( Settings::i()->ff_site_id );
		$apiKey = static::apiKey();
		if ( $siteId === '' || $apiKey === '' )
		{
			return NULL;
		}

		$payload = static::requestFromControlPlane( 'POST', '/v1/site/ping', [
			'api_key' => $apiKey,
			'site_id' => $siteId,
			'domain' => static::forumDomain(),
			'platform' => static::PLATFORM,
			'platform_version' => Application::load( 'core' )->version,
			'plugin_version' => static::PLUGIN_VERSION,
		], $timeoutOverride ?? self::CONNECTION_TEST_TIMEOUT_SECONDS );
		if ( is_array( $payload ) )
		{
			$state = static::loadEndpointState();
			$state['last_site_ping_at'] = time();
			static::saveEndpointState( $state );
		}
		return $payload;
	}

	public static function checkContent( string $endpoint, array $payload ): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		static::bootstrapIfNeeded();

		$preparedBase = static::preparePayload( $payload );
		$fingerprint = sha1( $endpoint . "\n" . json_encode( $preparedBase, JSON_UNESCAPED_SLASHES ) );
		if ( isset( static::$contentCheckCache[ $fingerprint ] ) )
		{
			static::$lastCheckHadTimeout = static::$contentCheckCache[ $fingerprint ]['timed_out'];
			return static::$contentCheckCache[ $fingerprint ]['response'];
		}

		static::$lastCheckHadTimeout = FALSE;
		$prepared = static::withCheckRequestId( $preparedBase );
		$timeoutOverride = $endpoint === 'contact_page'
			? \FfApiResilience::contactPageCheckTimeoutSeconds( max( 1, (int) Settings::i()->ff_timeout ) )
			: NULL;
		$response = static::request( 'POST', '/v1/check/' . $endpoint, $prepared, $timeoutOverride );
		if ( is_array( $response ) && !static::hasDefinitiveCheckDecision( $response ) )
		{
			$response = NULL;
		}
		static::$contentCheckCache[ $fingerprint ] = [
			'response' => $response,
			'timed_out' => static::$lastCheckHadTimeout,
		];
		if ( is_array( $response ) )
		{
			static::maybeRefreshEndpointCatalogAfterCheckIn( '/v1/check/' . $endpoint );
		}
		return $response;
	}

	/**
	 * Check an IPS content event. UI form checks and event listeners share the
	 * request cache, so the same submission is not billed twice.
	 *
	 * @param array<string, mixed> $values
	 */
	public static function checkIpsContentBefore( object $content, array $values, bool $new, string $baseEndpoint ): void
	{
		if ( !static::isEnabled() )
		{
			return;
		}
		$text = static::contentTextFromIpsObject( $content, $values );
		if ( $text === '' )
		{
			return;
		}
		$endpoint = $new ? $baseEndpoint : $baseEndpoint . '_edit';
		$payload = static::contentCheckPayload( $content, $text );
		$response = static::checkContent( $endpoint, $payload );
		$decision = strtolower( trim( (string) ( $response['decision'] ?? '' ) ) );
		if ( $decision === 'block' || ( $response === NULL && !Settings::i()->ff_fail_open ) )
		{
			$heldResponse = is_array( $response ) ? $response : [];
			$heldResponse['check_payload'] = $payload;
			static::stageContentPendingApproval(
				$content,
				$heldResponse,
				$endpoint,
				$decision === 'block'
					? 'Forum Fortress block: content hidden pending review'
					: 'Forum Fortress unavailable: content hidden by fail-closed policy',
				$new
			);
		}
		elseif ( !$new && static::isOwnedContentPendingApproval( $content ) )
		{
			/* An author may edit content that is already in the FF queue. Even an
			 * allowed or fail-open edit must refresh the held snapshot after save;
			 * otherwise a moderator can review body A and expose unreviewed body B. */
			$heldResponse = is_array( $response ) ? $response : [];
			$heldResponse['check_payload'] = $payload;
			static::stageContentPendingApproval(
				$content,
				$heldResponse,
				$endpoint,
				$response === NULL
					? 'Forum Fortress unavailable: edited pending content still requires review'
					: 'Forum Fortress pending content was edited; review the updated content',
				FALSE
			);
		}
		static::handleContentCheckResult( $endpoint, $payload, $response );
	}

	protected static function isOwnedContentPendingApproval( object $content ): bool
	{
		if ( !method_exists( $content, 'hidden' ) || (int) $content->hidden() !== 1 )
		{
			return FALSE;
		}
		$idColumn = $content::$databaseColumnId ?? NULL;
		$contentId = is_string( $idColumn ) ? (int) $content->$idColumn : 0;
		if ( $contentId <= 0 )
		{
			return FALSE;
		}
		try
		{
			$approval = Approval::loadFromContent( get_class( $content ), $contentId );
			$held = is_array( $approval->held_data ) ? $approval->held_data : [];
			return (string) $approval->held_reason === 'forum_fortress'
				&& is_array( $held['forum_fortress'] ?? NULL );
		}
		catch ( \OutOfRangeException $e )
		{
			return FALSE;
		}
	}

	/** @param array<string, mixed> $values */
	public static function finishIpsContentCheck( object $content, array $values, bool $new, string $baseEndpoint ): void
	{
		if ( !static::isEnabled() )
		{
			return;
		}
		$key = \spl_object_id( $content );
		$hold = static::$pendingContentHolds[ $key ] ?? NULL;
		unset( static::$pendingContentHolds[ $key ] );
		if ( !is_array( $hold ) )
		{
			return;
		}
		try
		{
			if ( !empty( $hold['transitioned'] ) )
			{
				static::reconcileStagedContentAccounting( $content, (bool) ( $hold['new'] ?? $new ) );
			}
			static::holdContentForReview(
				$content,
				is_array( $hold['response'] ?? NULL ) ? $hold['response'] : [],
				(string) ( $hold['endpoint'] ?? ( $new ? $baseEndpoint : $baseEndpoint . '_edit' ) ),
				(string) ( $hold['reason'] ?? 'Held for review by Forum Fortress' ),
				(bool) ( $hold['new'] ?? $new )
			);
		}
		catch ( Throwable $e )
		{
			if ( method_exists( $content, 'delete' ) )
			{
				try
				{
					$content->delete();
				}
				catch ( Throwable $deleteError )
				{
					Log::log( 'Forum Fortress could not remove content after a pending-state enforcement failure.', 'forumfortress' );
				}
			}
		}
	}

	/** @param array<string, mixed> $payload */
	protected static function handleContentCheckResult( string $endpoint, array $payload, ?array $response ): void
	{
		if ( $response === NULL )
		{
			if ( Settings::i()->ff_fail_open )
			{
				return;
			}
			throw new \DomainException( 'forumfortress_api_unreachable' );
		}
		$decision = strtolower( trim( (string) ( $response['decision'] ?? '' ) ) );
		if ( $decision === 'block' )
		{
			throw new \DomainException( 'forumfortress_post_blocked' );
		}
	}

	/** @param array<string, mixed> $values */
	protected static function contentTextFromIpsObject( object $content, array $values ): string
	{
		$title = trim( (string) ( $values['topic_title'] ?? $values['title'] ?? '' ) );
		/* IC5's before-edit event uses comment_value for reply bodies. The
		 * similarly named comment value is the row ID, not submitted content. */
		$body = trim( (string) ( $values['comment_value'] ?? $values['topic_content'] ?? $values['content'] ?? '' ) );
		if ( $body === '' && method_exists( $content, 'content' ) )
		{
			try
			{
				$body = trim( (string) $content->content() );
			}
			catch ( Throwable $e )
			{
			}
		}
		if ( $title === '' && method_exists( $content, 'mapped' ) )
		{
			try
			{
				$title = trim( (string) $content->mapped( 'title' ) );
			}
			catch ( Throwable $e )
			{
			}
		}
		return trim( $title . ( $title !== '' && $body !== '' ? "\n\n" : '' ) . $body );
	}

	/** @return array<string, mixed> */
	protected static function contentCheckPayload( object $content, string $text ): array
	{
		$member = $content instanceof \IPS\Member ? $content : \IPS\Member::loggedIn();
		try
		{
			if ( method_exists( $content, 'author' ) )
			{
				$member = $content->author();
			}
		}
		catch ( Throwable $e )
		{
		}
		$email = (string) $member->email;
		return [
			'ip' => static::clientIp(),
			'username' => (string) $member->name,
			'email' => $email,
			'email_domain' => static::emailDomain( $email ),
			'post_count' => (int) $member->member_posts,
			'account_age_seconds' => max( 0, time() - (int) $member->joined ),
			'user_agent' => (string) ( Request::i()->userAgent() ?? '' ),
			'content' => $text,
			'links' => static::extractLinks( $text ),
		];
	}

	public static function health( ?int $timeoutOverride = null ): ?array
	{
		return static::sitePing( $timeoutOverride );
	}

	public static function capabilities( ?int $timeoutOverride = null ): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		return static::requestFromControlPlane( 'GET', '/v1/capabilities', [], $timeoutOverride ?? self::CONNECTION_TEST_TIMEOUT_SECONDS );
	}

	public static function siteStatus( ?int $timeoutOverride = null ): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		$key = static::apiKey();
		if ( $key === '' )
		{
			return NULL;
		}

		$response = static::request( 'GET', '/v1/site/status', [
			'api_key' => $key,
			'domain' => static::forumDomain(),
		], $timeoutOverride ?? self::CONNECTION_TEST_TIMEOUT_SECONDS );
		if ( is_array( $response ) )
		{
			static::persistIdentity( $response );
			static::cacheApiSnapshot( 'site_status', $response );
		}

		return $response;
	}

	public static function forumStats( ?int $timeoutOverride = null ): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		$key = static::apiKey();
		if ( $key === '' )
		{
			return NULL;
		}

		$response = static::request( 'GET', '/v1/forum/stats', [
			'api_key' => $key,
			'domain' => static::forumDomain(),
		], $timeoutOverride ?? self::CONNECTION_TEST_TIMEOUT_SECONDS );
		if ( is_array( $response ) )
		{
			static::cacheApiSnapshot( 'forum_stats', $response );
		}

		return $response;
	}

	/** @param array<string, mixed> $payload */
	protected static function cacheApiSnapshot( string $name, array $payload ): void
	{
		$state = static::loadEndpointState();
		$state[ 'cached_' . $name ] = $payload;
		$state[ 'cached_' . $name . '_at' ] = time();
		static::saveEndpointState( $state );
	}

	/** @return array<string, mixed>|null */
	public static function cachedSiteStatus(): ?array
	{
		$state = static::loadEndpointState();
		$value = $state['cached_site_status'] ?? NULL;
		return is_array( $value ) ? $value : NULL;
	}

	/** @return array<string, mixed>|null */
	public static function cachedForumStats(): ?array
	{
		$state = static::loadEndpointState();
		$value = $state['cached_forum_stats'] ?? NULL;
		return is_array( $value ) ? $value : NULL;
	}

	/**
	 * Count configured IPS API clients that can create or edit forum content.
	 * IPS 5 does not expose a supported interception point for those mutators.
	 */
	public static function unprotectedWriteApiClientCount(): int
	{
		$restMutators = [
			'forums/topics/POSTindex',
			'forums/topics/POSTitem',
			'forums/posts/POSTindex',
			'forums/posts/POSTitem',
		];
		$count = 0;

		try
		{
			foreach ( Db::i()->select( 'api_permissions', 'core_api_keys' ) as $permissionJson )
			{
				$permissions = json_decode( (string) $permissionJson, TRUE );
				if ( !is_array( $permissions ) )
				{
					continue;
				}
				foreach ( $restMutators as $mutator )
				{
					if ( !empty( $permissions[ $mutator ]['access'] ) )
					{
						$count++;
						break;
					}
				}
			}
		}
		catch ( Throwable $e )
		{
		}

		try
		{
			foreach ( Db::i()->select( 'oauth_api_access, oauth_scopes', 'core_oauth_clients', [ 'oauth_enabled=?', 1 ] ) as $row )
			{
				$access = strtolower( trim( (string) ( $row['oauth_api_access'] ?? '' ) ) );
				if ( in_array( $access, [ 'graphql', 'both' ], TRUE ) )
				{
					$count++;
					continue;
				}
				$scopes = (string) ( $row['oauth_scopes'] ?? '' );
				foreach ( $restMutators as $mutator )
				{
					if ( str_contains( $scopes, $mutator ) )
					{
						$count++;
						break;
					}
				}
			}
		}
		catch ( Throwable $e )
		{
		}

		return $count;
	}

	public static function pluginRelease( ?int $timeoutOverride = null ): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		return static::requestFromControlPlane( 'GET', '/v1/plugin-release', [
			'platform' => static::PLATFORM,
			'current_version' => static::PLUGIN_VERSION,
		], $timeoutOverride ?? self::CONNECTION_TEST_TIMEOUT_SECONDS );
	}

	public static function registerSite( string $email ): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		$siteId = trim( Settings::i()->ff_site_id );
		if ( $siteId === '' )
		{
			static::bootstrapIfNeeded();
			$siteId = trim( Settings::i()->ff_site_id );
		}

		if ( $siteId === '' || $email === '' )
		{
			return NULL;
		}

		$apiKey = static::apiKey();
		if ( $apiKey === '' )
		{
			return NULL;
		}

		$payload = [
			'domain' => static::forumDomain(),
			'email' => trim( $email ),
			'site_id' => $siteId,
			'api_key' => $apiKey,
		];

		$response = static::request( 'POST', '/v1/site/register', $payload );
		if ( is_array( $response ) )
		{
			static::persistIdentity( $response );
		}
		return $response;
	}

	public static function activateAttackMode(): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		$siteId = trim( Settings::i()->ff_site_id );
		$apiKey = static::apiKey();
		if ( $siteId === '' || $apiKey === '' )
		{
			return NULL;
		}

		$response = static::requestFromControlPlane( 'POST', '/v1/site/attack-mode', [
			'site_id' => $siteId,
			'api_key' => $apiKey,
			'domain' => static::forumDomain(),
		] );

		return static::assertAttackModeResponse( $response, TRUE );
	}

	public static function deactivateAttackMode(): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		$siteId = trim( Settings::i()->ff_site_id );
		$apiKey = static::apiKey();
		if ( $siteId === '' || $apiKey === '' )
		{
			return NULL;
		}

		$response = static::requestFromControlPlane( 'POST', '/v1/site/attack-mode/end', [
			'site_id' => $siteId,
			'api_key' => $apiKey,
			'domain' => static::forumDomain(),
		] );

		return static::assertAttackModeResponse( $response, FALSE );
	}

	protected static function assertAttackModeResponse( ?array $response, bool $enabled ): array
	{
		$actual = NULL;
		if ( is_array( $response ) && array_key_exists( 'attack_mode_active', $response ) )
		{
			$actual = (bool) $response['attack_mode_active'];
		}
		elseif ( is_array( $response ) && array_key_exists( 'enabled', $response ) )
		{
			$actual = (bool) $response['enabled'];
		}
		elseif ( is_array( $response ) && is_array( $response['attack_mode'] ?? NULL ) && array_key_exists( 'enabled', $response['attack_mode'] ) )
		{
			$actual = (bool) $response['attack_mode']['enabled'];
		}
		if (
			$actual === NULL
			|| $actual !== $enabled
		)
		{
			throw new \RuntimeException( $enabled
				? 'Forum Fortress did not confirm that attack mode is active.'
				: 'Forum Fortress did not confirm that attack mode has ended.' );
		}

		$response['attack_mode_active'] = $actual;
		return $response;
	}

	public static function portalLaunch( ?int $timeoutOverride = null ): ?array
	{
		static::$authenticatedPortalUrl = NULL;
		if ( !static::isEnabled() )
		{
			return NULL;
		}

		$siteId = trim( Settings::i()->ff_site_id );
		$apiKey = static::apiKey();
		if ( $siteId === '' || $apiKey === '' )
		{
			static::bootstrapIfNeeded();
			$siteId = trim( Settings::i()->ff_site_id );
			$apiKey = static::apiKey();
		}

		if ( $siteId === '' || $apiKey === '' )
		{
			return NULL;
		}

		$response = static::requestFromControlPlane( 'POST', '/v1/site/portal', [
			'api_key' => $apiKey,
			'site_id' => $siteId,
			'domain' => static::forumDomain(),
			'platform' => static::PLATFORM,
			'platform_version' => Application::load( 'core' )->version,
			'plugin_version' => static::PLUGIN_VERSION,
		], $timeoutOverride ?? self::CONNECTION_TEST_TIMEOUT_SECONDS );
		$portalUrl = is_array( $response ) ? trim( (string) ( $response['portal_url'] ?? '' ) ) : '';
		if ( static::portalUrlHasSafeBearerShape( $portalUrl ) )
		{
			static::$authenticatedPortalUrl = $portalUrl;
		}
		return $response;
	}

	/** Validate bearer-URL structure without granting arbitrary origin trust. */
	protected static function portalUrlHasSafeBearerShape( string $value ): bool
	{
		if ( $value === '' || filter_var( $value, FILTER_VALIDATE_URL ) === FALSE )
		{
			return FALSE;
		}
		$parts = parse_url( $value );
		if (
			!is_array( $parts )
			|| strtolower( (string) ( $parts['scheme'] ?? '' ) ) !== 'https'
			|| trim( (string) ( $parts['host'] ?? '' ) ) === ''
			|| isset( $parts['user'] )
			|| isset( $parts['pass'] )
			|| isset( $parts['fragment'] )
			|| !static::endpointTransportIsSafe( $parts )
			|| rtrim( '/' . ltrim( (string) ( $parts['path'] ?? '' ), '/' ), '/' ) !== '/access'
		)
		{
			return FALSE;
		}
		$query = [];
		parse_str( (string) ( $parts['query'] ?? '' ), $query );
		return isset( $query['token'] ) && is_string( $query['token'] ) && trim( $query['token'] ) !== '';
	}

	/** @return array<string, mixed> */
	public static function deprovisionSite( string $reason = 'plugin_uninstall' ): array
	{
		$reason = strtolower( trim( $reason ) );
		if ( !in_array( $reason, [ 'plugin_uninstall', 'manual_disconnect' ], TRUE ) )
		{
			throw new \InvalidArgumentException( 'Unsupported Forum Fortress deprovision reason' );
		}
		$siteId = trim( (string) Settings::i()->ff_site_id );
		$apiKey = static::apiKey();
		if ( $siteId === '' || $apiKey === '' )
		{
			return [ 'status' => 'no_identity' ];
		}

		$payload = [
			'api_key' => $apiKey,
			'site_id' => $siteId,
			'domain' => static::forumDomain(),
			'platform' => static::PLATFORM,
			'platform_version' => Application::load( 'core' )->version,
			'plugin_version' => static::PLUGIN_VERSION,
			'reason' => $reason,
		];
		foreach ( static::controlPlaneRequestBases() as $base )
		{
			$response = static::rawRequest( 'POST', $base, '/v1/site/deprovision', $payload, 3 );
			$status = (int) ( $response['status'] ?? 0 );
			$data = is_array( $response['data'] ?? NULL ) ? $response['data'] : NULL;
			if ( $status >= 200 && $status < 300 && is_array( $data ) )
			{
				return $data;
			}
			if ( $status === 410 )
			{
				return [ 'status' => 'already_removed' ];
			}
		}
		throw new \RuntimeException( 'Forum Fortress could not confirm remote site deprovisioning' );
	}

	public static function runModerationSyncCycle( bool $force = FALSE ): bool
	{
		if ( !static::isEnabled() or static::$moderationSyncInProgress )
		{
			return TRUE;
		}

		$siteId = trim( Settings::i()->ff_site_id );
		$apiKey = static::apiKey();
		if ( $siteId === '' || $apiKey === '' )
		{
			return FALSE;
		}

		$state = static::loadEndpointState();
		$lastSyncAt = (int) ( $state['moderation_last_sync_at'] ?? 0 );
		$lastAttemptAt = (int) ( $state['moderation_last_attempt_at'] ?? 0 );
		$intervalSeconds = static::getModerationSyncIntervalSeconds( $state );
		if ( !$force && ( time() - $lastSyncAt ) < $intervalSeconds )
		{
			return TRUE;
		}
		if ( !$force && $lastAttemptAt > 0 && ( time() - $lastAttemptAt ) < 30 )
		{
			return TRUE;
		}
		$state['moderation_last_attempt_at'] = time();
		static::saveEndpointState( $state );

		[ $items, $snapshotComplete, $nextSnapshotCursor ] = static::buildModerationSnapshot();

		static::$moderationSyncInProgress = TRUE;
		$cycleSucceeded = FALSE;
		try
		{
			$syncPayload = static::requestModeration( 'POST', '/v1/moderation-queue/sync', [
				'api_key' => $apiKey,
				'site_id' => $siteId,
				'domain' => static::forumDomain(),
				'platform' => static::PLATFORM,
				'platform_version' => Application::load( 'core' )->version,
				'plugin_version' => static::PLUGIN_VERSION,
				'block_reject_action' => static::getWireBlockRejectAction(),
				'snapshot_complete' => $snapshotComplete,
				'items' => $items,
			] );

			if ( is_array( $syncPayload ) && !empty( $syncPayload['queue_notes'] ) && is_array( $syncPayload['queue_notes'] ) )
			{
				static::applyQueueNotes( $syncPayload['queue_notes'] );
			}

			$pendingRemaining = 0;
			$syncCompleted = is_array( $syncPayload );
			for ( $pass = 0; $pass < 8; $pass++ )
			{
				$actionsPayload = static::requestModeration( 'POST', '/v1/moderation-actions/pull', [
					'api_key' => $apiKey,
					'site_id' => $siteId,
					'domain' => static::forumDomain(),
					'platform' => static::PLATFORM,
					'platform_version' => Application::load( 'core' )->version,
					'plugin_version' => static::PLUGIN_VERSION,
					'limit' => 25,
				] );
				if ( !is_array( $actionsPayload ) )
				{
					$syncCompleted = FALSE;
					break;
				}
				$actions = is_array( $actionsPayload['actions'] ?? NULL ) ? $actionsPayload['actions'] : [];
				$pendingRemaining = (int) ( $actionsPayload['pending_actions'] ?? 0 );
				if ( !$actions )
				{
					break;
				}
				$results = static::executeModerationActions( $actions );
				$ackPayload = static::requestModeration( 'POST', '/v1/moderation-actions/ack', [
					'api_key' => $apiKey,
					'site_id' => $siteId,
					'domain' => static::forumDomain(),
					'platform' => static::PLATFORM,
					'platform_version' => Application::load( 'core' )->version,
					'plugin_version' => static::PLUGIN_VERSION,
					'results' => $results,
				] );
				if ( !is_array( $ackPayload ) )
				{
					$syncCompleted = FALSE;
					break;
				}
			}
			if ( is_array( $syncPayload ) )
			{
				$pendingRemaining = max( $pendingRemaining, (int) ( $syncPayload['pending_actions'] ?? 0 ) );
			}
			$state = static::loadEndpointState();
			$state['moderation_pending_actions'] = max( 0, $pendingRemaining );
			if ( is_array( $syncPayload ) )
			{
				$state['moderation_snapshot_cursor'] = $nextSnapshotCursor;
			}
			if ( $syncCompleted )
			{
				$state['moderation_last_sync_at'] = time();
				\FfApiResilience::shouldLogConsecutiveTransientFailure( $state, 'bg:moderation sync failed', FALSE );
			}
			elseif ( \FfApiResilience::shouldLogConsecutiveTransientFailure( $state, 'bg:moderation sync failed', TRUE ) )
			{
				Log::log( 'Forum Fortress moderation sync did not complete; it will retry automatically.', 'forumfortress' );
			}
			static::saveEndpointState( $state );
			$cycleSucceeded = $syncCompleted;
		}
		catch ( Throwable $e )
		{
			Log::log( 'Forum Fortress moderation sync failed: ' . $e->getMessage(), 'forumfortress' );
		}
		finally
		{
			static::$moderationSyncInProgress = FALSE;
		}
		return $cycleSucceeded;
	}

	/** @return array{0: list<array<string, mixed>>, 1: bool, 2: int} */
	protected static function buildModerationSnapshot(): array
	{
		$approvalRows = iterator_to_array( Db::i()->select(
			'*',
			'core_approval_queue',
			[ 'approval_held_reason=?', 'forum_fortress' ],
			'approval_id ASC'
		), FALSE );
		$rawValidationRows = iterator_to_array( Db::i()->select(
			'*',
			'core_validating',
			[ 'spam_flag=? AND new_reg=?', 2, 1 ],
			'entry_date ASC, vid ASC'
		), FALSE );
		$sourceRows = [];
		foreach ( $approvalRows as $row )
		{
			$sourceRows[] = [ 'kind' => 'approval', 'row' => $row ];
		}
		foreach ( $rawValidationRows as $row )
		{
			$heldData = static::ownedMemberValidationMetadata( $row );
			if ( $heldData !== NULL )
			{
				$sourceRows[] = [ 'kind' => 'validation', 'row' => $row, 'held' => $heldData ];
			}
		}

		$totalRows = count( $sourceRows );
		$state = static::loadEndpointState();
		$cursor = $totalRows > 200 ? max( 0, (int) ( $state['moderation_snapshot_cursor'] ?? 0 ) ) % $totalRows : 0;
		$take = min( 200, $totalRows );
		$selectedRows = array_slice( $sourceRows, $cursor, $take );
		if ( count( $selectedRows ) < $take )
		{
			$selectedRows = array_merge( $selectedRows, array_slice( $sourceRows, 0, $take - count( $selectedRows ) ) );
		}
		$nextCursor = $totalRows > 200 ? ( $cursor + $take ) % $totalRows : 0;
		$snapshotComplete = $totalRows <= 200;
		$serializationFailures = 0;
		$items = [];

		foreach ( $selectedRows as $sourceRow )
		{
			$row = is_array( $sourceRow['row'] ?? NULL ) ? $sourceRow['row'] : [];
			if ( (string) ( $sourceRow['kind'] ?? '' ) === 'approval' )
			{
				try
				{
					$approval = Approval::constructFromData( $row );
					$heldData = is_array( $approval->held_data ) ? $approval->held_data : [];
					$ffHeld = is_array( $heldData['forum_fortress'] ?? NULL ) ? $heldData['forum_fortress'] : NULL;
					$class = (string) $approval->content_class;
					$contentType = static::mapApprovalClassToType( $class );
					$contentId = (int) $approval->content_id;
					if ( $ffHeld === NULL || $contentType === NULL || $contentId <= 0 )
					{
						$serializationFailures++;
						continue;
					}
					$payload = [
						'approval_id' => (int) $approval->id,
						'content_type' => $contentType,
						'local_generation' => static::approvalLocalGeneration( $approval, $heldData ),
					];
					if ( (int) ( $ffHeld['decision_id'] ?? 0 ) > 0 )
					{
						$payload['decision_id'] = (int) $ffHeld['decision_id'];
					}
					$items[] = [
						'remote_content_type' => $contentType,
						'remote_content_id' => (string) $contentId,
						'title' => trim( (string) ( $heldData['title'] ?? '' ) ) ?: NULL,
						'reason' => trim( (string) ( $ffHeld['public_reason'] ?? '' ) ) ?: $approval->reason(),
						'excerpt' => (string) ( $heldData['content'] ?? '' ),
						'username' => trim( (string) ( $heldData['name'] ?? '' ) ) ?: NULL,
						'content_hash' => sha1( (string) ( $heldData['content'] ?? '' ) ),
						'content_url' => static::buildApprovalContentUrl( $contentType, $contentId ),
						'available_actions' => [ 'approve', 'reject' ],
						'payload' => $payload,
					];
				}
				catch ( Throwable $e )
				{
					$serializationFailures++;
				}
				continue;
			}

			$heldData = is_array( $sourceRow['held'] ?? NULL ) ? $sourceRow['held'] : NULL;
			$memberId = (int) ( $row['member_id'] ?? 0 );
			$validationId = trim( (string) ( $row['vid'] ?? '' ) );
			if ( $heldData === NULL || $memberId <= 0 || $validationId === '' )
			{
				$serializationFailures++;
				continue;
			}
			try
			{
				$member = \IPS\Member::load( $memberId );
			}
			catch ( Throwable $e )
			{
				$serializationFailures++;
				continue;
			}
			$ffHeld = $heldData['forum_fortress'];
			$payload = [
				'validation_id' => $validationId,
				'content_type' => 'member',
				'local_generation' => static::validationLocalGeneration( $row, $heldData ),
			];
			if ( (int) ( $ffHeld['decision_id'] ?? 0 ) > 0 )
			{
				$payload['decision_id'] = (int) $ffHeld['decision_id'];
			}
			$items[] = [
				'remote_content_type' => 'member',
				'remote_content_id' => (string) $memberId,
				'remote_user_id' => (string) $memberId,
				'title' => trim( (string) ( $heldData['title'] ?? '' ) ) ?: 'Registration held by Forum Fortress',
				'reason' => trim( (string) ( $ffHeld['public_reason'] ?? '' ) ) ?: 'Held for review by Forum Fortress',
				'excerpt' => NULL,
				'username' => (string) $member->name,
				'content_hash' => sha1( $validationId . ':' . $memberId ),
				'content_url' => NULL,
				'available_actions' => [ 'approve', 'reject', 'spam_clean' ],
				'payload' => $payload,
			];
		}

		if ( $serializationFailures > 0 )
		{
			$snapshotComplete = FALSE;
			Log::log( 'Forum Fortress skipped ' . $serializationFailures . ' owned moderation hold(s) that could not be serialized; the snapshot remains incomplete.', 'forumfortress' );
		}
		return [ $items, $snapshotComplete, $nextCursor ];
	}

	/** @param array<string, mixed> $heldData */
	protected static function approvalLocalGeneration( Approval $approval, array $heldData ): string
	{
		$ffHeld = is_array( $heldData['forum_fortress'] ?? NULL ) ? $heldData['forum_fortress'] : [];
		unset( $ffHeld['public_reason'] );
		return static::moderationLocalGeneration( [
			'kind' => 'approval',
			'approval_id' => (int) $approval->id,
			'content_class' => (string) $approval->content_class,
			'content_id' => (int) $approval->content_id,
			'held_reason' => (string) $approval->held_reason,
			'name' => (string) ( $heldData['name'] ?? '' ),
			'title' => (string) ( $heldData['title'] ?? '' ),
			'content' => (string) ( $heldData['content'] ?? '' ),
			'forum_fortress' => $ffHeld,
		] );
	}

	/** @param array<string, mixed> $row @param array<string, mixed> $heldData */
	protected static function validationLocalGeneration( array $row, array $heldData ): string
	{
		$ffHeld = is_array( $heldData['forum_fortress'] ?? NULL ) ? $heldData['forum_fortress'] : [];
		unset( $ffHeld['public_reason'] );
		return static::moderationLocalGeneration( [
			'kind' => 'validation',
			'validation_id' => (string) ( $row['vid'] ?? '' ),
			'member_id' => (int) ( $row['member_id'] ?? 0 ),
			'spam_flag' => (int) ( $row['spam_flag'] ?? 0 ),
			'new_reg' => (int) ( $row['new_reg'] ?? 0 ),
			'member' => (bool) ( $heldData['member'] ?? FALSE ),
			'name' => (string) ( $heldData['name'] ?? '' ),
			'title' => (string) ( $heldData['title'] ?? '' ),
			'content' => (string) ( $heldData['content'] ?? '' ),
			'forum_fortress' => $ffHeld,
		] );
	}

	/** @param array<string, mixed> $value */
	protected static function moderationLocalGeneration( array $value ): string
	{
		$canonical = static::canonicaliseModerationGenerationValue( $value );
		$encoded = json_encode( $canonical, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE );
		if ( !is_string( $encoded ) )
		{
			throw new \RuntimeException( 'Unable to encode local moderation generation' );
		}
		return hash( 'sha256', $encoded );
	}

	protected static function canonicaliseModerationGenerationValue( mixed $value ): mixed
	{
		if ( !is_array( $value ) )
		{
			return $value;
		}
		if ( !array_is_list( $value ) )
		{
			ksort( $value, SORT_STRING );
		}
		foreach ( $value as $key => $entry )
		{
			$value[$key] = static::canonicaliseModerationGenerationValue( $entry );
		}
		return $value;
	}

	/**
	 * @param list<array<string, mixed>> $notes
	 */
	protected static function applyQueueNotes( array $notes ): void
	{
		foreach ( $notes as $note )
		{
			if ( !is_array( $note ) )
			{
				continue;
			}
			$type = (string) ( $note['remote_content_type'] ?? '' );
			$contentId = (int) ( $note['remote_content_id'] ?? 0 );
			$reason = trim( (string) ( $note['fortress_public_reason'] ?? '' ) );
			if ( $type === '' || $contentId <= 0 || $reason === '' )
			{
				continue;
			}
			if ( mb_strlen( $reason ) > 2000 )
			{
				$reason = mb_substr( $reason, 0, 2000 );
			}
			try
			{
				if ( $type === 'member' )
				{
					foreach ( Db::i()->select( '*', 'core_validating', [ 'member_id=?', $contentId ] ) as $row )
					{
						$held = static::ownedMemberValidationMetadata( $row );
						if ( $held === NULL )
						{
							continue;
						}
						$held['forum_fortress']['public_reason'] = $reason;
						Db::i()->update( 'core_validating', [
							'extra' => json_encode( $held, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE ),
						], [ 'vid=? AND member_id=?', (string) $row['vid'], $contentId ] );
					}
					continue;
				}

				$class = static::mapTypeToApprovalClass( $type );
				if ( $class === NULL )
				{
					continue;
				}
				$approval = Approval::loadFromContent( $class, $contentId );
				$held = is_array( $approval->held_data ) ? $approval->held_data : [];
				if ( !is_array( $held['forum_fortress'] ?? NULL ) )
				{
					continue;
				}
				$held['forum_fortress']['public_reason'] = $reason;
				$approval->held_data = $held;
				$approval->save();
			}
			catch ( Throwable $e )
			{
			}
		}
	}

	/**
	 * @param list<array<string, mixed>> $actions
	 * @return list<array<string, mixed>>
	 */
	protected static function executeModerationActions( array $actions ): array
	{
		$results = [];
		foreach ( $actions as $action )
		{
			$actionId = (int) ( $action['id'] ?? 0 );
			$type = (string) ( $action['remote_content_type'] ?? '' );
			$contentId = (int) ( $action['remote_content_id'] ?? 0 );
			$requested = (string) ( $action['action'] ?? '' );
			$approvalId = (int) ( $action['approval_id'] ?? 0 );
			$validationId = trim( (string) ( $action['validation_id'] ?? '' ) );
			$localGeneration = strtolower( trim( (string) ( $action['local_generation'] ?? '' ) ) );
			if ( $actionId <= 0 || $contentId <= 0 )
			{
				$results[] = [ 'id' => $actionId, 'status' => 'failed', 'message' => 'Invalid moderation action payload' ];
				continue;
			}

			try
			{
				if ( $type === 'member' )
				{
					static::applyMemberModerationActionAtomically(
						$validationId,
						$contentId,
						$localGeneration,
						$requested
					);
					$results[] = [ 'id' => $actionId, 'status' => 'applied', 'message' => 'Action applied' ];
					continue;
				}

				$class = static::mapTypeToApprovalClass( $type );
				if ( $class === NULL )
				{
					throw new \RuntimeException( 'Unsupported moderation action payload' );
				}
				static::applyContentModerationActionAtomically(
					$approvalId,
					$class,
					$contentId,
					$localGeneration,
					$requested
				);
				$results[] = [ 'id' => $actionId, 'status' => 'applied', 'message' => 'Action applied' ];
			}
			catch ( \OutOfRangeException $e )
			{
				$results[] = [ 'id' => $actionId, 'status' => 'applied', 'message' => 'Queue item no longer pending' ];
			}
			catch ( Throwable $e )
			{
				Log::log( 'Forum Fortress rejected a remote moderation action: ' . $e->getMessage(), 'forumfortress' );
				$results[] = [ 'id' => $actionId, 'status' => 'failed', 'message' => 'Local moderation action failed validation' ];
			}
		}

		return $results;
	}

	protected static function applyContentModerationActionAtomically(
		int $approvalId,
		string $class,
		int $contentId,
		string $localGeneration,
		string $requested
	): void
	{
		if ( $approvalId <= 0 || !preg_match( '/^[a-f0-9]{64}$/D', $localGeneration ) )
		{
			throw new \RuntimeException( 'Missing local approval generation correlation' );
		}
		static::withModerationWriteTransaction( static function () use ( $approvalId, $class, $contentId, $localGeneration, $requested ): void {
			$table = (string) $class::$databaseTable;
			$idColumn = (string) $class::$databaseColumnId;
			$contentRow = static::lockModerationRow( $table, [ "{$idColumn}=?", $contentId ] );
			$approvalRow = static::lockModerationRow( 'core_approval_queue', [ 'approval_id=?', $approvalId ] );
			$content = $class::constructFromData( $contentRow );
			if ( !method_exists( $content, 'hidden' ) || (int) $content->hidden() !== 1 )
			{
				throw new \OutOfRangeException( 'Local content is no longer pending approval' );
			}
			$approval = Approval::constructFromData( $approvalRow );
			$held = is_array( $approval->held_data ) ? $approval->held_data : [];
			if (
				(string) $approval->content_class !== $class
				|| (int) $approval->content_id !== $contentId
				|| (string) $approval->held_reason !== 'forum_fortress'
				|| !is_array( $held['forum_fortress'] ?? NULL )
				|| !hash_equals( $localGeneration, static::approvalLocalGeneration( $approval, $held ) )
			)
			{
				throw new \RuntimeException( 'Local approval generation does not match Forum Fortress state' );
			}
			static::applyModerationActionToContent( $content, $requested, $approval );
		} );
	}

	protected static function applyMemberModerationActionAtomically(
		string $validationId,
		int $memberId,
		string $localGeneration,
		string $requested
	): void
	{
		if ( $validationId === '' || $memberId <= 0 || !preg_match( '/^[a-f0-9]{64}$/D', $localGeneration ) )
		{
			throw new \RuntimeException( 'Missing local validation generation correlation' );
		}
		static::withModerationWriteTransaction( static function () use ( $validationId, $memberId, $localGeneration, $requested ): void {
			$memberRow = static::lockModerationRow( 'core_members', [ 'member_id=?', $memberId ] );
			$validationRow = static::lockModerationRow( 'core_validating', [
				'vid=? AND member_id=? AND spam_flag=? AND new_reg=?',
				$validationId,
				$memberId,
				2,
				1,
			] );
			$member = \IPS\Member::constructFromData( $memberRow );
			$held = static::ownedMemberValidationMetadata( $validationRow );
			if (
				empty( $member->members_bitoptions['validating'] )
				|| $held === NULL
				|| !hash_equals( $localGeneration, static::validationLocalGeneration( $validationRow, $held ) )
			)
			{
				throw new \RuntimeException( 'Local validation generation does not match Forum Fortress state' );
			}
			static::applyModerationActionToMember( $member, $requested, $validationRow );
		} );
	}

	/** @param array<int, mixed> $where @return array<string, mixed> */
	protected static function lockModerationRow( string $table, array $where ): array
	{
		$select = Db::i()->select( '*', $table, $where, flags: Db::SELECT_FROM_WRITE_SERVER );
		$result = Db::i()->query( $select->returnFullQuery() . ' FOR UPDATE', \MYSQLI_STORE_RESULT, FALSE );
		$row = $result instanceof \mysqli_result ? $result->fetch_assoc() : NULL;
		if ( $result instanceof \mysqli_result )
		{
			$result->free();
		}
		if ( !is_array( $row ) )
		{
			throw new \OutOfRangeException( 'Local moderation row no longer exists' );
		}
		return $row;
	}

	protected static function withModerationWriteTransaction( callable $callback ): void
	{
		$db = Db::i();
		$db->query( 'START TRANSACTION', \MYSQLI_STORE_RESULT, FALSE );
		try
		{
			$callback();
			$db->query( 'COMMIT', \MYSQLI_STORE_RESULT, FALSE );
		}
		catch ( Throwable $e )
		{
			try
			{
				$db->query( 'ROLLBACK', \MYSQLI_STORE_RESULT, FALSE );
			}
			catch ( Throwable $rollbackError )
			{
			}
			throw $e;
		}
	}

	protected static function applyModerationActionToContent( object $content, string $requested, Approval $approval ): void
	{
		if ( $requested === 'approve' )
		{
			$held = is_array( $approval->held_data ) ? $approval->held_data : [];
			$ffHeld = is_array( $held['forum_fortress'] ?? NULL ) ? $held['forum_fortress'] : [];
			if ( !empty( $ffHeld['content_was_new'] ) && method_exists( $content, 'unhide' ) )
			{
				$content->unhide( FALSE );
				static::deleteOwnedApprovalById( (int) $approval->id );
				return;
			}
			static::restoreEditedContentWithoutApprovalSideEffects( $content, TRUE );
			static::deleteOwnedApprovalById( (int) $approval->id );
			return;
		}
		else if ( $requested === 'reject' || $requested === 'spam_clean' )
		{
			if ( $requested === 'spam_clean' && method_exists( $content, 'spam' ) )
			{
				$content->spam();
				return;
			}
			if ( $requested === 'reject' && static::getBlockRejectAction() === 'hide' && method_exists( $content, 'hide' ) )
			{
				/* Convert pending back to its accounted visible state without firing
				 * first-approval effects, then use IC5's real visible-to-soft-delete
				 * lifecycle. This avoids subtracting visible counters twice. */
				static::restoreEditedContentWithoutApprovalSideEffects( $content, FALSE );
				$content->hide( FALSE, 'Rejected by Forum Fortress' );
				static::deleteOwnedApprovalById( (int) $approval->id );
				return;
			}
			if ( method_exists( $content, 'delete' ) )
			{
				$content->delete();
				return;
			}
		}

		throw new \RuntimeException( 'Unsupported moderation action for content type' );
	}

	protected static function restoreEditedContentWithoutApprovalSideEffects( object $content, bool $reindex ): void
	{
		$columnMap = is_array( $content::$databaseColumnMap ?? NULL ) ? $content::$databaseColumnMap : [];
		if ( isset( $columnMap['approved'] ) )
		{
			$column = (string) $columnMap['approved'];
			$content->$column = 1;
		}
		elseif ( isset( $columnMap['hidden'] ) )
		{
			$column = (string) $columnMap['hidden'];
			$content->$column = 0;
		}
		else
		{
			throw new \RuntimeException( 'Content type does not expose a native approval state' );
		}
		$content->save();

		$item = $content instanceof \IPS\Content\Comment ? $content->item() : $content;
		if ( method_exists( $item, 'resyncCommentCounts' ) )
		{
			$item->resyncCommentCounts();
		}
		if ( method_exists( $item, 'resyncLastComment' ) )
		{
			$item->resyncLastComment();
		}
		if ( method_exists( $item, 'save' ) )
		{
			$item->save();
		}
		$container = method_exists( $item, 'container' ) ? $item->container() : NULL;
		if ( is_object( $container ) )
		{
			if ( method_exists( $container, 'resetCommentCounts' ) )
			{
				$container->resetCommentCounts();
			}
			if ( method_exists( $container, 'setLastComment' ) )
			{
				$container->setLastComment();
			}
			if ( method_exists( $container, 'save' ) )
			{
				$container->save();
			}
		}

		$author = method_exists( $content, 'author' ) ? $content->author() : NULL;
		$incrementPostCount = FALSE;
		if ( is_object( $author ) && (int) ( $author->member_id ?? 0 ) > 0 && is_object( $container ) )
		{
			if ( $content instanceof \IPS\Content\Comment )
			{
				$class = get_class( $content );
				$incrementPostCount = $class::incrementPostCount( $container );
			}
			elseif ( $content instanceof \IPS\Content\Item && isset( $content::$commentClass ) )
			{
				$itemClass = get_class( $content );
				$commentClass = $content::$commentClass;
				$incrementPostCount = ( $itemClass::$firstCommentRequired && $commentClass::incrementPostCount( $container ) )
					|| $itemClass::incrementPostCount( $container );
			}
		}
		if ( $incrementPostCount )
		{
			$author->member_posts++;
			$author->save();
		}
		static::syncDerivedContentVisibility( $content, TRUE );

		if ( $reindex )
		{
			$indexContent = $content;
			if ( $content instanceof \IPS\Content\Item && $content::$firstCommentRequired && method_exists( $content, 'firstComment' ) )
			{
				$indexContent = $content->firstComment();
			}
			\IPS\Content\Search\Index::i()->index( $indexContent );
		}
	}

	protected static function syncDerivedContentVisibility( object $content, bool $visible ): void
	{
		if ( \IPS\IPS::classUsesTrait( $content, 'IPS\Content\Taggable' ) && method_exists( $content, 'tagAAIKey' ) )
		{
			Db::i()->update( 'core_tags_perms', [ 'tag_perm_visible' => $visible ? 1 : 0 ], [
				'tag_perm_aai_lookup=?',
				$content->tagAAIKey(),
			] );
		}

		$idColumn = $content::$databaseColumnId ?? NULL;
		$contentId = is_string( $idColumn ) ? (int) $content->$idColumn : 0;
		if ( $contentId <= 0 )
		{
			return;
		}
		$solvedWhere = [ [ 'app=?', (string) $content::$application ] ];
		$item = $content;
		if ( $content instanceof \IPS\Content\Item )
		{
			if ( isset( $content::$commentClass ) )
			{
				$solvedWhere[] = [ 'comment_class=?', $content::$commentClass ];
			}
			$solvedWhere[] = [ 'item_id=?', $contentId ];
		}
		else if ( $content instanceof \IPS\Content\Comment )
		{
			$item = $content->item();
			$solvedWhere[] = [ 'comment_class=?', get_class( $content ) ];
			$solvedWhere[] = [ 'comment_id=?', $contentId ];
		}
		Db::i()->update( 'core_solved_index', [ 'hidden' => $visible ? 0 : 1 ], $solvedWhere );
		if ( \IPS\IPS::classUsesTrait( $item, 'IPS\Content\Helpful' ) && method_exists( $item, 'recountHelpfuls' ) )
		{
			$item->recountHelpfuls();
		}
	}

	/** @param array<string, mixed> $validationRow */
	protected static function applyModerationActionToMember( \IPS\Member $member, string $requested, array $validationRow ): void
	{
		$held = static::ownedMemberValidationMetadata( $validationRow );
		if ( $held === NULL )
		{
			throw new \RuntimeException( 'Forum Fortress validation metadata is missing' );
		}
		$metadata = $held['forum_fortress'];
		if ( $requested === 'spam_clean' )
		{
			static::releaseOwnedMemberValidation( $member, $validationRow );
			$member->flagAsSpammer();
			return;
		}
		if ( $requested === 'reject' )
		{
			$member->delete();
			return;
		}
		if ( $requested !== 'approve' )
		{
			throw new \RuntimeException( 'Unsupported moderation action for member' );
		}

		/* A member can be held by a nested profile-save listener. Refresh the
		 * ActiveRecord from the database so a stale outer save cannot mask the
		 * restriction that Forum Fortress actually wrote. */
		try
		{
			$current = Db::i()->select( '*', 'core_members', [ 'member_id=?', (int) $member->member_id ] )->first();
			if ( is_array( $current ) )
			{
				$member = \IPS\Member::constructFromData( $current );
			}
		}
		catch ( Throwable $e )
		{
		}

		static::$memberMutationInProgress = TRUE;
		try
		{
			if ( !empty( $metadata['restriction_applied'] ) && (int) $member->restrict_post === -1 )
			{
				$member->restrict_post = 0;
			}
			if ( !empty( $metadata['ban_applied'] ) && (int) $member->temp_ban === -1 )
			{
				$member->temp_ban = 0;
			}
			if ( !isset( $metadata['restriction_applied'] ) && (int) $member->restrict_post === 1 )
			{
				$member->restrict_post = 0;
			}
			if ( (string) ( $metadata['moderation_state'] ?? '' ) === 'registration_rejected' )
			{
				$member->validationComplete( FALSE );
			}
			else
			{
				static::releaseOwnedMemberValidation( $member, $validationRow );
			}
		}
		finally
		{
			static::$memberMutationInProgress = FALSE;
		}
	}

	/** @param array<string, mixed> $validationRow */
	protected static function releaseOwnedMemberValidation( \IPS\Member $member, array $validationRow ): void
	{
		if ( static::ownedMemberValidationMetadata( $validationRow ) === NULL )
		{
			throw new \RuntimeException( 'Refusing to release an unowned validation row' );
		}
		Db::i()->delete( 'core_validating', [
			'vid=? AND member_id=?',
			(string) $validationRow['vid'],
			(int) $member->member_id,
		] );
		if ( !(int) Db::i()->select( 'COUNT(*)', 'core_validating', [
			'member_id=? AND new_reg=?',
			(int) $member->member_id,
			1,
		] )->first() )
		{
			$member->members_bitoptions['validating'] = FALSE;
			$member->save();
		}
	}

	protected static function deleteOwnedApprovalById( int $approvalId ): void
	{
		if ( $approvalId <= 0 )
		{
			return;
		}
		try
		{
			$approval = Approval::load( $approvalId );
			$held = is_array( $approval->held_data ) ? $approval->held_data : [];
			if ( (string) $approval->held_reason === 'forum_fortress' && is_array( $held['forum_fortress'] ?? NULL ) )
			{
				$approval->delete();
			}
		}
		catch ( \OutOfRangeException $e )
		{
		}
	}

	protected static function deleteApprovalQueueFor( object $content ): void
	{
		$idColumn = $content::$databaseColumnId ?? NULL;
		$contentId = is_string( $idColumn ) ? (int) $content->$idColumn : 0;
		if ( $contentId > 0 )
		{
			try
			{
				$approval = Approval::loadFromContent( get_class( $content ), $contentId );
				$held = is_array( $approval->held_data ) ? $approval->held_data : [];
				if ( (string) $approval->held_reason === 'forum_fortress' && is_array( $held['forum_fortress'] ?? NULL ) )
				{
					$approval->delete();
				}
			}
			catch ( \OutOfRangeException $e )
			{
			}
		}
	}

	protected static function mapTypeToApprovalClass( string $type ): ?string
	{
		if ( $type === 'thread' )
		{
			return 'IPS\\forums\\Topic';
		}
		if ( $type === 'post' )
		{
			return 'IPS\\forums\\Topic\\Post';
		}
		if ( $type === 'member' )
		{
			return 'IPS\\Member';
		}

		return NULL;
	}

	protected static function buildApprovalContentUrl( string $type, int $contentId ): ?string
	{
		$class = static::mapTypeToApprovalClass( $type );
		if ( $class === NULL || $contentId <= 0 )
		{
			return NULL;
		}
		try
		{
			$content = $class::load( $contentId );
			if ( method_exists( $content, 'url' ) )
			{
				return (string) $content->url();
			}
		}
		catch ( Throwable $e )
		{
		}

		return NULL;
	}

	protected static function withCheckRequestId( array $payload ): array
	{
		if ( !isset( $payload['check_request_id'] ) || trim( (string) $payload['check_request_id'] ) === '' )
		{
			$payload['check_request_id'] = bin2hex( random_bytes( 16 ) );
		}

		return $payload;
	}

	protected static function preparePayload( array $payload ): array
	{
		$key = static::apiKey();
		$out = array_merge(
			[
				'domain' => static::forumDomain(),
				'platform' => static::PLATFORM,
			],
			$payload
		);

		if ( $key !== '' )
		{
			$out['api_key'] = $key;
		}

		return $out;
	}

	protected static function persistIdentity( array $response, string $usedBase = '' ): void
	{
		$wasOffline = static::isOfflineApiKey();
		$keyType = isset( $response['key_type'] ) ? (string) $response['key_type'] : '';
		$apiKey = isset( $response['api_key'] ) ? trim( (string) $response['api_key'] ) : '';
		$updates = [];

		if ( $apiKey !== '' && $apiKey !== static::apiKey() )
		{
			$updates['ff_api_key'] = static::encryptApiKeyForStorage( $apiKey );
		}

		if ( !empty( $response['site_id'] ) && $response['site_id'] !== Settings::i()->ff_site_id )
		{
			$updates['ff_site_id'] = (string) $response['site_id'];
		}

		if ( $updates )
		{
			Settings::i()->changeValues( $updates );
		}

		/* Only a keyed bootstrap/identity response is authoritative enough to
		 * replace or clear node-bound offline routing. Ordinary API responses omit
		 * api_key and must leave a working regional pin untouched. */
		if ( $apiKey !== '' )
		{
			$state = static::loadEndpointState();
			\FfApiResilience::applyOfflineBootstrapRouting( $response, $state, $usedBase );
			static::saveEndpointState( $state );
			if ( \FfApiResilience::isOfflineBootstrapKey( $apiKey, $keyType !== '' ? $keyType : NULL ) )
			{
				Log::log( 'Forum Fortress: control plane unavailable; using temporary regional key', 'forumfortress' );
			}
			elseif ( $wasOffline )
			{
				Log::log( 'Forum Fortress migrated to a normal control-plane API key.', 'forumfortress' );
			}
		}
	}

	protected static function loadEndpointState(): array
	{
		$raw = trim( (string) Settings::i()->ff_endpoint_state );
		if ( $raw === '' )
		{
			return [];
		}

		$data = json_decode( $raw, TRUE );

		return is_array( $data ) ? $data : [];
	}

	protected static function saveEndpointState( array $state ): void
	{
		ksort( $state );
		$encoded = json_encode( $state, JSON_UNESCAPED_SLASHES );
		if ( !is_string( $encoded ) )
		{
			return;
		}

		if ( (string) Settings::i()->ff_endpoint_state === $encoded )
		{
			return;
		}

		Settings::i()->changeValues( [ 'ff_endpoint_state' => $encoded ] );
	}

	public static function endpointStateSummary(): array
	{
		$state = static::loadEndpointState();
		$lastRespondedNode = trim( (string) ( $state['last_responded_node'] ?? '' ) );
		$lastRespondedBase = trim( (string) ( $state['last_responded'] ?? '' ) );

		return [
			// Compatibility key for existing admin templates. The route is no
			// longer selected from plugin-maintained preference state.
			'preferred' => static::normaliseBaseUrl( static::baseUrl() ),
			'last_responded' => $lastRespondedNode !== '' ? $lastRespondedNode : $lastRespondedBase,
			'endpoints_count' => is_array( $state['endpoints'] ?? NULL ) ? count( $state['endpoints'] ) : 1,
			'last_health_at' => (int) ( $state['catalog_fetched_at'] ?? 0 ),
			'last_site_ping_at' => (int) ( $state['last_site_ping_at'] ?? 0 ),
			'preferred_missing' => '',
		];
	}

	public static function endpointHealthDisplayLabel( string $endpointUrl, ?array $state = NULL ): string
	{
		$state = $state ?? static::loadEndpointState();
		$endpointUrl = static::normaliseBaseUrl( $endpointUrl );
		if ( $endpointUrl === static::normaliseBaseUrl( static::baseUrl() ) )
		{
			return 'GeoDNS primary';
		}
		$meta = is_array( $state['endpoint_meta'][ $endpointUrl ] ?? NULL ) ? $state['endpoint_meta'][ $endpointUrl ] : [];
		$role = strtolower( (string) ( $meta['role'] ?? '' ) );
		if ( static::isCatalogBackupEndpointUrl( $endpointUrl, $role ) )
		{
			return 'control fallback';
		}
		return array_key_exists( 'check_ready', $meta ) && empty( $meta['check_ready'] )
			? 'catalog standby'
			: 'catalog fallback';
	}
	/**
	 * @return list<array{endpoint: string, latency: string, is_preferred: bool}>
	 */
	public static function buildEndpointLatencyRows(): array
	{
		$state = static::loadEndpointState();
		$primary = static::normaliseBaseUrl( static::baseUrl() );
		$targets = \FfApiResilience::uniqueOrderedBases(
			$primary !== '' ? [ $primary ] : [],
			is_array( $state['endpoints'] ?? NULL ) ? $state['endpoints'] : []
		);
		$rows = [];
		foreach ( $targets as $endpointUrl )
		{
			$rows[] = [
				'endpoint' => $endpointUrl,
				'latency' => static::endpointHealthDisplayLabel( $endpointUrl, $state ),
				'is_preferred' => $endpointUrl === $primary,
			];
		}
		return $rows;
	}
	public static function refreshEndpointCatalogAndHealth( bool $force = FALSE, ?int $probeTimeout = NULL ): void
	{
		if ( !static::enabled() )
		{
			return;
		}
		$primary = static::normaliseBaseUrl( static::baseUrl() );
		if ( $primary === '' )
		{
			return;
		}
		$state = static::loadEndpointState();
		if ( $force )
		{
			$state['catalog_fetched_at'] = 0;
			static::saveEndpointState( $state );
		}
		if ( $force || \FfApiResilience::isEndpointCatalogStale( $state ) )
		{
			static::fetchNodeEndpointsCatalog( $force, $probeTimeout );
			$state = static::loadEndpointState();
		}
		$endpoints = is_array( $state['endpoints'] ?? NULL ) ? $state['endpoints'] : [];
		$state['endpoints'] = static::normaliseAndSanitiseEndpoints( $endpoints, $primary );
		$state['preferred'] = $primary;
		$state['refresh_requested_at'] = 0;
		unset(
			$state['health_day'],
			$state['health_ms'],
			$state['last_health_at'],
			$state['health_timed_out'],
			$state['slow_health_mode'],
			$state['best_latency_ms'],
			$state['preferred_candidate'],
			$state['preferred_candidate_streak'],
			$state['preferred_missing'],
			$state['preferred_missing_at'],
			$state['suppressed_endpoints']
		);
		static::saveEndpointState( $state );
	}
	/**
	 * @param list<mixed> $endpoints
	 * @return list<string>
	 */
	protected static function normaliseAndSanitiseEndpoints( array $endpoints, string $manualBase ): array
	{
		$manualBase = static::normaliseBaseUrl( $manualBase );
		$normalised = array_values( array_unique( array_map( static fn( $u ) => static::normaliseBaseUrl( (string) $u ), $endpoints ) ) );
		$normalised = array_values( array_filter( $normalised, static fn( $u ) => $u !== '' && static::isTrustedEndpointBase( $u ) ) );
		if ( $manualBase !== '' && count( $normalised ) > 1 )
		{
			$normalised = array_values( array_filter( $normalised, static fn( $u ) => $u !== $manualBase ) );
		}
		if ( !$normalised && $manualBase !== '' )
		{
			$normalised = [ $manualBase ];
		}
		return $normalised;
	}

	/**
	 * The catalog controls whether the concrete control fallback may serve checks.
	 * Normal check routing itself always starts at the GeoDNS hostname.
	 */
	protected static function baseUrlMayServeCheckTraffic( string $baseUrl ): bool
	{
		$baseUrl = static::normaliseBaseUrl( $baseUrl );
		$control = static::normaliseBaseUrl( static::controlBaseUrl() );
		if ( $baseUrl === '' || $baseUrl !== $control )
		{
			return $baseUrl !== '';
		}
		$state = static::loadEndpointState();
		if ( !empty( $state['control_check_fallback'] ) )
		{
			return TRUE;
		}
		foreach ( is_array( $state['endpoint_meta'] ?? NULL ) ? $state['endpoint_meta'] : [] as $url => $meta )
		{
			if ( !is_array( $meta ) || empty( $meta['check_ready'] ) )
			{
				continue;
			}
			$role = isset( $meta['role'] ) ? (string) $meta['role'] : NULL;
			if ( !static::isCatalogBackupEndpointUrl( (string) $url, $role ) )
			{
				return FALSE;
			}
		}
		return TRUE;
	}

	protected static function getOrderedBasesForRequests( ?string $requestPath = NULL ): array
	{
		$primary = static::normaliseBaseUrl( static::baseUrl() );
		if ( $primary === '' )
		{
			return [];
		}
		$state = static::loadEndpointState();
		if ( static::isOfflineApiKey() )
		{
			$pinned = \FfApiResilience::offlinePinnedCheckBases( $state );
			if ( $pinned && static::isTrustedEndpointBase( (string) $pinned[0] ) )
			{
				return $pinned;
			}
		}
		return \FfApiResilience::regionLockedCheckBases(
			static::apiRegion(),
			static::allowGlobalEmergencyFallback()
		);
	}
	protected static function shouldFailoverOnIntermittentStatus( int $status, string $path ): bool
	{
		if ( !in_array( $status, [ 401, 404 ], TRUE ) )
		{
			return FALSE;
		}
		return in_array(
			$path,
			[
				'/v1/site/portal',
				'/v1/site/status',
				'/v1/forum/stats',
				'/v1/moderation-queue/sync',
				'/v1/moderation-actions/pull',
				'/v1/moderation-actions/ack',
				'/v1/plugin-release',
			],
			TRUE
		);
	}

	protected static function rawRequest( string $method, string $baseUrl, string $path, array $body, int $timeout ): array
	{
		$out = [ 'status' => 0, 'body' => '', 'data' => NULL, 'error' => NULL, 'node_header' => '', 'timed_out' => FALSE ];
		$startedAt = microtime( TRUE );
		$baseUrl = static::normaliseBaseUrl( $baseUrl );
		if ( $baseUrl === '' || !static::isTrustedEndpointBase( $baseUrl ) )
		{
			$out['error'] = $baseUrl === '' ? 'empty_base' : 'untrusted_base';
			return $out;
		}

		$curl = NULL;
		try
		{
			if ( !function_exists( 'curl_init' ) )
			{
				throw new \RuntimeException( 'cURL is unavailable' );
			}
			$method = strtoupper( $method );
			$requestScheme = strtolower( (string) parse_url( $baseUrl, PHP_URL_SCHEME ) );
			$url = $baseUrl . $path;
			$headers = [ 'Accept: application/json', 'User-Agent: Forum-Fortress-Invision/' . static::PLUGIN_VERSION ];
			if ( $method === 'GET' )
			{
				$apiKey = trim( str_replace( [ "\r", "\n" ], '', (string) ( $body['api_key'] ?? '' ) ) );
				unset( $body['api_key'] );
				if ( $apiKey !== '' )
				{
					$headers[] = 'X-FF-Key: ' . $apiKey;
				}
				if ( $body )
				{
					$url .= '?' . http_build_query( $body, '', '&', PHP_QUERY_RFC3986 );
				}
			}
			else
			{
				$headers[] = 'Content-Type: application/json';
			}

			$curl = curl_init();
			if ( $curl === FALSE )
			{
				throw new \RuntimeException( 'Unable to initialize cURL' );
			}
			$responseBody = '';
			$responseTooLarge = FALSE;
			curl_setopt_array( $curl, [
				CURLOPT_URL => $url,
				CURLOPT_CUSTOMREQUEST => $method,
				CURLOPT_HTTPHEADER => $headers,
				CURLOPT_FOLLOWLOCATION => FALSE,
				CURLOPT_MAXREDIRS => 0,
				CURLOPT_CONNECTTIMEOUT => max( 1, min( 3, $timeout ) ),
				CURLOPT_TIMEOUT => max( 1, $timeout ),
				CURLOPT_NOSIGNAL => TRUE,
				CURLOPT_RETURNTRANSFER => TRUE,
				CURLOPT_HEADER => FALSE,
				CURLOPT_WRITEFUNCTION => static function ( $handle, string $chunk ) use ( &$responseBody, &$responseTooLarge ): int {
					if ( strlen( $responseBody ) + strlen( $chunk ) > self::MAX_API_RESPONSE_BYTES )
					{
						$responseTooLarge = TRUE;
						return 0;
					}
					$responseBody .= $chunk;
					return strlen( $chunk );
				},
				CURLOPT_HEADERFUNCTION => static function ( $handle, string $line ) use ( &$out ): int {
					$separator = strpos( $line, ':' );
					if ( $separator !== FALSE )
					{
						$name = strtolower( trim( substr( $line, 0, $separator ) ) );
						if ( in_array( $name, [ 'x-forumfortress-node', 'x-ff-serving-node' ], TRUE ) )
						{
							$out['node_header'] = trim( substr( $line, $separator + 1 ) );
						}
					}
					return strlen( $line );
				},
			] );
			if ( defined( 'CURLOPT_PROTOCOLS_STR' ) )
			{
				curl_setopt( $curl, CURLOPT_PROTOCOLS_STR, $requestScheme );
			}
			else
			{
				curl_setopt( $curl, CURLOPT_PROTOCOLS, $requestScheme === 'https' ? CURLPROTO_HTTPS : CURLPROTO_HTTP );
			}
			if ( $requestScheme === 'https' )
			{
				curl_setopt( $curl, CURLOPT_SSL_VERIFYHOST, 2 );
				curl_setopt( $curl, CURLOPT_SSL_VERIFYPEER, TRUE );
			}
			if ( $method !== 'GET' )
			{
				$encoded = json_encode( $body, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE );
				if ( !is_string( $encoded ) )
				{
					throw new \RuntimeException( 'Unable to encode API request' );
				}
				curl_setopt( $curl, CURLOPT_POSTFIELDS, $encoded );
			}

			$executed = curl_exec( $curl );
			$out['status'] = (int) curl_getinfo( $curl, CURLINFO_RESPONSE_CODE );
			if ( $executed === FALSE )
			{
				$out['error'] = $responseTooLarge ? 'response_too_large' : curl_error( $curl );
			}
			$out['body'] = $responseBody;
			if ( $out['body'] !== '' )
			{
				$decoded = json_decode( $out['body'], TRUE );
				$out['data'] = is_array( $decoded ) ? $decoded : NULL;
			}
		}
		catch ( Throwable $e )
		{
			$out['error'] = $e->getMessage();
		}
		finally
		{
			if ( $curl instanceof \CurlHandle )
			{
				curl_close( $curl );
			}
		}
		$elapsed = microtime( TRUE ) - $startedAt;
		$out['timed_out'] = static::isTimeoutMessage( (string) ( $out['error'] ?? '' ) )
			|| ( (int) $out['status'] === 0 && $elapsed >= max( 0.75, $timeout * 0.75 ) );

		return $out;
	}

	/** Bootstrap, catalog, capabilities, plugin-release: control, hot api.ffapi.net, then edges. */
	protected static function requestFromControlPlane( string $method, string $path, array $body, ?int $timeoutOverride = NULL ): ?array
	{
		if ( !static::isEnabled() )
		{
			return NULL;
		}
		$bases = static::controlPlaneRequestBases();
		if ( !$bases )
		{
			$manual = static::normaliseBaseUrl( static::baseUrl() );
			if ( $manual !== '' )
			{
				$bases = [ $manual ];
			}
		}
		if ( !$bases )
		{
			return NULL;
		}
		$timeout = $timeoutOverride ?? max( 1, (int) Settings::i()->ff_timeout );
		foreach ( $bases as $base )
		{
			$res = static::rawRequest( $method, $base, $path, $body, $timeout );
			$status = (int) ( $res['status'] ?? 0 );
			$data = $res['data'] ?? NULL;
			if ( $status >= 200 && $status < 300 && is_array( $data ) )
			{
				static::persistIdentity( $data );
				$state = static::loadEndpointState();
				$state['last_responded'] = $base;
				$state['last_responded_node'] = trim( (string) ( $res['node_header'] ?? '' ) );
				$state['last_response_at'] = time();
				static::saveEndpointState( $state );
				static::maybeRefreshEndpointCatalogAfterCheckIn( $path );
				return $data;
			}
			if ( Settings::i()->ff_debug_log )
			{
				$debug = json_encode( [ 'ff_path' => $path, 'status' => $status, 'base' => $base, 'ff_control_plane' => TRUE ], JSON_UNESCAPED_SLASHES );
				Log::debug( is_string( $debug ) ? $debug : 'Forum Fortress control-plane request failed.', 'forumfortress' );
			}
		}

		return NULL;
	}

	public static function request( string $method, string $path, array $body, ?int $timeoutOverride = NULL ): ?array
	{
		$result = static::requestPass( $method, $path, $body, $timeoutOverride, TRUE );
		if ( $result !== NULL )
		{
			return $result;
		}
		return NULL;
	}

	protected static function requestModeration( string $method, string $path, array $body ): ?array
	{
		$timeout = max( self::MODERATION_SYNC_TIMEOUT_SECONDS, (int) Settings::i()->ff_timeout );
		return static::request( $method, $path, $body, $timeout );
	}

	protected static function requestPass( string $method, string $path, array $body, ?int $timeoutOverride, bool $allowRebootstrap ): ?array
	{
		$bases = static::getOrderedBasesForRequests( $path );
		if ( !$bases )
		{
			return NULL;
		}
		$isCheck = mb_strpos( $path, '/v1/check' ) === 0;
		$isContactPageCheck = \FfApiResilience::shouldUseContactPageRouting( $path, $body );
		if ( $isContactPageCheck && !static::isOfflineApiKey() && !\FfApiResilience::apiRegionIsLocked( static::apiRegion() ) )
		{
			$bases = \FfApiResilience::contactPageCheckBasesOrdered( $bases, static::hotFailoverApiBaseUrl() );
		}
		$enforceCheckBudget = $isCheck && !$isContactPageCheck;
		$timeout = $timeoutOverride ?? max( 1, (int) Settings::i()->ff_timeout );
		if ( $enforceCheckBudget )
		{
			$timeout = min( $timeout, \FfApiResilience::RUNTIME_CHECK_ENDPOINT_TIMEOUT_SECONDS );
		}
		$hotApi = $isCheck ? '' : static::hotFailoverApiBaseUrl();
		$tried = [];
		$startedAt = microtime( TRUE );

		foreach ( $bases as $index => $base )
		{
			if ( $enforceCheckBudget && ( microtime( TRUE ) - $startedAt ) >= \FfApiResilience::RUNTIME_CHECK_TOTAL_BUDGET_SECONDS )
			{
				break;
			}
			$base = static::normaliseBaseUrl( (string) $base );
			if ( $base === '' || in_array( $base, $tried, TRUE ) )
			{
				continue;
			}
			$tried[] = $base;

			$res = static::requestOnBaseWithRetry( $method, $base, $path, $body, $timeout, $allowRebootstrap && $index === 0 );
			$status = (int) ( $res['status'] ?? 0 );
			$data = $res['data'] ?? NULL;
			if ( $status >= 200 && $status < 300 && is_array( $data ) )
			{
				static::persistIdentity( $data );
				$state = static::loadEndpointState();
				$state['last_responded'] = $base;
				$state['last_responded_node'] = trim( (string) ( $res['node_header'] ?? '' ) );
				$state['last_response_at'] = time();
				static::saveEndpointState( $state );
				static::maybeRefreshEndpointCatalogAfterCheckIn( $path );
				return $data;
			}

			$canFailover = $status === 0
				|| $status === 520
				|| \FfApiResilience::shouldFailoverOnEndpointStatus( $status )
				|| static::shouldFailoverOnIntermittentStatus( $status, (string) $path );
			if ( $canFailover )
			{
				static::markEndpointRefreshRequested();
			}
			if ( !$canFailover )
			{
				if ( Settings::i()->ff_debug_log )
				{
					$debug = json_encode( [ 'ff_path' => $path, 'status' => $status, 'base' => $base ], JSON_UNESCAPED_SLASHES );
					Log::debug( is_string( $debug ) ? $debug : 'Forum Fortress API request failed.', 'forumfortress' );
				}
				return NULL;
			}

			if ( $hotApi !== '' && !in_array( $hotApi, $tried, TRUE ) && ( !$enforceCheckBudget || ( microtime( TRUE ) - $startedAt ) < \FfApiResilience::RUNTIME_CHECK_TOTAL_BUDGET_SECONDS ) )
			{
				$tried[] = $hotApi;
				$hotRes = static::requestOnBaseWithRetry( $method, $hotApi, $path, $body, $timeout, FALSE );
				$hotStatus = (int) ( $hotRes['status'] ?? 0 );
				$hotData = $hotRes['data'] ?? NULL;
				if ( $hotStatus >= 200 && $hotStatus < 300 && is_array( $hotData ) )
				{
					static::persistIdentity( $hotData );
					$state = static::loadEndpointState();
					$state['last_responded'] = $hotApi;
					$state['last_responded_node'] = trim( (string) ( $hotRes['node_header'] ?? '' ) );
					$state['last_response_at'] = time();
					static::saveEndpointState( $state );
					static::maybeRefreshEndpointCatalogAfterCheckIn( $path );
					return $hotData;
				}
				$hotCanFailover = $hotStatus === 0
					|| $hotStatus === 520
					|| \FfApiResilience::shouldFailoverOnEndpointStatus( $hotStatus )
					|| static::shouldFailoverOnIntermittentStatus( $hotStatus, (string) $path );
				if ( !$hotCanFailover )
				{
					return NULL;
				}
			}
		}

		/* Contact checks already consumed their bounded hot-API/edge list. */
		if ( $isContactPageCheck )
		{
			return NULL;
		}
		if ( $enforceCheckBudget && ( microtime( TRUE ) - $startedAt ) >= \FfApiResilience::RUNTIME_CHECK_TOTAL_BUDGET_SECONDS )
		{
			return NULL;
		}

		if ( $isCheck && \FfApiResilience::apiRegionIsLocked( static::apiRegion() ) )
		{
			return NULL;
		}

		return static::requestControlCheckFallbackAfterEdges(
			$method,
			$path,
			$body,
			$tried,
			$timeoutOverride,
			$allowRebootstrap
		);
	}

	/**
	 * @param list<string> $tried
	 */
	protected static function requestControlCheckFallbackAfterEdges(
		string $method,
		string $path,
		array $body,
		array $tried,
		?int $timeoutOverride,
		bool $allowRebootstrap
	): ?array {
		if ( mb_strpos( $path, '/v1/check' ) !== 0 )
		{
			return NULL;
		}
		$state = static::loadEndpointState();
		if ( empty( $state['control_check_fallback'] ) )
		{
			return NULL;
		}
		$control = static::normaliseBaseUrl( static::controlBaseUrl() );
		if ( $control === '' || in_array( $control, $tried, TRUE ) )
		{
			return NULL;
		}
		if ( !static::baseUrlMayServeCheckTraffic( $control ) )
		{
			return NULL;
		}
		$timeout = $timeoutOverride ?? max( 1, (int) Settings::i()->ff_timeout );
		$res = static::requestOnBaseWithRetry( $method, $control, $path, $body, $timeout, FALSE );
		$status = (int) ( $res['status'] ?? 0 );
		$data = $res['data'] ?? NULL;
		if ( $status >= 200 && $status < 300 && is_array( $data ) )
		{
			static::persistIdentity( $data );
			$state = static::loadEndpointState();
			$state['last_responded'] = $control;
			$state['last_responded_node'] = trim( (string) ( $res['node_header'] ?? '' ) );
			$state['last_response_at'] = time();
			static::saveEndpointState( $state );
			static::maybeRefreshEndpointCatalogAfterCheckIn( $path );

			return $data;
		}

		return NULL;
	}

	protected static function requestOnBaseWithRetry(
		string $method,
		string $base,
		string $path,
		array $body,
		int $timeout,
		bool $allowRebootstrap,
		bool $timeoutRetried = FALSE
	): array {
		$res = static::rawRequest( $method, $base, $path, $body, $timeout );
		$status = (int) ( $res['status'] ?? 0 );
		$responseBody = (string) ( $res['body'] ?? '' );
		$error = (string) ( $res['error'] ?? '' );
		$timedOut = !empty( $res['timed_out'] ) || ( $error !== '' && static::isTimeoutMessage( $error ) );
		if ( $timedOut )
		{
			static::$lastCheckHadTimeout = TRUE;
		}
		if (
			mb_strpos( $path, '/v1/check' ) === 0
			&& $status >= 200
			&& $status < 300
			&& is_array( $res['data'] ?? NULL )
		)
		{
			static::$lastCheckHadTimeout = FALSE;
		}
		if ( $timedOut && !$timeoutRetried && ( mb_strpos( $path, '/v1/check' ) !== 0 || \FfApiResilience::apiRegionIsLocked( static::apiRegion() ) ) )
		{
			return static::requestOnBaseWithRetry( $method, $base, $path, $body, $timeout, $allowRebootstrap, TRUE );
		}
		if ( $timedOut )
		{
			static::markEndpointRefreshRequested();
		}
		$decodedError = is_array( $res['data'] ?? NULL ) ? $res['data'] : json_decode( $responseBody, TRUE );
		if (
			$allowRebootstrap
			&& $status === 403
			&& static::isOfflineApiKey()
			&& \FfApiResilience::isNodeMismatchResponse( is_array( $decodedError ) ? $decodedError : NULL )
		)
		{
			$bootstrap = static::tryOfflineFailoverRebootstrap( $timeout );
			if ( $bootstrap )
			{
				$retried = $body;
				if ( array_key_exists( 'api_key', $retried ) )
				{
					$retried['api_key'] = static::apiKey();
				}
				if ( array_key_exists( 'site_id', $retried ) )
				{
					$retried['site_id'] = trim( (string) Settings::i()->ff_site_id );
				}
				if ( array_key_exists( 'domain', $retried ) )
				{
					$retried['domain'] = static::bootstrapDomain();
				}
				$retryBases = static::getOrderedBasesForRequests( $path );
				$retryBase = static::normaliseBaseUrl( (string) ( $retryBases[0] ?? $bootstrap['base'] ) );
				return static::requestOnBaseWithRetry( $method, $retryBase, $path, $retried, $timeout, FALSE, $timeoutRetried );
			}
			return $res;
		}
		if ( $allowRebootstrap && static::shouldRebootstrap( $status, $responseBody, $path ) )
		{
			$previousStoredKey = (string) Settings::i()->ff_api_key;
			$previousSiteId = (string) Settings::i()->ff_site_id;
			if ( $status === 409 && static::responseErrorCode( $responseBody ) === 'stale_site' )
			{
				Settings::i()->changeValues( [ 'ff_site_id' => '' ] );
			}
			else
			{
				static::resetIdentity();
			}
			$bootstrap = static::bootstrapIfNeeded();
			if ( is_array( $bootstrap ) && static::apiKey() !== '' && trim( (string) Settings::i()->ff_site_id ) !== '' )
			{
				// Swap *all* identity fields the retry payload carries. The
				// freshly-minted credentials have a new site_id, so leaving
				// stale values here causes the server to return 409 stale_site.
				$retried = $body;
				if ( array_key_exists( 'api_key', $retried ) )
				{
					$retried['api_key'] = static::apiKey();
				}
				if ( array_key_exists( 'site_id', $retried ) )
				{
					$retried['site_id'] = trim( (string) Settings::i()->ff_site_id );
				}
				return static::requestOnBaseWithRetry( $method, $base, $path, $retried, $timeout, FALSE, $timeoutRetried );
			}
			Settings::i()->changeValues( [
				'ff_api_key' => $previousStoredKey,
				'ff_site_id' => $previousSiteId,
			] );
		}
		return $res;
	}

	protected static function shouldRebootstrap( int $status, string $body, string $path ): bool
	{
		if ( $path === '/v1/site/bootstrap' || static::apiKey() === '' )
		{
			return FALSE;
		}
		$code = static::responseErrorCode( $body );
		if ( $status === 409 )
		{
			return $code === 'stale_site';
		}
		if ( $status !== 401 )
		{
			return FALSE;
		}
		return in_array( $code, [ 'invalid_key', 'invalid_api_key', 'unknown_site', 'invalid_key_format', 'site_not_found', 'invalid api key', 'site not found' ], TRUE );
	}

	protected static function responseErrorCode( string $body ): string
	{
		$data = json_decode( $body, TRUE );
		if ( !is_array( $data ) )
		{
			return '';
		}
		if ( isset( $data['error'] ) )
		{
			return strtolower( trim( (string) $data['error'] ) );
		}
		$detail = $data['detail'] ?? NULL;
		if ( is_array( $detail ) && isset( $detail['error'] ) )
		{
			return strtolower( trim( (string) $detail['error'] ) );
		}
		return is_string( $detail ) ? strtolower( trim( $detail ) ) : '';
	}

	protected static function resetIdentity(): void
	{
		Settings::i()->changeValues( [
			'ff_api_key' => '',
			'ff_site_id' => '',
		] );
	}

	protected static function isTimeoutMessage( string $message ): bool
	{
		$text = strtolower( trim( $message ) );
		if ( $text === '' )
		{
			return FALSE;
		}
		return strpos( $text, 'timed out' ) !== FALSE
			|| strpos( $text, 'timeout' ) !== FALSE
			|| strpos( $text, 'cURL error 28' ) !== FALSE;
	}

	protected static function getModerationSyncIntervalSeconds( array $state ): int
	{
		if ( (int) ( $state['moderation_pending_actions'] ?? 0 ) > 0 )
		{
			return 60;
		}

		return self::MODERATION_SYNC_SECONDS;
	}

	protected static function getBlockRejectAction(): string
	{
		$action = strtolower( trim( (string) ( Settings::i()->ff_block_reject_action ?? 'reject' ) ) );
		return in_array( $action, [ 'reject', 'hide' ], TRUE ) ? $action : 'reject';
	}

	/** The API models a local hide as a rejected moderation action. */
	protected static function getWireBlockRejectAction(): string
	{
		$action = static::getBlockRejectAction();
		return $action === 'hide' ? 'reject' : $action;
	}

	/** @param array<string, mixed> $response */
	protected static function hasDefinitiveCheckDecision( array $response ): bool
	{
		$decision = strtolower( trim( (string) ( $response['decision'] ?? '' ) ) );
		return in_array( $decision, [ 'allow', 'block' ], TRUE );
	}

	protected static function refreshPlanCacheIfStale( bool $force ): void
	{
		$state = static::loadEndpointState();
		$last = (int) ( $state['plan_checked_at'] ?? 0 );
		if ( !$force && $last > 0 && ( time() - $last ) < self::PLAN_REFRESH_SECONDS )
		{
			return;
		}
		$status = static::siteStatus();
		$state['plan_checked_at'] = time();
		if ( is_array( $status ) && !empty( $status['plan'] ) )
		{
			$state['plan_name'] = strtolower( trim( (string) $status['plan'] ) );
		}
		static::saveEndpointState( $state );
	}

	protected static function markEndpointRefreshRequested(): void
	{
		$state = static::loadEndpointState();
		$state['refresh_requested_at'] = time();
		static::saveEndpointState( $state );
	}

	protected static function shouldRunDailyTask( string $key ): bool
	{
		$state = static::loadEndpointState();
		$last = (int) ( $state[ $key ] ?? 0 );
		return $last <= 0 || ( time() - $last ) >= 86400;
	}

	protected static function markDailyTaskRun( string $key ): void
	{
		$state = static::loadEndpointState();
		$state[ $key ] = time();
		static::saveEndpointState( $state );
	}

	public static function emailDomain( string $email ): ?string
	{
		if ( $email === '' || mb_strpos( $email, '@' ) === FALSE )
		{
			return NULL;
		}

		$parts = explode( '@', $email, 2 );

		return isset( $parts[1] ) ? strtolower( trim( $parts[1] ) ) : NULL;
	}

	public static function extractLinks( string $text ): array
	{
		if ( $text === '' )
		{
			return [];
		}

		preg_match_all( '#https?://[^\s<>"\']+#i', $text, $matches );
		$links = is_array( $matches[0] ?? NULL ) ? $matches[0] : [];

		return array_values( array_unique( array_map( 'strval', $links ) ) );
	}

	protected static function mapApprovalClassToType( string $class ): ?string
	{
		if ( $class === 'IPS\\forums\\Topic' )
		{
			return 'thread';
		}
		if ( $class === 'IPS\\forums\\Topic\\Post' )
		{
			return 'post';
		}
		if ( $class === 'IPS\\Member' )
		{
			return 'member';
		}

		return NULL;
	}

	protected static function extractNodeHeader( object $response ): string
	{
		try
		{
			foreach ( [ 'headers', 'httpHeaders' ] as $property )
			{
				if ( isset( $response->{$property} ) && is_array( $response->{$property} ) )
				{
					foreach ( $response->{$property} as $key => $value )
					{
						if ( strtolower( trim( (string) $key ) ) === 'x-forumfortress-node' )
						{
							return trim( is_array( $value ) ? (string) reset( $value ) : (string) $value );
						}
					}
				}
			}
		}
		catch ( Throwable $e )
		{
		}
		return '';
	}
}
