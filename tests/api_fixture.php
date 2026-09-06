<?php

/* Local-only Forum Fortress API fixture used by the IPS lifecycle tests. */

$path = parse_url( $_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH ) ?: '/';
$input = file_get_contents( 'php://input' );
$payload = json_decode( $input ?: '{}', TRUE );
$payload = is_array( $payload ) ? $payload : [];
$expectedBootstrapToken = trim( (string) getenv( 'FF_IPS_BOOTSTRAP_TOKEN' ) );
$offlineMigration = str_starts_with( trim( (string) ( $payload['api_key'] ?? '' ) ), 'ff_ob_' );
if (
	$path === '/v1/site/bootstrap'
	&& $expectedBootstrapToken !== ''
	&& !$offlineMigration
	&& !hash_equals( $expectedBootstrapToken, (string) ( $payload['bootstrap_token'] ?? '' ) )
)
{
	header( 'Content-Type: application/json' );
	http_response_code( 403 );
	echo json_encode( [ 'error' => 'invalid_bootstrap_token' ] );
	exit;
}
if (
	$path === '/v1/site/bootstrap'
	&& $offlineMigration
	&& (
		trim( (string) ( $payload['offline_issuer_node_id'] ?? '' ) ) === ''
		|| trim( (string) ( $payload['offline_site_id'] ?? '' ) ) === ''
	)
)
{
	header( 'Content-Type: application/json' );
	http_response_code( 403 );
	echo json_encode( [ 'error' => 'invalid_offline_migration_scope' ] );
	exit;
}

$logPayload = $payload;
foreach ( [ 'api_key', 'bootstrap_token', 'recovery_token', 'token', 'secret' ] as $secretKey )
{
	if ( array_key_exists( $secretKey, $logPayload ) )
	{
		$logPayload[ $secretKey ] = '[redacted]';
	}
}
$logFile = getenv( 'FF_IPS_FIXTURE_LOG' );
if ( is_string( $logFile ) && $logFile !== '' )
{
	file_put_contents( $logFile, json_encode( [
		'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
		'path' => $path,
		'payload' => $logPayload,
	], JSON_UNESCAPED_SLASHES ) . "\n", FILE_APPEND | LOCK_EX );
}

header( 'Content-Type: application/json' );
header( 'X-ForumFortress-Node: local-ips-fixture' );

$base = 'http://127.0.0.1:18081';
$content = (string) ( $payload['content'] ?? $payload['signature_text'] ?? '' );
$username = (string) ( $payload['username'] ?? '' );
$malformed = str_contains( $content, 'FF_TEST_MALFORMED' );
$aboveLimit = str_contains( $content, 'FF_TEST_ABOVE_LIMIT' );
$rateLimited = str_contains( $content, 'FF_TEST_RATE_LIMIT' );
$serverError = str_contains( $content, 'FF_TEST_5XX' );
if ( str_contains( $content, 'FF_TEST_SLOW' ) )
{
	usleep( 2500000 );
}
$decision = str_contains( $content, 'FF_TEST_BLOCK' ) || str_contains( $username, 'ff_test_block' )
	? 'block'
	: 'allow';

$actionStateFile = sys_get_temp_dir() . '/ff_ips_fixture_action.json';
$fixtureStateFile = getenv( 'FF_IPS_FIXTURE_STATE' );
$fixtureStateFile = is_string( $fixtureStateFile ) ? trim( $fixtureStateFile ) : '';
$fixtureState = [];
if ( $fixtureStateFile !== '' && is_file( $fixtureStateFile ) )
{
	$decodedState = json_decode( (string) file_get_contents( $fixtureStateFile ), TRUE );
	$fixtureState = is_array( $decodedState ) ? $decodedState : [];
}
$attackModeActive = !empty( $fixtureState['attack_mode_active'] );
$failAll = !empty( $fixtureState['fail_all'] );
$queuedActions = [];
if ( $failAll && !str_starts_with( $path, '/__fixture/' ) )
{
	http_response_code( 503 );
	echo json_encode( [ 'detail' => 'fixture unavailable' ] );
	exit;
}
if ( $path === '/__fixture/queue-action' )
{
	file_put_contents( $actionStateFile, json_encode( $payload['actions'] ?? [] ), LOCK_EX );
	$response = [ 'accepted' => TRUE ];
}
else
{
	if ( $path === '/v1/site/attack-mode' )
	{
		$attackModeActive = TRUE;
	}
	elseif ( $path === '/v1/site/attack-mode/end' )
	{
		$attackModeActive = FALSE;
	}
	if ( $fixtureStateFile !== '' && ( $path === '/v1/site/attack-mode' || $path === '/v1/site/attack-mode/end' ) )
	{
		file_put_contents( $fixtureStateFile, json_encode( [
			'attack_mode_active' => $attackModeActive,
		] ), LOCK_EX );
	}

	if ( $path === '/v1/moderation-actions/pull' && is_file( $actionStateFile ) )
	{
		$decodedActions = json_decode( (string) file_get_contents( $actionStateFile ), TRUE );
		$queuedActions = is_array( $decodedActions ) ? $decodedActions : [];
		@unlink( $actionStateFile );
	}

	$response = match ( TRUE )
	{
	$path === '/health' => [ 'ok' => TRUE ],
	$path === '/v1/node-endpoints' => [
		'control_check_fallback' => TRUE,
		'endpoints' => [ [
			'url' => $base,
			'check_ready' => TRUE,
			'status' => 'healthy',
			'role' => 'edge',
			'traffic_tier' => 1,
		] ],
	],
	$path === '/v1/site/bootstrap' => [
		'api_key' => 'ff_local_fixture_key',
		'site_id' => '9001',
		'preferred_endpoint' => $base,
	],
	str_starts_with( $path, '/v1/check' ) && $malformed => [
		'message' => 'fixture intentionally omitted a decision',
	],
	str_starts_with( $path, '/v1/check' ) && $aboveLimit => [
		'status_code' => 'ABOVELIMIT',
	],
	str_starts_with( $path, '/v1/check' ) && $rateLimited => [
		'detail' => 'fixture rate limit',
	],
	str_starts_with( $path, '/v1/check' ) && $serverError => [
		'detail' => 'fixture server error',
	],
	str_starts_with( $path, '/v1/check' ) => [
		'decision' => $decision,
		'decision_id' => $decision === 'block' ? 42001 : 42000,
		'decision_reference' => $decision === 'block' ? 'LOCAL-BLOCK' : 'LOCAL-ALLOW',
		'score' => $decision === 'block' ? 99 : 1,
	],
	$path === '/v1/site/status' => [
		'plan' => 'pro',
		'mode' => 'live',
		'attack_mode_active' => $attackModeActive,
	],
	$path === '/v1/forum/stats' => [
		'current_month_checks' => 2,
		'allows' => 1,
		'blocks' => 1,
	],
	$path === '/v1/capabilities' => [ 'allow_block_decisions' => TRUE ],
	$path === '/v1/plugin-release' => [ 'accepted' => TRUE ],
	$path === '/v1/site/ping' => [ 'accepted' => TRUE ],
	$path === '/v1/site/register' => [ 'registered' => TRUE, 'site_id' => '9001' ],
	$path === '/v1/site/portal' => [ 'portal_url' => 'http://192.168.50.203/ipb/' ],
	$path === '/v1/site/attack-mode' => [ 'attack_mode_active' => $attackModeActive ],
	$path === '/v1/site/attack-mode/end' => [ 'attack_mode_active' => $attackModeActive ],
	$path === '/v1/moderation-queue/sync' => [ 'accepted' => TRUE, 'pending_actions' => 0 ],
	$path === '/v1/moderation-actions/pull' => [ 'actions' => $queuedActions, 'pending_actions' => 0 ],
	$path === '/v1/moderation-actions/ack' => [ 'accepted' => TRUE ],
	str_starts_with( $path, '/v1/report/' ) => [ 'accepted' => TRUE ],
	default => [ 'error' => 'fixture_not_found', 'path' => $path ],
	};
}

if ( $rateLimited && str_starts_with( $path, '/v1/check' ) )
{
	http_response_code( 429 );
}
elseif ( $serverError && str_starts_with( $path, '/v1/check' ) )
{
	http_response_code( 503 );
}
elseif ( isset( $response['error'] ) )
{
	http_response_code( 404 );
}
echo json_encode( $response, JSON_UNESCAPED_SLASHES );
