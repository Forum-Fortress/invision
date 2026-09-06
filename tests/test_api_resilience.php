<?php

declare(strict_types=1);

require_once __DIR__ . '/../upload/applications/forumfortress/sources/Api/FfApiResilience.php';

$failures = [];
$assert = static function ( bool $condition, string $message ) use ( &$failures ): void {
	if ( !$condition )
	{
		$failures[] = $message;
	}
};

$offlineState = [
	'offline_pinned' => TRUE,
	'issuer_node_id' => 'edge-a',
	'offline_preferred_endpoint' => 'https://edge-a.ffapi.net',
	'offline_rebootstrap_at' => time() + 600,
	'offline_canonical_domain' => 'forum.example',
	'fallback_bootstrap_endpoints' => [ 'https://fortress.ffapi.net' ],
];
$ordinaryResponseState = $offlineState;
FfApiResilience::applyOfflineBootstrapRouting(
	[ 'decision' => 'allow', 'status_code' => 'OK' ],
	$ordinaryResponseState,
	'https://edge-a.ffapi.net'
);
$assert(
	$ordinaryResponseState === $offlineState,
	'ordinary check responses must not clear an offline-bootstrap route pin'
);

$registeredState = $offlineState;
FfApiResilience::applyOfflineBootstrapRouting(
	[ 'api_key' => 'ff_registered_key', 'key_type' => 'registered' ],
	$registeredState,
	'https://fortress.ffapi.net'
);
$assert(
	empty( $registeredState['offline_pinned'] ),
	'an explicit registered identity must clear the temporary offline route pin'
);

$assert(
	FfApiResilience::shouldRebootstrapOfflineNow( [
		'offline_pinned' => TRUE,
		'offline_rebootstrap_at' => time() - 1,
	] ),
	'an expired offline-bootstrap schedule must request migration'
);
$assert(
	!FfApiResilience::shouldRebootstrapOfflineNow( [
		'offline_pinned' => TRUE,
		'offline_rebootstrap_at' => time() + 600,
	] ),
	'a future offline-bootstrap schedule must remain pinned'
);

$rebootstrapBases = FfApiResilience::offlineRebootstrapBases(
	[ 'fallback_bootstrap_endpoints' => [ 'https://recovery.ffapi.net', 'https://fortress.ffapi.net' ] ],
	'https://fortress.ffapi.net',
	'https://api.ffapi.net',
	[ 'https://edge-a.ffapi.net' ],
	'https://api.ffapi.net'
);
$assert(
	$rebootstrapBases === [
		'https://recovery.ffapi.net',
		'https://fortress.ffapi.net',
		'https://api.ffapi.net',
		'https://edge-a.ffapi.net',
	],
	'offline migration must prefer supplied recovery bases and de-duplicate normal bootstrap routes'
);

$assert(
	FfApiResilience::isNodeMismatchResponse( [ 'error' => 'node_mismatch' ] ),
	'a flat node_mismatch response must be recognized'
);
$assert(
	FfApiResilience::isNodeMismatchResponse( [ 'detail' => [ 'error' => 'node_mismatch' ] ] ),
	'a FastAPI detail node_mismatch response must be recognized'
);
$assert(
	!FfApiResilience::isNodeMismatchResponse( [ 'error' => 'invalid_key' ] ),
	'unrelated authentication failures must not be treated as node mismatch'
);

$assert(
	FfApiResilience::contactPageCheckTimeoutSeconds( 1 ) === 6,
	'contact checks must retain the six-second minimum timeout'
);
$assert(
	FfApiResilience::contactPageCheckTimeoutSeconds( 20 ) === 12,
	'contact checks must retain the twelve-second maximum timeout'
);
$assert(
	FfApiResilience::contactPageCheckBasesOrdered(
		[ 'https://edge-a.ffapi.net', 'https://api.ffapi.net', 'https://edge-b.ffapi.net' ],
		'https://api.ffapi.net'
	) === [ 'https://api.ffapi.net', 'https://edge-a.ffapi.net' ],
	'contact checks must use the hot API first and at most one fallback edge'
);

$assert(
	FfApiResilience::apiBaseUrlForRegion( 'eu' ) === 'https://api-eu.ffapi.net',
	'EU region must resolve to the fixed EU API hostname'
);
$assert(
	FfApiResilience::regionLockedCheckBases( 'uk', FALSE ) === [ 'https://api-uk.ffapi.net' ],
	'UK lock must not escape the selected region without consent'
);
$assert(
	FfApiResilience::regionLockedCheckBases( 'uk', TRUE ) === [ 'https://api-uk.ffapi.net', 'https://api.ffapi.net' ],
	'UK emergency fallback must add only the global hostname after the regional hostname'
);

if ( $failures )
{
	foreach ( $failures as $failure )
	{
		fwrite( STDERR, 'FAIL: ' . $failure . "\n" );
	}
	exit( 1 );
}

echo "Forum Fortress Invision resilience assertions: OK\n";
