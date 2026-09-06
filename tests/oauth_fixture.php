<?php
declare(strict_types=1);

/*
 * Local-only OAuth 2.0 authorization-code provider for IPS lifecycle tests.
 * Run with PHP's development server; never expose this fixture to the internet.
 */

const FF_OAUTH_CLIENT_ID = 'forumfortress-local-oauth';
const FF_OAUTH_CLIENT_SECRET = 'forumfortress-local-oauth-secret';
const FF_OAUTH_CALLBACK = 'http://192.168.50.203/ipb/oauth/callback/';

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$statePath = trim((string) getenv('FF_IPS_OAUTH_STATE')) ?: sys_get_temp_dir() . '/ff_ips_oauth_fixture_state.json';

function ff_oauth_json(array $payload, int $status = 200): never
{
	http_response_code($status);
	header('Cache-Control: no-store');
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
	exit;
}

function ff_oauth_load_state(string $path): array
{
	if (!is_file($path))
	{
		return ['codes' => [], 'tokens' => []];
	}
	$decoded = json_decode((string) file_get_contents($path), true);
	return is_array($decoded) ? $decoded + ['codes' => [], 'tokens' => []] : ['codes' => [], 'tokens' => []];
}

function ff_oauth_save_state(string $path, array $state): void
{
	$directory = dirname($path);
	if (!is_dir($directory) || !is_writable($directory))
	{
		throw new RuntimeException('OAuth fixture state directory is not writable.');
	}
	file_put_contents($path, json_encode($state, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), LOCK_EX);
	chmod($path, 0600);
}

function ff_oauth_client_credentials(): array
{
	$user = (string) ($_SERVER['PHP_AUTH_USER'] ?? '');
	$password = (string) ($_SERVER['PHP_AUTH_PW'] ?? '');
	if ($user !== '')
	{
		return [$user, $password];
	}
	$header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
	if (str_starts_with($header, 'Basic '))
	{
		$decoded = base64_decode(substr($header, 6), true);
		if (is_string($decoded) && str_contains($decoded, ':'))
		{
			return explode(':', $decoded, 2);
		}
	}
	return [(string) ($_POST['client_id'] ?? ''), (string) ($_POST['client_secret'] ?? '')];
}

function ff_oauth_base64url(string $bytes): string
{
	return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

if ($path === '/health')
{
	ff_oauth_json(['ok' => true, 'provider' => 'forumfortress-local-oauth']);
}

if ($path === '/authorize')
{
	$params = [
		'client_id' => (string) ($_GET['client_id'] ?? ''),
		'redirect_uri' => (string) ($_GET['redirect_uri'] ?? ''),
		'response_type' => (string) ($_GET['response_type'] ?? ''),
		'state' => (string) ($_GET['state'] ?? ''),
		'scope' => (string) ($_GET['scope'] ?? ''),
		'code_challenge' => (string) ($_GET['code_challenge'] ?? ''),
		'code_challenge_method' => (string) ($_GET['code_challenge_method'] ?? ''),
	];
	if ($params['client_id'] !== FF_OAUTH_CLIENT_ID || $params['redirect_uri'] !== FF_OAUTH_CALLBACK || $params['response_type'] !== 'code')
	{
		ff_oauth_json(['error' => 'invalid_request'], 400);
	}
	if ($params['state'] === '' || $params['code_challenge'] === '' || $params['code_challenge_method'] !== 'S256')
	{
		ff_oauth_json(['error' => 'invalid_request', 'error_description' => 'state and PKCE S256 are required'], 400);
	}

	$profile = (string) ($_GET['profile'] ?? '');
	if (!in_array($profile, ['allow', 'reject', 'delete'], true))
	{
		header('Cache-Control: no-store');
		header('Content-Type: text/html; charset=utf-8');
		$hidden = '';
		foreach ($params as $key => $value)
		{
			$hidden .= '<input type="hidden" name="' . htmlspecialchars($key, ENT_QUOTES) . '" value="' . htmlspecialchars($value, ENT_QUOTES) . '">';
		}
		echo '<!doctype html><html lang="en"><meta name="viewport" content="width=device-width,initial-scale=1">'
			. '<title>Local OAuth test provider</title><style>body{font:16px system-ui;background:#101318;color:#eef2f7;margin:0;padding:40px}'
			. 'main{max-width:620px;margin:auto;background:#1b2028;border:1px solid #343c48;border-radius:16px;padding:28px}'
			. 'button{display:block;width:100%;padding:14px;margin:12px 0;border:0;border-radius:9px;background:#2878ff;color:white;font-weight:700}'
			. 'small{color:#aab4c3}</style><main><h1>Local OAuth test provider</h1>'
			. '<p>Choose the synthetic identity used for this authorization.</p><form method="get" action="/authorize">' . $hidden
			. '<button name="profile" value="allow">Allow identity</button>'
			. '<button name="profile" value="reject">Blocked identity · mark rejected</button>'
			. '<button name="profile" value="delete">Blocked identity · delete account</button>'
			. '</form><small>Development fixture only. It contains no real accounts or personal data.</small></main></html>';
		exit;
	}

	$run = gmdate('YmdHis') . '-' . bin2hex(random_bytes(4));
	$code = ff_oauth_base64url(random_bytes(32));
	$state = ff_oauth_load_state($statePath);
	$state['codes'][$code] = [
		'profile' => $profile,
		'run' => $run,
		'redirect_uri' => $params['redirect_uri'],
		'code_challenge' => $params['code_challenge'],
		'expires_at' => time() + 300,
	];
	ff_oauth_save_state($statePath, $state);
	$query = http_build_query(['code' => $code, 'state' => $params['state']], '', '&', PHP_QUERY_RFC3986);
	header('Location: ' . FF_OAUTH_CALLBACK . '?' . $query, true, 302);
	exit;
}

if ($path === '/token')
{
	[$clientId, $clientSecret] = ff_oauth_client_credentials();
	if (!hash_equals(FF_OAUTH_CLIENT_ID, $clientId) || !hash_equals(FF_OAUTH_CLIENT_SECRET, $clientSecret))
	{
		ff_oauth_json(['error' => 'invalid_client'], 401);
	}
	if ((string) ($_POST['grant_type'] ?? '') !== 'authorization_code')
	{
		ff_oauth_json(['error' => 'unsupported_grant_type'], 400);
	}
	$code = (string) ($_POST['code'] ?? '');
	$state = ff_oauth_load_state($statePath);
	$record = is_array($state['codes'][$code] ?? null) ? $state['codes'][$code] : null;
	if (!$record || (int) ($record['expires_at'] ?? 0) < time() || (string) ($_POST['redirect_uri'] ?? '') !== (string) $record['redirect_uri'])
	{
		ff_oauth_json(['error' => 'invalid_grant'], 400);
	}
	$verifier = (string) ($_POST['code_verifier'] ?? '');
	$derived = ff_oauth_base64url(hash('sha256', $verifier, true));
	if ($verifier === '' || !hash_equals((string) $record['code_challenge'], $derived))
	{
		ff_oauth_json(['error' => 'invalid_grant', 'error_description' => 'PKCE verification failed'], 400);
	}
	unset($state['codes'][$code]);
	$token = ff_oauth_base64url(random_bytes(32));
	$state['tokens'][$token] = $record + ['expires_at' => time() + 600];
	ff_oauth_save_state($statePath, $state);
	ff_oauth_json(['access_token' => $token, 'token_type' => 'Bearer', 'expires_in' => 600, 'scope' => 'profile email']);
}

if ($path === '/userinfo')
{
	$authorization = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
	$token = str_starts_with($authorization, 'Bearer ') ? substr($authorization, 7) : (string) ($_GET['access_token'] ?? '');
	$state = ff_oauth_load_state($statePath);
	$record = is_array($state['tokens'][$token] ?? null) ? $state['tokens'][$token] : null;
	if (!$record || (int) ($record['expires_at'] ?? 0) < time())
	{
		ff_oauth_json(['error' => 'invalid_token'], 401);
	}
	$profile = (string) $record['profile'];
	$run = preg_replace('/[^a-zA-Z0-9-]/', '', (string) $record['run']);
	$blocked = in_array($profile, ['reject', 'delete'], true);
	ff_oauth_json([
		'id' => 'ff-oauth-' . $profile . '-' . $run,
		'name' => ($blocked ? 'ff_test_block_' : 'ff_test_allow_') . 'oauth_' . $profile . '_' . $run,
		'email' => 'ff.oauth.' . $profile . '.' . strtolower($run) . '@example.invalid',
	]);
}

ff_oauth_json(['error' => 'not_found'], 404);
