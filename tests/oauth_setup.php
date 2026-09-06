<?php
declare(strict_types=1);

/* Install, inspect or remove the local Custom OAuth 2 login handler in an IPS test site. */

$root = rtrim((string) getenv('FF_IPS_ROOT'), '/');
if ($root === '' || !is_file($root . '/init.php'))
{
	fwrite(STDERR, "Set FF_IPS_ROOT to a local IPS installation.\n");
	exit(2);
}
require $root . '/init.php';

use IPS\Db;
use IPS\Lang;
use IPS\Login\Handler;
use IPS\Login\Handler\OAuth2\Custom;

$action = strtolower((string) ($argv[1] ?? 'status'));
$provider = rtrim((string) (getenv('FF_IPS_OAUTH_BASE') ?: 'http://192.168.50.203:18182'), '/');
$clientId = 'forumfortress-local-oauth';
$clientSecret = 'forumfortress-local-oauth-secret';
$handlerIds = [];
foreach (Db::i()->select('*', 'core_login_methods', ['login_classname=?', Custom::class]) as $row)
{
	$settings = json_decode((string) ($row['login_settings'] ?? ''), true);
	if (is_array($settings) && ($settings['client_id'] ?? '') === $clientId)
	{
		$handlerIds[] = (int) $row['login_id'];
	}
}

if ($action === 'cleanup')
{
	$syntheticMemberIds = [];
	foreach ($handlerIds as $handlerId)
	{
		foreach (Db::i()->select('token_member,token_identifier', 'core_login_links', ['token_login_method=?', $handlerId]) as $link)
		{
			if (str_starts_with((string) $link['token_identifier'], 'ff-oauth-'))
			{
				$syntheticMemberIds[(int) $link['token_member']] = true;
			}
		}
	}
	foreach (Db::i()->select('member_id', 'core_members', ['email LIKE ?', 'ff.oauth.%@example.invalid']) as $row)
	{
		$syntheticMemberIds[(int) $row['member_id']] = true;
	}
	foreach ($handlerIds as $handlerId)
	{
		try
		{
			Handler::load($handlerId)->delete();
		}
		catch (Throwable $e)
		{
			Db::i()->delete('core_login_links', ['token_login_method=?', $handlerId]);
			Db::i()->delete('core_login_methods', ['login_id=?', $handlerId]);
		}
		Db::i()->delete('core_sys_lang_words', ['word_key IN(?,?)', "core_custom_oauth_{$handlerId}", "login_method_{$handlerId}"]);
	}
	$removedMembers = 0;
	foreach (array_keys($syntheticMemberIds) as $memberId)
	{
		$member = \IPS\Member::load((int) $memberId);
		if ($member->member_id && str_starts_with((string) $member->email, 'ff.oauth.') && str_ends_with((string) $member->email, '@example.invalid'))
		{
			$member->delete();
			$removedMembers++;
		}
		if (!(int) Db::i()->select('COUNT(*)', 'core_members', ['member_id=?', $memberId])->first())
		{
			foreach ([
				['core_pfields_content', 'member_id'],
				['core_login_links', 'token_member'],
				['core_member_history', 'log_member'],
				['core_members_known_devices', 'member_id'],
				['core_members_known_ip_addresses', 'member_id'],
				['core_members_logins', 'member_id'],
				['core_sessions', 'member_id'],
			] as [$table, $column])
			{
				Db::i()->delete($table, ["{$column}=?", $memberId]);
			}
			Db::i()->delete('core_approval_queue', [
				'approval_content_class=? AND approval_content_id=?',
				'IPS\\Member',
				$memberId,
			]);
		}
	}
	echo "Local OAuth handler(s) removed: " . count($handlerIds) . "\n";
	echo "Synthetic member(s) removed: {$removedMembers}\n";
	exit;
}

if ($action === 'install')
{
	if (count($handlerIds) > 1)
	{
		fwrite(STDERR, "Multiple Forum Fortress local OAuth handlers exist; run cleanup first.\n");
		exit(1);
	}
	$handler = $handlerIds ? Handler::load($handlerIds[0]) : new Custom;
	if (!$handlerIds)
	{
		$handler->classname = Custom::class;
		$handler->order = (int) Db::i()->select('MAX(login_order)', 'core_login_methods')->first() + 1;
	}
	$handler->acp = 0;
	$handler->enabled = 1;
	$handler->register = 1;
	$handler->front = 1;
	$handler->settings = [
		'grant_type' => 'authorization_code',
		'client_id' => $clientId,
		'client_secret' => $clientSecret,
		'authentication_type' => 'header',
		'scopes' => ['profile', 'email'],
		'authorization_endpoint' => $provider . '/authorize',
		'authorization_endpoint_secure' => '',
		'token_endpoint' => $provider . '/token',
		'user_endpoint' => $provider . '/userinfo',
		'uid_field' => 'id',
		'name_field' => 'name',
		'email_field' => 'email',
		'photo_field' => '',
		'auth_types' => 2,
		'button_color' => '#2878ff',
		'button_icon' => '',
		'show_in_ucp' => 'disabled',
		'update_name_changes' => 'disabled',
		'update_email_changes' => 'disabled',
	];
	$handler->save();
	Lang::saveCustom('core', "core_custom_oauth_{$handler->id}", 'Continue with Local OAuth');
	Lang::saveCustom('core', "login_method_{$handler->id}", 'Local OAuth test provider');
	$handler->testSettings();
	$handlerIds = [(int) $handler->id];
}

if (!in_array($action, ['install', 'status'], true))
{
	fwrite(STDERR, "Usage: php oauth_setup.php [install|status|cleanup]\n");
	exit(2);
}

echo "Handler configured: " . ($handlerIds ? 'yes' : 'no') . "\n";
if ($handlerIds)
{
	echo "Handler ID: {$handlerIds[0]}\n";
	echo "Provider: {$provider}\n";
	echo "Callback: http://192.168.50.203/ipb/oauth/callback/\n";
}
