<?php

namespace IPS\forumfortress\modules\admin\forumfortress;

use IPS\Dispatcher;
use IPS\Dispatcher\Controller;
use IPS\forumfortress\Api\Client;
use IPS\Helpers\Form;
use IPS\Helpers\Form\Email;
use IPS\Http\Url;
use IPS\Helpers\Form\Number;
use IPS\Helpers\Form\Password;
use IPS\Helpers\Form\Select;
use IPS\Helpers\Form\Text;
use IPS\Helpers\Form\YesNo;
use IPS\Member;
use IPS\Output;
use IPS\Request;
use IPS\Session;
use IPS\Settings as SettingsClass;
use Throwable;
use function htmlspecialchars;
use function json_encode;
use const JSON_PRETTY_PRINT;
use const JSON_UNESCAPED_SLASHES;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class settings extends Controller
{
	public static bool $csrfProtected = TRUE;

	public function execute() : void
	{
		Dispatcher::i()->checkAcpPermission( 'settings_manage', 'forumfortress' );
		parent::execute();
	}

	protected function manage() : void
	{
		$actionResult = NULL;
		$action = (string) ( Request::i()->ff_action ?? '' );
		$settingsUrl = Url::internal( 'app=forumfortress&module=forumfortress&controller=settings' );

		if ( $action !== '' )
		{
			if ( !in_array( $action, [ 'bootstrap', 'test', 'register', 'attack_on', 'attack_off', 'portal' ], TRUE ) )
			{
				Output::i()->error( 'node_error', '2FF100/2', 400, '' );
				return;
			}
			if ( strtoupper( Request::i()->requestMethod() ) !== 'POST' )
			{
				Output::i()->error( 'forumfortress_action_requires_post', '2FF100/1', 405, '' );
				return;
			}
			Session::i()->csrfCheck();
			if ( $action === 'bootstrap' )
			{
				try
				{
					$payload = Client::bootstrapIfNeeded();
					if ( $payload !== NULL && !empty( $payload['api_key'] ) )
					{
						Client::refreshEndpointCatalogAndHealth( TRUE );
					}
					if ( Client::apiKey() === '' || trim( (string) SettingsClass::i()->ff_site_id ) === '' )
					{
						throw new \RuntimeException( 'Forum Fortress did not return a site identity.' );
					}
					$actionResult = [ 'action' => 'bootstrap', 'payload' => $payload ];
				}
				catch ( Throwable $e )
				{
					$actionResult = [ 'action' => 'bootstrap', 'error' => $e->getMessage() ];
				}
			}
			elseif ( $action === 'test' )
			{
				try
				{
					$bootstrap = Client::bootstrapIfNeeded();
					Client::refreshEndpointCatalogAndHealth( TRUE, 2 );
					$testPayload = [
						'bootstrap' => $bootstrap,
						'health' => Client::health(2),
						'capabilities' => Client::capabilities(2),
						'site_status' => Client::siteStatus(2),
						'forum_stats' => Client::forumStats(2),
						'site_ping' => Client::sitePing(2),
					];
					if ( !is_array( $testPayload['health'] ) )
					{
						throw new \RuntimeException( 'No Forum Fortress endpoint answered the connection test.' );
					}
					$summaryAfterTest = Client::endpointStateSummary();
					$actionResult = [
						'action' => 'test',
						'payload' => $testPayload,
						'answered_endpoint' => (string) ( $summaryAfterTest['last_responded'] ?? '' ),
					];
				}
				catch ( Throwable $e )
				{
					$actionResult = [ 'action' => 'test', 'error' => $e->getMessage() ];
				}
			}
			elseif ( $action === 'register' )
			{
				try
				{
					$email = trim( (string) SettingsClass::i()->ff_registration_email );
					$payload = Client::registerSite( $email );
					if ( !is_array( $payload ) )
					{
						throw new \RuntimeException( 'Forum Fortress could not complete registration.' );
					}
					$actionResult = [ 'action' => 'register', 'payload' => $payload ];
				}
				catch ( Throwable $e )
				{
					$actionResult = [ 'action' => 'register', 'error' => $e->getMessage() ];
				}
			}
			elseif ( $action === 'attack_on' )
			{
				try
				{
					$payload = Client::activateAttackMode();
					if ( !is_array( $payload ) || empty( $payload['attack_mode_active'] ) )
					{
						throw new \RuntimeException( 'Forum Fortress did not confirm that attack mode is active.' );
					}
					Client::siteStatus(2);
					$actionResult = [ 'action' => 'attack_on', 'payload' => $payload ];
				}
				catch ( Throwable $e )
				{
					$actionResult = [ 'action' => 'attack_on', 'error' => $e->getMessage() ];
				}
			}
			elseif ( $action === 'attack_off' )
			{
				try
				{
					$payload = Client::deactivateAttackMode();
					if ( !is_array( $payload ) || !array_key_exists( 'attack_mode_active', $payload ) || !empty( $payload['attack_mode_active'] ) )
					{
						throw new \RuntimeException( 'Forum Fortress did not confirm that attack mode has ended.' );
					}
					Client::siteStatus(2);
					$actionResult = [ 'action' => 'attack_off', 'payload' => $payload ];
				}
				catch ( Throwable $e )
				{
					$actionResult = [ 'action' => 'attack_off', 'error' => $e->getMessage() ];
				}
			}
			elseif ( $action === 'portal' )
			{
				try
				{
					$launch = Client::portalLaunch(2);
					$portalUrl = is_array( $launch ) ? trim( (string) ( $launch['portal_url'] ?? '' ) ) : '';
					if ( Client::isTrustedPortalUrl( $portalUrl ) )
					{
						Output::i()->redirect( Url::external( $portalUrl ) );
						return;
					}
					$actionResult = [ 'action' => 'portal', 'error' => 'Portal URL is not available.' ];
				}
				catch ( Throwable $e )
				{
					$actionResult = [ 'action' => 'portal', 'error' => $e->getMessage() ];
				}
			}

			if ( is_array( $actionResult ) )
			{
				if ( !empty( $actionResult['error'] ) && SettingsClass::i()->ff_debug_log )
				{
					$redactedLog = json_encode( $this->redactActionResult( $actionResult ), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE );
					\IPS\Log::debug( is_string( $redactedLog ) ? $redactedLog : 'Forum Fortress action failed.', 'forumfortress' );
				}
				$messageKey = !empty( $actionResult['error'] )
					? 'ff_action_' . $action . '_failed'
					: 'ff_action_' . $action . '_succeeded';
				Output::i()->redirect( $settingsUrl, $messageKey, 303 );
				return;
			}
		}
		else
		{
			try
			{
				Client::ensureIdentity();
				Client::refreshEndpointCatalogAndHealth( FALSE, 2 );
			}
			catch ( Throwable $e )
			{
			}
		}

		$base = $settingsUrl->csrf();
		$links = [
			'bootstrap' => (string) $base->setQueryString( 'ff_action', 'bootstrap' ),
			'test' => (string) $base->setQueryString( 'ff_action', 'test' ),
			'register' => (string) $base->setQueryString( 'ff_action', 'register' ),
			'attack_on' => (string) $base->setQueryString( 'ff_action', 'attack_on' ),
			'attack_off' => (string) $base->setQueryString( 'ff_action', 'attack_off' ),
			'portal' => (string) $base->setQueryString( 'ff_action', 'portal' ),
		];

		$portalDirectUrl = '';
		$siteStatus = NULL;
		$forumStats = NULL;
		$attackModeActive = NULL;
		if ( Client::isEnabled() )
		{
			try
			{
				$siteStatus = Client::cachedSiteStatus();
				if ( is_array( $siteStatus ) )
				{
					$attackModeActive = !empty( $siteStatus['attack_mode_active'] );
				}
				$forumStats = Client::cachedForumStats();
			}
			catch ( Throwable $e )
			{
			}

			if ( trim( (string) SettingsClass::i()->ff_site_id ) !== '' && Client::apiKey() !== '' )
			{
				$portalDirectUrl = $links['portal'];
			}
		}

		$endpoint = Client::endpointStateSummary();
		$latencyRows = Client::buildEndpointLatencyRows();
		$lastTestEndpoint = '';
		if ( is_array( $actionResult ) && isset( $actionResult['answered_endpoint'] ) )
		{
			$lastTestEndpoint = (string) $actionResult['answered_endpoint'];
		}
		if ( $lastTestEndpoint === '' )
		{
			$lastTestEndpoint = (string) ( $endpoint['last_responded'] ?? '' );
		}

		Output::i()->title = Member::loggedIn()->language()->addToStack( 'forumfortress_acp_title' );
		$output = $this->renderThemeStyles() . '<div class="ffDashboard">';

		$output .= $this->renderActionsPanel( $links, $portalDirectUrl, $attackModeActive, $actionResult );
		$output .= $this->renderSiteStatusPanel( $siteStatus, $forumStats, $endpoint, $lastTestEndpoint );
		$output .= $this->renderEndpointHealthPanel( $latencyRows );
		$output .= $this->renderCompatibilityPanel();

		$output .= '<section class="ipsBox ffCard"><div class="ffSectionHeader"><div><strong>' . Member::loggedIn()->language()->addToStack( 'ff_section_api_config' ) . '</strong><span>Connection and protection settings.</span></div></div>';

		$form = new Form;
		$form->action = $settingsUrl;
		$form->add( new YesNo( 'ff_enabled', SettingsClass::i()->ff_enabled ) );
		$urlValidator = static function ( mixed $value ): void {
			Client::validateConfiguredBaseUrl( (string) $value );
		};
		$currentRegion = \FfApiResilience::normaliseApiRegion( (string) ( SettingsClass::i()->ff_api_region ?? \FfApiResilience::apiRegionFromLegacyBaseUrl( (string) SettingsClass::i()->ff_api_base_url ) ) );
		$form->add( new Select( 'ff_api_region', $currentRegion, TRUE, [ 'options' => [
			'global' => 'ff_region_global', 'uk' => 'ff_region_uk', 'eu' => 'ff_region_eu', 'us' => 'ff_region_us',
		] ] ) );
		$form->add( new YesNo( 'ff_allow_global_fallback', SettingsClass::i()->ff_allow_global_fallback ?? FALSE ) );
		$form->add( new Text( 'ff_control_base_url', SettingsClass::i()->ff_control_base_url, FALSE, [], $urlValidator ) );
		$form->add( new Number( 'ff_timeout', SettingsClass::i()->ff_timeout, FALSE, [ 'min' => 1, 'max' => 30 ] ) );
		$form->add( new YesNo( 'ff_fail_open', SettingsClass::i()->ff_fail_open ) );
		$form->add( new YesNo( 'ff_send_ham', SettingsClass::i()->ff_send_ham ?? TRUE ) );
		$form->add( new Select( 'ff_block_reject_action', SettingsClass::i()->ff_block_reject_action ?? 'reject', FALSE, [
			'options' => [
				'reject' => 'ff_block_reject_action_reject',
				'hide' => 'ff_block_reject_action_hide',
			],
		] ) );
		$form->add( new Select( 'ff_registration_block_action', SettingsClass::i()->ff_registration_block_action ?? 'reject', FALSE, [
			'options' => [
				'reject' => 'ff_registration_block_action_reject',
				'delete' => 'ff_registration_block_action_delete',
			],
		] ) );
		$form->add( new Text( 'ff_trusted_proxies', SettingsClass::i()->ff_trusted_proxies ?? '', FALSE, [], static function ( mixed $value ): void {
			Client::validateTrustedProxies( (string) $value );
		} ) );
		$form->add( new YesNo( 'ff_debug_log', SettingsClass::i()->ff_debug_log ) );
		$form->add( new Password( 'ff_bootstrap_token', '', FALSE, [ 'htmlAutocomplete' => 'new-password' ] ) );
		$form->add( new Password( 'ff_api_key', '', FALSE, [ 'htmlAutocomplete' => 'new-password' ] ) );
		$form->add( new Text( 'ff_site_id', SettingsClass::i()->ff_site_id ) );
		$form->add( new Email( 'ff_registration_email', SettingsClass::i()->ff_registration_email, FALSE ) );

		if ( $values = $form->values() )
		{
			$values['ff_api_region'] = \FfApiResilience::normaliseApiRegion( (string) ( $values['ff_api_region'] ?? 'global' ) );
			$values['ff_api_base_url'] = \FfApiResilience::apiBaseUrlForRegion( $values['ff_api_region'] );
			$values['ff_preferred_endpoint'] = '';
			$submittedBootstrapToken = trim( (string) ( $values['ff_bootstrap_token'] ?? '' ) );
			$values['ff_bootstrap_token'] = $submittedBootstrapToken !== ''
				? Client::encryptSecretForStorage( $submittedBootstrapToken )
				: (string) SettingsClass::i()->ff_bootstrap_token;
			$submittedApiKey = trim( (string) ( $values['ff_api_key'] ?? '' ) );
			$values['ff_api_key'] = $submittedApiKey !== ''
				? Client::encryptApiKeyForStorage( $submittedApiKey )
				: (string) SettingsClass::i()->ff_api_key;
			$form->saveAsSettings( $values );
			Session::i()->log( 'acplogs__ff_settings' );
			Output::i()->redirect( $settingsUrl, 'saved', 303 );
			return;
		}

		$output .= (string) $form . '</section></div>';
		Output::i()->output = $output;
	}

	protected function renderThemeStyles(): string
	{
		return '<style>
		.ffDashboard{--ff-green:#087443;--ff-green-bright:#159458;--ff-green-soft:rgba(8,116,67,.1);--ff-amber:#b86313;--ff-border:rgba(127,127,127,.24);display:grid;gap:14px}.ffDashboard *{box-sizing:border-box}.ffCard{overflow:hidden;margin:0!important;border:1px solid var(--ff-border);border-radius:10px;background:var(--i-background_1,#fff);box-shadow:0 2px 10px rgba(0,0,0,.05)}.ffHero{border-top:3px solid var(--ff-green)}.ffHeroHeader{display:flex;align-items:center;gap:13px;padding:18px;background:linear-gradient(135deg,var(--ff-green-soft),transparent 62%)}.ffMark{display:grid;flex:0 0 46px;width:46px;height:50px;place-content:center;gap:4px;clip-path:polygon(50% 0,94% 16%,88% 67%,70% 88%,50% 100%,30% 88%,12% 67%,6% 16%);background:linear-gradient(145deg,var(--ff-green-bright),#034f2e);filter:drop-shadow(0 2px 2px rgba(0,0,0,.18))}.ffMark i{display:block;width:25px;height:4px;border-radius:3px;background:#f4f0e5}.ffMark i:nth-child(2){width:20px}.ffMark i:nth-child(3){width:15px}.ffHeroCopy{display:grid;flex:1;gap:2px}.ffHeroCopy strong{font-size:17px}.ffHeroCopy span,.ffSectionHeader span{color:var(--i-color_soft,#6b7480)}.ffPill{padding:5px 10px;border-radius:999px;background:rgba(108,116,128,.12);color:var(--i-color_soft,#6b7480);font-size:12px;font-weight:700}.ffPill.is-connected{background:var(--ff-green-soft);color:var(--ff-green-bright)}.ffActionGrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;padding:0 18px 18px}.ffActionGrid form,.ffActionGrid .ipsButton{display:flex;width:100%;margin:0!important}.ffActionGrid .ipsButton{align-items:center;justify-content:center;min-height:42px;font-weight:600}.ffPortalButton{background:var(--ff-green)!important;border-color:var(--ff-green)!important}.ffSectionHeader{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:14px 16px;border-bottom:1px solid var(--ff-border)}.ffSectionHeader>div{display:grid;gap:2px}.ffDashboard .ipsData__item{padding:12px 16px}.ffDashboard .ipsTable{margin:0}.ffDashboard .ipsForm{margin:0}.ffDashboard .ipsForm .ipsForm__content{padding:16px}@media(max-width:700px){.ffHeroHeader{align-items:flex-start}.ffPill{margin-left:auto}.ffActionGrid{grid-template-columns:1fr}}
		</style>';
	}

	protected function renderActionsPanel( array $links, string $portalDirectUrl, ?bool $attackModeActive, ?array $actionResult ): string
	{
		$lang = Member::loggedIn()->language();
		$connected = trim( (string) SettingsClass::i()->ff_site_id ) !== '' && Client::apiKey() !== '';
		$panel = '<section class="ipsBox ffCard ffHero"><div class="ffHeroHeader"><div class="ffMark" aria-hidden="true"><i></i><i></i><i></i></div><div class="ffHeroCopy"><strong>Forum Fortress</strong><span>' . $lang->addToStack( 'ff_action_help' ) . '</span></div><span class="ffPill' . ( $connected ? ' is-connected' : '' ) . '">' . ( $connected ? 'Connected' : 'Configured' ) . '</span></div>';
		$panel .= '<div class="ffActionGrid">';
		if ( $portalDirectUrl !== '' )
		{
			$panel .= $this->renderActionForm( $portalDirectUrl, 'ff_action_portal', TRUE, TRUE );
		}
		else
		{
			$panel .= '<span class="ipsButton ipsButton--secondary" aria-disabled="true" style="opacity:.55;" title="' . htmlspecialchars( $lang->addToStack( 'ff_portal_unavailable' ) ) . '">' . $lang->addToStack( 'ff_action_portal' ) . '</span>';
		}
		if ( trim( SettingsClass::i()->ff_site_id ) !== '' && Client::apiKey() !== '' )
		{
			if ( $attackModeActive )
			{
				$panel .= $this->renderActionForm( $links['attack_off'], 'ff_action_attack_off', TRUE );
			}
			else
			{
				$panel .= $this->renderActionForm( $links['attack_on'], 'ff_action_attack_on', TRUE );
			}
		}
		$panel .= $this->renderActionForm( $links['test'], 'ff_action_test', TRUE );
		$panel .= $this->renderActionForm( $links['bootstrap'], 'ff_action_bootstrap' );
		$panel .= $this->renderActionForm( $links['register'], 'ff_action_register' );
		$panel .= '</div><p class="i-color_soft" style="padding:0 18px 16px;margin:0;">' . $lang->addToStack( 'ff_attack_mode_status' ) . ': <strong>';
		if ( $attackModeActive === NULL )
		{
			$panel .= 'Unknown';
		}
		else
		{
			$panel .= $attackModeActive ? $lang->addToStack( 'ff_attack_mode_active' ) : $lang->addToStack( 'ff_attack_mode_inactive' );
		}
		$panel .= '</strong></p>';
		if ( is_array( $actionResult ) )
		{
			$panel .= $this->formatActionResultPanel( $actionResult );
		}
		$panel .= '</section>';

		return $panel;
	}

	protected function renderActionForm( string $url, string $languageKey, bool $primary = FALSE, bool $newWindow = FALSE ): string
	{
		$class = $primary ? 'ipsButton--primary' : 'ipsButton--secondary';
		if ( $newWindow ) $class .= ' ffPortalButton';
		$target = $newWindow ? ' target="_blank"' : '';
		return '<form method="post" action="' . htmlspecialchars( $url ) . '"' . $target . ' style="display:inline;margin:0;">'
			. '<button type="submit" class="ipsButton ' . $class . '">'
			. Member::loggedIn()->language()->addToStack( $languageKey )
			. '</button></form>';
	}

	protected function renderSiteStatusPanel( ?array $siteStatus, ?array $forumStats, array $endpoint, string $lastTestEndpoint ): string
	{
		$lang = Member::loggedIn()->language();
		$panel = '<section class="ipsBox ffCard"><div class="ffSectionHeader"><div><strong>' . $lang->addToStack( 'ff_section_site_status' ) . '</strong><span>Current protection and service details.</span></div></div><ul class="ipsData ipsData--table">';
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main">' . $lang->addToStack( 'ff_status_domain' ) . '</strong><span class="ipsData__stats">' . htmlspecialchars( Client::forumDomain() ) . '</span></li>';
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main">' . $lang->addToStack( 'ff_status_site_id' ) . '</strong><span class="ipsData__stats">' . htmlspecialchars( (string) SettingsClass::i()->ff_site_id ) . '</span></li>';
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main">' . $lang->addToStack( 'ff_status_plan' ) . '</strong><span class="ipsData__stats">' . htmlspecialchars( (string) ( $siteStatus['plan'] ?? '' ) ) . '</span></li>';
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main">' . $lang->addToStack( 'ff_status_preferred' ) . '</strong><span class="ipsData__stats">' . htmlspecialchars( (string) ( $endpoint['preferred'] ?? '' ) ) . '</span></li>';
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main">' . $lang->addToStack( 'ff_status_test_answered' ) . '</strong><span class="ipsData__stats">' . htmlspecialchars( $lastTestEndpoint ) . '</span></li>';
		$lastForumSyncAt = (int) ( $endpoint['last_site_ping_at'] ?? 0 );
		$lastForumSyncText = $lastForumSyncAt > 0 ? \gmdate( 'Y-m-d H:i:s', $lastForumSyncAt ) . ' UTC' : 'Unknown';
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main">Forum last synced</strong><span class="ipsData__stats">' . htmlspecialchars( $lastForumSyncText ) . '</span></li>';
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main">' . $lang->addToStack( 'ff_status_mode' ) . '</strong><span class="ipsData__stats">' . htmlspecialchars( (string) ( $siteStatus['mode'] ?? '' ) ) . '</span></li>';
		$attackText = 'Unknown';
		if ( is_array( $siteStatus ) && array_key_exists( 'attack_mode_active', $siteStatus ) )
		{
			$attackText = !empty( $siteStatus['attack_mode_active'] ) ? $lang->addToStack( 'ff_attack_mode_active' ) : $lang->addToStack( 'ff_attack_mode_inactive' );
		}
		elseif ( is_array( $siteStatus ) && isset( $siteStatus['attack_mode_until'] ) )
		{
			$attackText = (string) $siteStatus['attack_mode_until'];
		}
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main">' . $lang->addToStack( 'ff_status_attack_mode' ) . '</strong><span class="ipsData__stats">' . htmlspecialchars( $attackText ) . '</span></li>';
		if ( is_array( $forumStats ) )
		{
			$panel .= '<li class="ipsData__item"><strong class="ipsData__main">Current month checks</strong><span class="ipsData__stats">' . (int) ( $forumStats['current_month_checks'] ?? 0 ) . '</span></li>';
			$panel .= '<li class="ipsData__item"><strong class="ipsData__main">Allows</strong><span class="ipsData__stats">' . (int) ( $forumStats['allows'] ?? 0 ) . '</span></li>';
			$panel .= '<li class="ipsData__item"><strong class="ipsData__main">Blocks</strong><span class="ipsData__stats">' . (int) ( $forumStats['blocks'] ?? 0 ) . '</span></li>';
		}
		$panel .= '</ul></section>';

		return $panel;
	}

	/**
	 * @param list<array{endpoint: string, latency: string, is_preferred: bool}> $latencyRows
	 */
	protected function renderEndpointHealthPanel( array $latencyRows ): string
	{
		if ( $latencyRows === [] )
		{
			return '';
		}

		$lang = Member::loggedIn()->language();
		$panel = '<section class="ipsBox ffCard"><div class="ffSectionHeader"><div><strong>' . $lang->addToStack( 'ff_section_endpoint_health' ) . '</strong><span>Measured from this forum server.</span></div></div>';
		$panel .= '<table class="ipsTable ipsTable_zebra"><thead><tr><th>Endpoint</th><th>Latency</th></tr></thead><tbody>';
		foreach ( $latencyRows as $row )
		{
			$preferred = !empty( $row['is_preferred'] ) ? ' *' : '';
			$panel .= '<tr><td>' . htmlspecialchars( (string) ( $row['endpoint'] ?? '' ) ) . $preferred . '</td><td>' . htmlspecialchars( (string) ( $row['latency'] ?? '' ) ) . '</td></tr>';
		}
		$panel .= '</tbody></table></section>';

		return $panel;
	}

	protected function renderCompatibilityPanel(): string
	{
		$lang = Member::loggedIn()->language();
		$writeApiClients = Client::unprotectedWriteApiClientCount();
		$keyStatus = Client::apiKeyIsEncrypted()
			? $lang->addToStack( 'ff_diagnostic_key_encrypted' )
			: $lang->addToStack( 'ff_diagnostic_key_plaintext' );
		$apiStatus = $writeApiClients > 0
			? $lang->addToStack( 'ff_diagnostic_write_api_warning', FALSE, [ 'sprintf' => [ $writeApiClients ] ] )
			: $lang->addToStack( 'ff_diagnostic_write_api_clear' );

		$panel = '<section class="ipsBox ffCard"><div class="ffSectionHeader"><div><strong>' . $lang->addToStack( 'ff_section_compatibility' ) . '</strong><span>Installation and API compatibility.</span></div></div><ul class="ipsData ipsData--table">';
		$labelStyle = ' style="flex:0 0 42%;min-width:8.5rem;"';
		$valueStyle = ' style="min-width:0;overflow-wrap:anywhere;"';
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main"' . $labelStyle . '>' . $lang->addToStack( 'ff_diagnostic_ips_version' ) . '</strong><span class="ipsData__stats"' . $valueStyle . '>' . htmlspecialchars( (string) \IPS\Application::load( 'core' )->version ) . '</span></li>';
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main"' . $labelStyle . '>' . $lang->addToStack( 'ff_diagnostic_key_storage' ) . '</strong><span class="ipsData__stats"' . $valueStyle . '>' . htmlspecialchars( $keyStatus ) . '</span></li>';
		$panel .= '<li class="ipsData__item"><strong class="ipsData__main"' . $labelStyle . '>' . $lang->addToStack( 'ff_diagnostic_write_api' ) . '</strong><span class="ipsData__stats"' . $valueStyle . '>' . htmlspecialchars( $apiStatus ) . '</span></li>';
		$panel .= '</ul></section>';

		return $panel;
	}

	protected function formatActionResultPanel( array $actionResult ): string
	{
		if ( !empty( $actionResult['error'] ) )
		{
			$html = '<div class="ipsMessage ipsMessage_error">' . htmlspecialchars( (string) $actionResult['error'] ) . '</div>';
		}
		else
		{
			$action = (string) ( $actionResult['action'] ?? '' );
			$message = match ( $action )
			{
				'bootstrap' => 'Bootstrap completed successfully.',
				'test' => 'Connection test completed.',
				'register' => 'Registration completed successfully.',
				'attack_on' => 'Attack mode enabled.',
				'attack_off' => 'Attack mode ended.',
				default => 'Action completed successfully.',
			};
			if ( $action === 'test' && !empty( $actionResult['answered_endpoint'] ) )
			{
				$message .= ' Answered by ' . (string) $actionResult['answered_endpoint'] . '.';
			}
			$html = '<div class="ipsMessage ipsMessage_success">' . htmlspecialchars( $message ) . '</div>';
		}

		if ( SettingsClass::i()->ff_debug_log )
		{
			$html .= '<pre style="white-space:pre-wrap;">' . htmlspecialchars( json_encode( $this->redactActionResult( $actionResult ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) ?: '' ) . '</pre>';
		}

		return $html;
	}

	protected function redactActionResult( array $value ): array
	{
		foreach ( $value as $key => $item )
		{
			if ( in_array( strtolower( (string) $key ), [ 'api_key', 'portal_url', 'token', 'secret' ], TRUE ) )
			{
				$value[ $key ] = '[redacted]';
			}
			elseif ( is_array( $item ) )
			{
				$value[ $key ] = $this->redactActionResult( $item );
			}
		}
		return $value;
	}
}
