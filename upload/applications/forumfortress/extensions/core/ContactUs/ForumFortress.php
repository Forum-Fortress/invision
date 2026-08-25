<?php

namespace IPS\forumfortress\extensions\core\ContactUs;

use DomainException;
use IPS\Extensions\ContactUsAbstract;
use IPS\forumfortress\Api\Client;
use IPS\Helpers\Form;
use IPS\Helpers\Form\Custom;
use IPS\Member;
use IPS\Request;
use IPS\Settings;
use function strtolower;
use function trim;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * Protect the stock IPS contact form using the supported ContactUs extension.
 *
 * The validation field is intentionally invisible. It runs as part of the
 * normal form validation before the selected core contact handler sends mail.
 */
class ForumFortress extends ContactUsAbstract
{
	public function process( Form &$form, array &$formFields, array &$options, array &$toggles, array &$disabled ) : void
	{
	}

	public function runBeforeFormOutput( Form $form ) : void
	{
		$form->add( new Custom( 'forumfortress_contact_check', NULL, FALSE, [
			'getHtml' => static fn() => '',
			'rowHtml' => static fn() => '',
			'formatValue' => static fn() => '1',
			'validate' => static function (): void {
				if ( !Client::isEnabled() )
				{
					return;
				}

				$content = trim( (string) ( Request::i()->contact_text ?? '' ) );
				if ( $content === '' )
				{
					return;
				}

				$member = Member::loggedIn();
				$email = $member->member_id
					? (string) $member->email
					: trim( (string) ( Request::i()->email_address ?? '' ) );
				$name = $member->member_id
					? (string) $member->name
					: trim( (string) ( Request::i()->contact_name ?? '' ) );
				$response = Client::checkContent( 'contact_page', [
					'ip' => Client::clientIp(),
					'username' => $name,
					'email' => $email,
					'email_domain' => Client::emailDomain( $email ),
					'user_agent' => (string) ( Request::i()->userAgent() ?? '' ),
					'content' => $content,
					'links' => Client::extractLinks( $content ),
				] );

				if ( $response === NULL )
				{
					if ( Settings::i()->ff_fail_open )
					{
						return;
					}
					throw new DomainException( 'forumfortress_api_unreachable' );
				}

				if ( strtolower( trim( (string) ( $response['decision'] ?? '' ) ) ) !== 'allow' )
				{
					throw new DomainException( 'forumfortress_contact_blocked' );
				}
			},
		] ) );
	}

	public function handleForm( array $values ) : bool
	{
		return FALSE;
	}
}
