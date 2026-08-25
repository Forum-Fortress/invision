<?php

namespace IPS\forumfortress\extensions\core\Forms;

use DomainException;
use IPS\Extensions\FormsAbstract;
use IPS\forumfortress\Api\Client;
use IPS\Helpers\Form\Custom;
use IPS\Member;
use IPS\Settings;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class Registration extends FormsAbstract
{
	public static function formType() : string
	{
		return \IPS\Helpers\Form::FORM_REGISTRATION;
	}

	public function formElements() : array
	{
		return [
			new Custom( 'forumfortress_registration_check', NULL, FALSE, [
				'getHtml' => static fn() => '',
				'rowHtml' => static fn() => '',
				'formatValue' => static fn() => '1',
				'validate' => static function ( Custom $field ): void {
					if ( !Client::isEnabled() )
					{
						return;
					}

					$response = Client::checkRegisterFromRequest();

					if ( $response === NULL && Client::lastCheckHadTimeout() )
					{
						if ( !Settings::i()->ff_fail_open )
						{
							throw new DomainException( 'forumfortress_registration_blocked' );
						}
						return;
					}

					if ( $response === NULL )
					{
						if ( Settings::i()->ff_fail_open )
						{
							return;
						}

						throw new DomainException( 'forumfortress_api_unreachable' );
					}

					$code = $response['status_code'] ?? NULL;

					if ( (string) $code === 'ABOVELIMIT' && Settings::i()->ff_fail_open )
					{
						return;
					}

					if ( (string) $code === 'ABOVELIMIT' )
					{
						throw new DomainException( 'forumfortress_above_limit' );
					}

					$decision = strtolower( trim( (string) ( $response['decision'] ?? '' ) ) );

					if ( $decision === 'allow' )
					{
						return;
					}

					if ( $decision === 'block' && Client::registrationBlockAction() === 'reject' )
					{
						return;
					}

					if ( $decision !== 'allow' )
					{
						throw new DomainException( 'forumfortress_registration_blocked' );
					}
				},
			] ),
		];
	}

	public function processFormValues( array $values, ?Member $member = NULL ) : void
	{
		if ( $member !== NULL )
		{
			Client::completeRegistrationCheck( $member );
		}
	}
}
