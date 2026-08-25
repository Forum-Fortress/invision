<?php

namespace IPS\forumfortress\extensions\core\UIItem;

use DomainException;
use IPS\Content\Item as BaseItem;
use IPS\forumfortress\Api\Client;
use IPS\forums\Topic;
use IPS\Helpers\Form\Custom;
use IPS\Node\Model;
use IPS\Output\UI\Item;
use IPS\Request;
use IPS\Settings;
use function in_array;
use function is_array;
use function trim;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class ForumTopic extends Item
{
	public static ?string $class = Topic::class;

	public function formElements( ?BaseItem $item, ?Model $container ): array
	{
		$endpoint = $item === NULL ? 'topic' : 'topic_edit';
		return [
			'forumfortress_topic_check' => new Custom( 'forumfortress_topic_check', NULL, FALSE, [
				'getHtml' => static fn() => '',
				'rowHtml' => static fn() => '',
				'formatValue' => static fn() => '1',
				'validate' => static function () use ( $endpoint ): void {
					if ( !Client::isEnabled() )
					{
						return;
					}

					$title = trim( (string) Request::i()->topic_title );
					$raw = trim( (string) Request::i()->topic_content );
					$content = trim( $title . "\n\n" . $raw );
					if ( $content === '' )
					{
						return;
					}

					$payload = [
						'ip' => Client::clientIp(),
						'username' => (string) \IPS\Member::loggedIn()->name,
						'email' => (string) \IPS\Member::loggedIn()->email,
						'email_domain' => Client::emailDomain( (string) \IPS\Member::loggedIn()->email ),
						'post_count' => (int) \IPS\Member::loggedIn()->member_posts,
						'account_age_seconds' => (int) ( time() - (int) \IPS\Member::loggedIn()->joined ),
						'user_agent' => (string) ( Request::i()->userAgent() ?? '' ),
						'content' => $content,
						'links' => Client::extractLinks( $content ),
					];
					$response = Client::checkContent( $endpoint, $payload );

					if ( $response === NULL )
					{
						if ( Settings::i()->ff_fail_open )
						{
							return;
						}
						throw new DomainException( 'forumfortress_api_unreachable' );
					}

					$decision = strtolower( trim( (string) ( $response['decision'] ?? '' ) ) );
					if ( $decision === 'block' )
					{
						throw new DomainException( 'forumfortress_post_blocked' );
					}
				},
			] ),
		];
	}
}
