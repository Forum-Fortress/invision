<?php

namespace IPS\forumfortress\extensions\core\UIComment;

use DomainException;
use IPS\Content\Comment as BaseComment;
use IPS\Content\Item as BaseItem;
use IPS\forumfortress\Api\Client;
use IPS\forums\Topic\Post;
use IPS\Helpers\Form\Custom;
use IPS\Output\UI\Comment;
use IPS\Request;
use IPS\Settings;
use function in_array;
use function trim;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class ForumPost extends Comment
{
	public static ?string $class = Post::class;

	public function formElements( ?BaseComment $comment, BaseItem $item ): array
	{
		$endpoint = $comment === NULL ? 'reply' : 'reply_edit';
		return [
			'forumfortress_reply_check' => new Custom( 'forumfortress_reply_check', NULL, FALSE, [
				'getHtml' => static fn() => '',
				'rowHtml' => static fn() => '',
				'formatValue' => static fn() => '1',
				'validate' => static function () use ( $item, $endpoint ): void {
					if ( !Client::isEnabled() )
					{
						return;
					}

					$idColumn = $item::$databaseColumnId;
					$itemId = (int) $item->$idColumn;
					$key = 'topic_comment_' . $itemId;
					/* IC5 reply edits submit the editor body as comment_value; the
					 * comment field is the numeric content ID and must never be sent
					 * to the checker as if it were the proposed text. */
					$raw = trim( (string) ( Request::i()->comment_value ?? Request::i()->$key ?? '' ) );
					if ( $raw === '' )
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
						'content' => $raw,
						'links' => Client::extractLinks( $raw ),
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
