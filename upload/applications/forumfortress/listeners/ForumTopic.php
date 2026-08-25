<?php

namespace IPS\forumfortress\listeners;

use IPS\Content as ContentClass;
use IPS\Events\ListenerType\ContentListenerType;
use IPS\forumfortress\Api\Client;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/** Covers UI, API and other supported topic creation/edit paths. */
class ForumTopic extends ContentListenerType
{
	public static string $class = \IPS\forums\Topic::class;

	public function onBeforeCreateOrEdit( ContentClass $object, array $values, bool $new = FALSE ) : void
	{
		Client::checkIpsContentBefore( $object, $values, $new, 'topic' );
	}

	public function onCreateOrEdit( ContentClass $object, array $values, bool $new = FALSE ) : void
	{
		Client::finishIpsContentCheck( $object, $values, $new, 'topic' );
	}
}
