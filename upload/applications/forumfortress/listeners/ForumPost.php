<?php

namespace IPS\forumfortress\listeners;

use IPS\Content as ContentClass;
use IPS\Events\ListenerType\ContentListenerType;
use IPS\forumfortress\Api\Client;
use Throwable;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/** Covers reply edits; native reply creation is checked by the UIComment extension. */
class ForumPost extends ContentListenerType
{
	public static string $class = \IPS\forums\Topic\Post::class;

	public function onBeforeCreateOrEdit( ContentClass $object, array $values, bool $new = FALSE ) : void
	{
		if ( !$new && !$this->isFirstPost( $object ) )
		{
			Client::checkIpsContentBefore( $object, $values, FALSE, 'reply' );
		}
	}

	public function onCreateOrEdit( ContentClass $object, array $values, bool $new = FALSE ) : void
	{
		/* IC5 has no reply before-create event. Native forms are protected by the
		 * UIComment extension; a late event cannot retract notifications, search,
		 * achievements or counters from a programmatic create. */
		if ( !$new && !$this->isFirstPost( $object ) )
		{
			Client::finishIpsContentCheck( $object, $values, $new, 'reply' );
		}
	}

	protected function isFirstPost( ContentClass $object ): bool
	{
		try
		{
			return (bool) $object->mapped( 'first' );
		}
		catch ( Throwable $e )
		{
			return FALSE;
		}
	}
}
