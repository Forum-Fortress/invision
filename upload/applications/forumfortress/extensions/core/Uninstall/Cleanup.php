<?php

namespace IPS\forumfortress\extensions\core\Uninstall;

use IPS\Db;
use IPS\Extensions\UninstallAbstract;
use IPS\forumfortress\Api\Client;
use IPS\Log;
use IPS\Member;
use Throwable;
use function is_array;
use function json_decode;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/** Remove only runtime state that Forum Fortress owns. */
class Cleanup extends UninstallAbstract
{
	public function preUninstall( string $application ) : void
	{
		if ( $application !== 'forumfortress' )
		{
			return;
		}

		try
		{
			$result = Client::deprovisionSite( 'plugin_uninstall' );
			if ( !in_array( strtolower( trim( (string) ( $result['status'] ?? '' ) ) ), [ 'ok', 'already_removed', 'no_identity' ], TRUE ) )
			{
				Log::log( 'Forum Fortress remote deprovisioning was not confirmed during uninstall.', 'forumfortress' );
			}
		}
		catch ( Throwable $e )
		{
			/* Uninstall remains possible during an outage, but the failure is visible
			 * to the operator instead of silently orphaning the remote site. */
			Log::log( 'Forum Fortress remote deprovisioning failed during uninstall: ' . $e->getMessage(), 'forumfortress' );
		}

		try
		{
			foreach ( Db::i()->select( '*', 'core_approval_queue' ) as $row )
			{
				$held = json_decode( (string) ( $row['approval_held_data'] ?? '' ), TRUE );
				$metadata = is_array( $held ) ? ( $held['forum_fortress'] ?? NULL ) : NULL;
				if ( !is_array( $metadata ) )
				{
					continue;
				}

				/* Keep hidden content in IC5's native review queue after the app is
				 * removed; only transfer the reason and discard FF-owned metadata. */
				unset( $held['forum_fortress'] );
				Db::i()->update( 'core_approval_queue', [
					'approval_held_reason' => 'user',
					'approval_held_data' => json_encode( $held, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE ),
				], [ 'approval_id=?', (int) $row['approval_id'] ] );
			}

			foreach ( Db::i()->select( '*', 'core_validating', [ 'spam_flag=? AND new_reg=?', 2, 1 ] ) as $row )
			{
				$held = json_decode( (string) ( $row['extra'] ?? '' ), TRUE );
				$metadata = is_array( $held ) ? ( $held['forum_fortress'] ?? NULL ) : NULL;
				if ( !is_array( $metadata ) )
				{
					continue;
				}
				try
				{
					$member = Member::load( (int) $row['member_id'] );
					if ( !empty( $metadata['restriction_applied'] ) && (int) $member->restrict_post === -1 )
					{
						$member->restrict_post = 0;
					}
					if ( !empty( $metadata['ban_applied'] ) && (int) $member->temp_ban === -1 )
					{
						$member->temp_ban = 0;
					}
					$member->save();
				}
				catch ( Throwable $e )
				{
				}

				unset( $held['forum_fortress'] );
				Db::i()->update( 'core_validating', [
					'spam_flag' => 1,
					'extra' => $held ? json_encode( $held, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE ) : NULL,
				], [ 'vid=? AND member_id=?', (string) $row['vid'], (int) $row['member_id'] ] );
			}
		}
		catch ( Throwable $e )
		{
			Log::log( 'Forum Fortress uninstall cleanup failed: ' . $e->getMessage(), 'forumfortress' );
		}
	}
}
