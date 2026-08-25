<?php

namespace IPS\forumfortress\tasks;

use IPS\forumfortress\Api\Client;
use IPS\Task;
use IPS\Task\Exception as TaskException;
use Throwable;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class hourlySync extends Task
{
	public function execute() : mixed
	{
		try
		{
			if ( !Client::hourlySync() )
			{
				throw new \RuntimeException( 'one or more synchronization operations failed' );
			}
		}
		catch ( Throwable $e )
		{
			throw new TaskException( $this, 'Forum Fortress hourly synchronization failed: ' . $e->getMessage() );
		}

		return NULL;
	}
}
