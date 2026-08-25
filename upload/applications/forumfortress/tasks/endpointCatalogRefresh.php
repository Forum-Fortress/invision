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

class endpointCatalogRefresh extends Task
{
	public function execute() : mixed
	{
		try
		{
			if ( !Client::refreshEndpointCatalogIfStale() )
			{
				throw new \RuntimeException( 'endpoint catalog refresh returned no usable catalog' );
			}
		}
		catch ( Throwable $e )
		{
			throw new TaskException( $this, 'Forum Fortress endpoint catalog refresh failed: ' . $e->getMessage() );
		}

		return NULL;
	}
}
