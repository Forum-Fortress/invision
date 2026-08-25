<?php

namespace IPS\forumfortress;

use IPS\Application as SystemApplication;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class Application extends SystemApplication
{
}
