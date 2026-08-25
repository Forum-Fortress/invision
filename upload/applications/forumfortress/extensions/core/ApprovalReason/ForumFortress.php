<?php

namespace IPS\forumfortress\extensions\core\ApprovalReason;

use IPS\core\Approval;
use IPS\Extensions\ApprovalReasonAbstract;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class ForumFortress extends ApprovalReasonAbstract
{
	public function reasonKey(): string
	{
		return 'forum_fortress';
	}

	public function parseReason( Approval $approval ): array
	{
		return [
			'lang' => 'approval_reason_forum_fortress',
			'sprintf' => [],
		];
	}
}
