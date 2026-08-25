<?php

namespace IPS\forumfortress\listeners;

use IPS\Events\ListenerType\MemberListenerType;
use IPS\forumfortress\Api\Client;
use IPS\Member;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class Fortress extends MemberListenerType
{
	public function onCreateAccount( Member $member ) : void
	{
		Client::completeRegistrationCheck( $member );
	}

	public function onProfileUpdate( Member $member, array $changes ) : void
	{
		Client::checkProfileUpdate( $member, $changes );
	}

	public function onSetAsSpammer( Member $member ) : void
	{
		Client::reportMemberVerdict( $member, 'moderation' );
	}

	public function onUnSetAsSpammer( Member $member ) : void
	{
		Client::reportMemberVerdict( $member, 'ham' );
	}

	public function onDelete( Member $member ) : void
	{
		Client::cleanupMemberApprovalOnDelete( $member );
	}
}
