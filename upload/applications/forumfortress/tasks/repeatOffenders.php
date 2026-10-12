<?php
// Copyright (c) 2026 Marscastle Ltd trading as Forum Fortress
// SPDX-License-Identifier: GPL-2.0-or-later
namespace IPS\forumfortress\tasks;
if (!defined('\IPS\SUITE_UNIQUE_KEY')) { header('HTTP/1.1 403 Forbidden'); exit; }
class repeatOffenders extends \IPS\Task
{
    public function execute(): mixed { \IPS\forumfortress\RepeatOffenders::run(); return null; }
}
