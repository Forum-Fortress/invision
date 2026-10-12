<?php
// Copyright (c) 2026 Marscastle Ltd trading as Forum Fortress
// SPDX-License-Identifier: GPL-2.0-or-later
namespace IPS\forumfortress;
use IPS\Helpers\Form;
use IPS\Helpers\Form\Custom;
if (!defined('\IPS\SUITE_UNIQUE_KEY')) { header('HTTP/1.1 403 Forbidden'); exit; }
/** Capture the native form only after its validation/render boundary. */
class RepeatCheck extends Custom
{
    private ?Form $nativeForm=null;
    public function rowHtml(Form $form=null): string { $this->nativeForm=$form; return parent::rowHtml($form); }
    public function validatedSubmission(): bool
    {
        if (!$this->nativeForm || $this->error!=='forumfortress_post_blocked' || strtoupper(\IPS\Request::i()->requestMethod())!=='POST' || \IPS\Request::i()->ajaxValidate || !\IPS\Login::compareHashes(\IPS\Session::i()->csrfKey,(string)\IPS\Request::i()->csrfKey)) { return false; }
        foreach($this->nativeForm->elements as $elements) { foreach($elements as $element) { if ($element!==$this && $element instanceof Form\FormAbstract && $element->error) { return false; } } }
        return true;
    }
}
