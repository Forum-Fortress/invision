<?php
// Copyright (c) 2026 Marscastle Ltd trading as Forum Fortress
// SPDX-License-Identifier: GPL-2.0-or-later
namespace IPS\forumfortress;
use IPS\Db;
use IPS\Member;
use Throwable;
if (!defined('\IPS\SUITE_UNIQUE_KEY')) { header('HTTP/1.1 403 Forbidden'); exit; }

/** Only evidence is written at request shutdown; native account changes belong to the task. */
class RepeatOffenders
{
    private static array $staged = [];
    private static bool $armed = false;
    private static function q(string $sql): \mysqli_result|bool
    {
        $r = Db::i()->query($sql, MYSQLI_STORE_RESULT, false);
        if ($r === false) { throw new \RuntimeException('Repeat enforcement SQL failed'); }
        return $r;
    }
    private static function table(string $name): string { return '`'.str_replace('`','``',Db::i()->prefix.$name).'`'; }
    private static function rows(string $sql): array { return self::q($sql)->fetch_all(MYSQLI_ASSOC); }
    private static function idle(): bool
    {
        try { $r=self::rows('SELECT @@autocommit AS a, @@in_transaction AS t'); return (int)$r[0]['a']===1 && (int)$r[0]['t']===0; }
        catch(Throwable $e) { return false; }
    }
    public static function available(): bool
    {
        if (!self::idle() || !is_file(__DIR__.'/../../tasks/repeatOffenders.php')) { return false; }
        try {
            $required=['forumfortress_repeat_state','forumfortress_repeat_events','core_members','core_groups','core_admin_permission_rows','core_moderators','core_sys_conf_settings','core_applications','core_member_history','core_oauth_server_access_tokens','core_api_webhooks','core_api_webhook_fires','core_tasks','core_validating'];
            $engines=[]; foreach(self::rows('SHOW TABLE STATUS') as $r) { $engines[$r['Name']]=$r['Engine']; }
            foreach($required as $t) { if (($engines[Db::i()->prefix.$t]??'')!=='InnoDB') { return false; } }
            return method_exists(Member::class,'set_temp_ban') && method_exists(Member::class,'logHistory');
        } catch(Throwable $e) { return false; }
    }
    private static function begin(): void { self::q('START TRANSACTION'); if ((int)self::rows('SELECT @@in_transaction AS t')[0]['t']!==1) { throw new \RuntimeException('No owned transaction'); } }
    private static function rollback(): void { try { self::q('ROLLBACK'); } catch(Throwable $e) {} }
    private static function mutex(): void
    {
        self::q('INSERT INTO '.self::table('forumfortress_repeat_state').' (member_id,pending,touched,attempted) VALUES (0,0,0,0) ON DUPLICATE KEY UPDATE member_id=VALUES(member_id)');
        self::q('SELECT member_id FROM '.self::table('forumfortress_repeat_state').' WHERE member_id=0 FOR UPDATE');
    }
    /** Read/lock settings and application status from the write server, never the IPS cache. */
    private static function settings(): array
    {
        $s=[]; foreach(self::rows('SELECT conf_key,conf_value,conf_default FROM '.self::table('core_sys_conf_settings')." WHERE conf_key IN ('ff_enabled','ff_repeat_ban','member_group') FOR UPDATE") as $r) { $s[$r['conf_key']]=$r['conf_value']===''?$r['conf_default']:$r['conf_value']; }
        $a=self::rows('SELECT app_enabled FROM '.self::table('core_applications')." WHERE app_directory='forumfortress' FOR UPDATE");
        $s['member_group']=\IPS\Settings::i()->getFromConfGlobal('member_group');
        $s['active']=!empty($a[0]['app_enabled']) && (string)($s['ff_enabled']??'')==='1' && (string)($s['ff_repeat_ban']??'')==='1';
        return $s;
    }
    private static function member(int $id,array $s): ?array
    {
        $r=self::rows('SELECT * FROM '.self::table('core_members')." WHERE member_id=$id FOR UPDATE"); $m=$r[0]??null;
        if (!$m || $id<=1 || trim((string)$m['name'])==='' || trim((string)$m['email'])==='' || !$m['completed'] || ((int)$m['members_bitoptions'] & 1073741825)!==0 || (int)$m['joined']<=0 || (int)$m['joined']>time() || (int)$m['joined']<time()-604800 || (int)$m['member_posts']>10 || (int)$m['temp_ban']!==0 || (int)$m['restrict_post']!==0 || (int)$m['mod_posts']!==0 || trim((string)$m['mgroup_others'])!=='' || (int)$m['member_group_id']!==(int)($s['member_group']??0)) { return null; }
        $gid=(int)$m['member_group_id']; if ($gid<=2 || $gid===4) { return null; }
        $g=self::rows('SELECT g_view_board FROM '.self::table('core_groups')." WHERE g_id=$gid FOR UPDATE"); if (empty($g[0]['g_view_board'])) { return null; }
        $admins=self::rows('SELECT row_id FROM '.self::table('core_admin_permission_rows')." WHERE (row_id_type='member' AND row_id=$id) OR (row_id_type='group' AND row_id=$gid) FOR UPDATE");
        $mods=self::rows('SELECT id FROM '.self::table('core_moderators')." WHERE (type='m' AND id=$id) OR (type='g' AND id=$gid) FOR UPDATE");
        if ($admins || $mods || self::rows('SELECT member_id FROM '.self::table('core_validating')." WHERE member_id=$id FOR UPDATE")) { return null; }
        return $m;
    }
    public static function stage(int $id,string $body,?array $response,?callable $validated=null): void
    {
        if (!(bool)(\IPS\Settings::i()->ff_repeat_ban ?? false) || !(bool)\IPS\Settings::i()->ff_enabled || $id<=1 || $id!==(int)Member::loggedIn()->member_id || $body==='' || strtolower(trim((string)($response['decision']??'')))!=='block' || ($response['escalation_eligible']??null)!==true || count(self::$staged)>=16) { return; }
        $ref=$response['decision_reference']??null;
        if (is_string($ref) && trim($ref)!=='' && strlen(trim($ref))<=256) { $ref='reference:'.trim($ref); }
        else {
            $ref=$response['decision_id']??null;
            if (!(is_int($ref)||is_string($ref)) || !preg_match('/^[0-9]{1,32}$/',(string)$ref) || trim((string)$ref,'0')==='') { return; }
            $ref='decision:'.ltrim((string)$ref,'0');
        }
        self::$staged[]=[$id,hash('sha256',$body),hash('sha256',$ref),$validated];
        if (!self::$armed) { self::$armed=true; register_shutdown_function([self::class,'flush']); }
    }
    public static function flush(): void
    {
        $events=self::$staged; self::$staged=[];
        foreach($events as [$id,$body,$ref,$validated]) {
            try { if ($validated!==null && !$validated()) { continue; } } catch(Throwable $e) { continue; }
            self::record($id,$body,$ref);
        }
    }
    private static function record(int $id,string $body,string $ref): void
    {
        if (!self::available()) { return; }
        try {
            self::begin(); self::mutex(); $s=self::settings();
            if (!$s['active'] || !self::member($id,$s)) { self::q('COMMIT'); return; }
            $state=self::rows('SELECT * FROM '.self::table('forumfortress_repeat_state')." WHERE member_id=$id FOR UPDATE");
            if (!empty($state[0]['attempted'])) { self::q('COMMIT'); return; }
            $total=(int)self::rows('SELECT COUNT(*) AS n FROM '.self::table('forumfortress_repeat_events'))[0]['n'];
            $states=(int)self::rows('SELECT COUNT(*) AS n FROM '.self::table('forumfortress_repeat_state'))[0]['n'];
            $count=(int)self::rows('SELECT COUNT(*) AS n FROM '.self::table('forumfortress_repeat_events')." WHERE member_id=$id")[0]['n'];
            if ($total>=50000 || $states>=100000 || $count>=128) { self::q('COMMIT'); return; }
            $now=time();
            self::q('INSERT INTO '.self::table('forumfortress_repeat_state')." (member_id,pending,touched,attempted) VALUES ($id,0,$now,0) ON DUPLICATE KEY UPDATE touched=VALUES(touched)");
            self::q('INSERT IGNORE INTO '.self::table('forumfortress_repeat_events')." (member_id,body_hash,ref_hash,observed,consumed) VALUES ($id,'$body','$ref',$now,0)");
            $n=self::count($id);
            if ($n>=2) { self::q('UPDATE '.self::table('forumfortress_repeat_state')." SET pending=1 WHERE member_id=$id AND attempted=0"); }
            self::q('COMMIT');
        } catch(Throwable $e) { self::rollback(); }
    }
    private static function count(int $id): int
    {
        $since=time()-86400; return (int)self::rows('SELECT COUNT(*) AS n FROM '.self::table('forumfortress_repeat_events')." WHERE member_id=$id AND consumed=0 AND observed>=$since AND observed<=".time())[0]['n'];
    }
    private static function consume(int $id): void
    {
        self::q('UPDATE '.self::table('forumfortress_repeat_events')." SET consumed=1 WHERE member_id=$id");
        self::q('UPDATE '.self::table('forumfortress_repeat_state')." SET pending=0 WHERE member_id=$id");
    }
    public static function run(): void
    {
        if (!self::available()) { return; }
        try {
            $ids=self::rows('SELECT member_id FROM '.self::table('forumfortress_repeat_state').' WHERE pending=1 ORDER BY touched LIMIT 50');
            foreach($ids as $row) { self::apply((int)$row['member_id']); }
            self::prune();
        } catch(Throwable $e) { self::rollback(); }
    }
    private static function apply(int $id): void
    {
        if (!self::available()) { return; }
        try {
            self::begin(); self::mutex(); $s=self::settings();
            $state=self::rows('SELECT * FROM '.self::table('forumfortress_repeat_state')." WHERE member_id=$id FOR UPDATE");
            if (empty($state[0]['pending']) || !empty($state[0]['attempted'])) { self::q('COMMIT'); return; }
            $m=$s['active']?self::member($id,$s):null;
            if (!$m || self::count($id)<2) { self::consume($id); self::q('COMMIT'); return; }
            /* Native setter revokes OAuth tokens and queues native webhooks. Save and history
             * share the evidence transaction, so failure/process death permits a safe retry. */
            $member=Member::constructFromData($m); $until=time()+604800;
            $member->temp_ban=(string)$until;
            $member->logHistory('core','warning',['restrictions'=>['ban'=>['old'=>0,'new'=>$until]],'forumfortress'=>'Two certified original-score >80 BLOCKs in 24 hours'],new Member);
            $member->save();
            $saved=self::rows('SELECT * FROM '.self::table('core_members')." WHERE member_id=$id FOR UPDATE")[0];
            if ((int)$saved['temp_ban']!==$until || $saved['member_group_id']!=$m['member_group_id'] || $saved['mgroup_others']!=$m['mgroup_others']) { throw new \RuntimeException('Native ban changed account unexpectedly'); }
            self::q('UPDATE '.self::table('forumfortress_repeat_state')." SET attempted=".time().",touched=".time()." WHERE member_id=$id AND attempted=0");
            self::consume($id); self::q('COMMIT');
        } catch(Throwable $e) { self::rollback(); }
    }
    public static function cancelPending(): void
    {
        if (!self::idle()) { return; }
        try { self::begin(); self::mutex(); self::q('UPDATE '.self::table('forumfortress_repeat_events').' SET consumed=1 WHERE consumed=0'); self::q('UPDATE '.self::table('forumfortress_repeat_state').' SET pending=0 WHERE pending=1'); self::q('COMMIT'); }
        catch(Throwable $e) { self::rollback(); }
    }
    private static function prune(): void
    {
        if (!self::idle()) { return; }
        try {
            self::begin(); self::mutex(); $old=time()-604800;
            self::q('DELETE FROM '.self::table('forumfortress_repeat_events')." WHERE observed<$old ORDER BY observed LIMIT 500");
            $ids=self::rows('SELECT s.member_id FROM '.self::table('forumfortress_repeat_state').' s LEFT JOIN '.self::table('core_members')." m ON m.member_id=s.member_id WHERE s.member_id>0 AND (m.member_id IS NULL OR (s.attempted=0 AND s.pending=0 AND s.touched<$old)) LIMIT 500");
            foreach($ids as $r) { $id=(int)$r['member_id']; self::q('DELETE FROM '.self::table('forumfortress_repeat_events')." WHERE member_id=$id"); self::q('DELETE FROM '.self::table('forumfortress_repeat_state')." WHERE member_id=$id"); }
            self::q('COMMIT');
        } catch(Throwable $e) { self::rollback(); }
    }
    public static function recent(): array
    {
        try { return self::rows('SELECT member_id,attempted FROM '.self::table('forumfortress_repeat_state').' WHERE attempted>0 ORDER BY attempted DESC LIMIT 15'); }
        catch(Throwable $e) { return []; }
    }
}
