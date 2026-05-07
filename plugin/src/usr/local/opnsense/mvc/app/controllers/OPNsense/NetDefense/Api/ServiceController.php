<?php

/**
 * Copyright (C) 2024 NetDefense
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\NetDefense\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 * @package OPNsense\NetDefense\Api
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\NetDefense\Settings';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceTemplate = 'OPNsense/NetDefense';
    protected static $internalServiceName = 'netdefense';

    /**
     * Path to the JSON status snapshot written by the Go agent on
     * connect/disconnect/heartbeat. See internal/status/status.go.
     */
    const STATUS_FILE = '/var/run/ndagent.status';

    /**
     * Snapshots older than this many seconds are treated as stale even
     * if the agent still claims it's connected — covers the case where
     * the process hung or was SIGKILL'd before it could rewrite the file.
     * Heartbeat interval is 60s, so 120s gives one missed beat headroom.
     */
    const STATUS_STALE_AFTER = 120;

    /**
     * Returns the agent's current version + WS connection status, read
     * from {@see STATUS_FILE}. Used by the NetDefense Settings page to
     * render the "Agent Version" and "Server Connection" cells.
     */
    public function agentStatusAction()
    {
        $defaults = [
            'version' => 'unknown',
            'connected' => false,
            'state' => 'unknown',
            'stale' => true,
            'server' => '',
            'since' => '',
            'last_error' => '',
        ];

        if (!is_readable(self::STATUS_FILE)) {
            return $defaults;
        }

        $raw = @file_get_contents(self::STATUS_FILE);
        if ($raw === false) {
            return $defaults;
        }

        $snap = @json_decode($raw, true);
        if (!is_array($snap)) {
            return $defaults;
        }

        $mtime = @filemtime(self::STATUS_FILE);
        $stale = ($mtime === false) || ((time() - $mtime) > self::STATUS_STALE_AFTER);

        $state = isset($snap['state']) ? (string)$snap['state'] : 'unknown';
        $connected = ($state === 'connected') && !$stale;

        return [
            'version' => isset($snap['version']) ? (string)$snap['version'] : 'unknown',
            'connected' => $connected,
            'state' => $state,
            'stale' => $stale,
            'server' => isset($snap['server']) ? (string)$snap['server'] : '',
            'since' => isset($snap['since']) ? (string)$snap['since'] : '',
            'last_error' => isset($snap['last_error']) ? (string)$snap['last_error'] : '',
        ];
    }
}