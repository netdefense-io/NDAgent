<?php

/**
 * Copyright (C) 2024 NetDefense
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
            'key_state' => '',
            'key_message' => '',
            'tls_error' => '',
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
            'key_state' => isset($snap['key_state']) ? (string)$snap['key_state'] : '',
            'key_message' => isset($snap['key_message']) ? (string)$snap['key_message'] : '',
            'tls_error' => isset($snap['tls_error']) ? (string)$snap['tls_error'] : '',
        ];
    }
}