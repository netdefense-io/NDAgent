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

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\NetDefense\ApiCredsProvisioner;

/**
 * Class SettingsController
 * @package OPNsense\NetDefense\Api
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'settings';
    protected static $internalModelClass = '\OPNsense\NetDefense\Settings';

    /**
     * Check if API credentials are configured
     * @return array status information
     */
    public function getApiStatusAction()
    {
        $status = ApiCredsProvisioner::status();
        // Web UI expects a slightly more verbose default message when
        // credentials are missing — keep that wording here so the prompt
        // continues to point operators at the right button.
        if (!$status['configured']) {
            $status['message'] = 'API credentials not configured. Click "Setup API Credentials" to configure.';
        }
        return $status;
    }

    /**
     * Setup API credentials - creates user and API key
     * @return array result with status or error
     */
    public function setupApiCredsAction()
    {
        if (!$this->request->isPost()) {
            return ["result" => "failed", "message" => "POST request required"];
        }

        Config::getInstance()->lock();
        try {
            $result = ApiCredsProvisioner::provision(false);
            if ($result['result'] === 'ok') {
                Config::getInstance()->save();
            }
        } catch (\Exception $e) {
            Config::getInstance()->unlock();
            return ["result" => "failed", "message" => $e->getMessage()];
        }
        Config::getInstance()->unlock();

        if ($result['result'] === 'ok') {
            $backend = new Backend();
            $backend->configdpRun('auth sync user', [ApiCredsProvisioner::NETDEFENSE_USERNAME]);
            $backend->configdRun('template reload OPNsense/NetDefense');

            return [
                'result' => 'ok',
                'message' => 'API credentials configured successfully',
                'api_key' => $result['api_key'],
            ];
        }

        return $result;
    }

    /**
     * Regenerate API credentials - deletes old key and creates new one
     * @return array result
     */
    public function regenerateApiCredsAction()
    {
        if (!$this->request->isPost()) {
            return ["result" => "failed", "message" => "POST request required"];
        }

        Config::getInstance()->lock();
        try {
            $result = ApiCredsProvisioner::provision(true);
            if ($result['result'] === 'ok') {
                Config::getInstance()->save();
            }
        } catch (\Exception $e) {
            Config::getInstance()->unlock();
            return ["result" => "failed", "message" => $e->getMessage()];
        }
        Config::getInstance()->unlock();

        if ($result['result'] === 'ok') {
            $backend = new Backend();
            $backend->configdpRun('auth sync user', [ApiCredsProvisioner::NETDEFENSE_USERNAME]);
            $backend->configdRun('template reload OPNsense/NetDefense');
            $backend->configdRun('netdefense restart');

            return [
                'result' => 'ok',
                'message' => 'API credentials regenerated successfully. Service restarted.',
            ];
        }

        return $result;
    }

    /**
     * Get available shells from /etc/shells
     * @return array list of available shells (path => display label)
     */
    public function getShellsAction()
    {
        $shells = [];
        $defaultShell = '/usr/local/sbin/opnsense-shell';

        // Always include opnsense-shell as first option
        $shells[$defaultShell] = 'OPNsense Shell';

        if (file_exists('/etc/shells')) {
            $lines = file('/etc/shells', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                $line = trim($line);
                // Skip comments, empty lines, opnsense-installer, and already-added opnsense-shell
                if (empty($line) || $line[0] === '#') {
                    continue;
                }
                if (strpos($line, 'opnsense-installer') !== false) {
                    continue;
                }
                if ($line === $defaultShell) {
                    continue;
                }
                // Use basename for display, full path as value
                $shells[$line] = basename($line) . ' (' . $line . ')';
            }
        }

        return $shells;
    }
}
