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
use OPNsense\Core\ACL;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\NetDefense\ApiCredsProvisioner;
use OPNsense\NetDefense\LocalAccounts;
use OPNsense\NetDefense\ReadOnlyUserProvisioner;

/**
 * Class SettingsController
 * @package OPNsense\NetDefense\Api
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'settings';
    protected static $internalModelClass = '\OPNsense\NetDefense\Settings';

    /**
     * Retrieve model settings, omitting the OPNsense API credentials.
     * apiKey/apiSecret are never read back by settings.volt (the web UI
     * doesn't bind them to any form field), so this is zero UI impact.
     * Defense-in-depth on top of the ACL split: this route is gated by the
     * full-admin page-services-netdefense priv (api/netdefense/* wildcard),
     * but a future manual ACL misgrant should not be able to read secrets
     * off this endpoint regardless of caller.
     * @return array settings
     */
    public function getAction()
    {
        $result = parent::getAction();
        if (isset($result[static::$internalModelName])) {
            unset($result[static::$internalModelName]['apiKey']);
            unset($result[static::$internalModelName]['apiSecret']);
        }
        return $result;
    }

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

        // Explicit read-only guard, on top of the ACL split: mirrors the
        // same check ApiMutableModelControllerBase::save() uses so a
        // future manual ACL misgrant can't reach Config::save() below.
        if ((new ACL())->hasPrivilege($this->getUserName(), 'user-config-readonly')) {
            return ["result" => "failed", "message" => "Read-only session: write denied"];
        }

        Config::getInstance()->lock();
        $readonlyResult = ['result' => 'skipped'];
        $passwordResult = ['result' => 'skipped', 'changed' => false];
        try {
            // provision() returns 'skipped' before it looks at an already
            // configured user, so repair an empty password from an earlier
            // release first. If it cannot be repaired the setup fails.
            $passwordResult = ApiCredsProvisioner::ensurePassword();
            $result = $passwordResult['result'] === 'failed'
                ? ['result' => 'failed', 'message' => $passwordResult['message']]
                : ApiCredsProvisioner::provision(false);
            // Provision the shared read-only WebAdmin user in the same
            // transaction so it exists from day one alongside the agent
            // user. No API key — only the curated read-only ACL and a
            // scrambled password nobody knows. A failure here is non-fatal
            // to API setup.
            $readonlyResult = ReadOnlyUserProvisioner::provision();
            if (
                $result['result'] === 'ok'
                || $readonlyResult['result'] === 'ok'
                || $passwordResult['changed']
            ) {
                Config::getInstance()->save();
            }
        } catch (\Exception $e) {
            Config::getInstance()->unlock();
            return ["result" => "failed", "message" => $e->getMessage()];
        }
        Config::getInstance()->unlock();

        $backend = new Backend();
        if ($readonlyResult['result'] === 'ok') {
            $backend->configdpRun('auth sync user', [ReadOnlyUserProvisioner::READONLY_USERNAME]);
        }

        if ($result['result'] === 'ok' || $passwordResult['changed']) {
            $backend->configdpRun('auth sync user', [ApiCredsProvisioner::NETDEFENSE_USERNAME]);
        }

        if ($result['result'] === 'ok') {
            $backend->configdRun('template reload OPNsense/NetDefense');

            // Note: the generated API key/secret are intentionally not
            // included in the response. They live only in /conf/config.xml
            // and the rendered ndagent.conf — never on the wire to the UI.
            return [
                'result' => 'ok',
                'message' => 'API credentials configured successfully',
            ];
        }

        // API setup didn't change anything (e.g. already configured), but
        // the read-only user may still have been (re)provisioned — reload
        // the template so the conf reflects the current state.
        if ($readonlyResult['result'] === 'ok') {
            $backend->configdRun('template reload OPNsense/NetDefense');
        }

        // provision() answers 'skipped' once the credentials are in place, and
        // the UI reads anything but 'ok' as a failed setup. Whatever this call
        // wrote, a password or the read-only user and group, is a repair and
        // answers 'ok'; 'skipped' is left for a call that changed nothing.
        $passwords = [];
        if ($passwordResult['changed']) {
            $passwords[] = ApiCredsProvisioner::NETDEFENSE_USERNAME;
        }
        $readonlyPassword = $readonlyResult['password'] ?? LocalAccounts::PASSWORD_KEPT;
        if ($readonlyPassword === LocalAccounts::PASSWORD_SET) {
            $passwords[] = ReadOnlyUserProvisioner::READONLY_USERNAME;
        }
        $repairs = [];
        if (!empty($passwords)) {
            $repairs[] = 'account passwords repaired (' . implode(', ', $passwords) . ')';
        }
        // No password given, yet an 'ok' from the read-only provisioner still
        // saved something: the group created, or its privileges or membership
        // rewritten.
        if ($readonlyResult['result'] === 'ok' && $readonlyPassword !== LocalAccounts::PASSWORD_SET) {
            $repairs[] = 'read-only user and group reconciled (' . ReadOnlyUserProvisioner::READONLY_USERNAME . ')';
        }
        if ($result['result'] === 'skipped' && !empty($repairs)) {
            return [
                'result' => 'ok',
                'message' => ucfirst(implode('; ', $repairs)) . '; API credentials were already configured.',
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

        // Explicit read-only guard, on top of the ACL split: mirrors the
        // same check ApiMutableModelControllerBase::save() uses so a
        // future manual ACL misgrant can't reach Config::save() below.
        if ((new ACL())->hasPrivilege($this->getUserName(), 'user-config-readonly')) {
            return ["result" => "failed", "message" => "Read-only session: write denied"];
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
