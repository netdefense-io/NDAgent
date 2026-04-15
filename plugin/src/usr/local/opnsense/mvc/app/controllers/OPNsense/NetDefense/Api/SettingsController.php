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
use OPNsense\Auth\User;

/**
 * Class SettingsController
 * @package OPNsense\NetDefense\Api
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'settings';
    protected static $internalModelClass = '\OPNsense\NetDefense\Settings';

    /**
     * Username for the NetDefense API user
     */
    const NETDEFENSE_USERNAME = 'netdefense-agent';

    /**
     * Check if API credentials are configured
     * @return array status information
     */
    public function getApiStatusAction()
    {
        $mdl = $this->getModel();

        $status = [
            'configured' => false,
            'user_exists' => false,
            'has_api_key' => false,
            'key_count' => 0,
            'message' => ''
        ];

        // Check if user exists and has API keys
        $userMdl = new User();
        foreach ($userMdl->user->iterateItems() as $uuid => $user) {
            if ((string)$user->name === self::NETDEFENSE_USERNAME) {
                $status['user_exists'] = true;
                // Check if user has API keys using all() method
                $keys = $user->apikeys->all();
                if (!empty($keys)) {
                    $status['has_api_key'] = true;
                    $status['key_count'] = count($keys);
                }
                break;
            }
        }

        // Check our stored reference
        $apiConfigured = (string)$mdl->apiConfigured;
        $apiKey = (string)$mdl->apiKey;

        $status['configured'] = ($apiConfigured === '1' && !empty($apiKey));

        if (!$status['configured']) {
            $status['message'] = 'API credentials not configured. Click "Setup API Credentials" to configure.';
        } else {
            $status['message'] = 'API credentials are configured and ready.';
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

        try {
            Config::getInstance()->lock();

            $userMdl = new User();
            $existingUser = null;

            // Check if user already exists
            foreach ($userMdl->user->iterateItems() as $uuid => $user) {
                if ((string)$user->name === self::NETDEFENSE_USERNAME) {
                    $existingUser = $user;
                    break;
                }
            }

            // Create user if doesn't exist
            if ($existingUser === null) {
                $existingUser = $userMdl->user->Add();
                if ($existingUser === null) {
                    Config::getInstance()->unlock();
                    return ["result" => "failed", "message" => "Failed to create user"];
                }
                $existingUser->name = self::NETDEFENSE_USERNAME;
                $existingUser->disabled = '0';
                $existingUser->scope = 'user';
                $existingUser->descr = 'NetDefense Agent API User (auto-generated)';
                // Phase 1: Full admin privileges
                $existingUser->priv = 'page-all';
            }

            // Generate new API key
            $keyResult = $existingUser->apikeys->add();
            if (empty($keyResult) || !isset($keyResult['key']) || !isset($keyResult['secret'])) {
                Config::getInstance()->unlock();
                return ["result" => "failed", "message" => "Failed to generate API key"];
            }

            // Save user model to config
            $userMdl->serializeToConfig(false, true);

            // Store credentials directly in config XML
            // We bypass model validation since token/deviceId may not be configured yet.
            // Those fields will be validated when the user clicks Apply.
            $config = Config::getInstance()->object();

            // Ensure the path exists
            if (!isset($config->OPNsense)) {
                $config->addChild('OPNsense');
            }
            if (!isset($config->OPNsense->netdefense)) {
                $config->OPNsense->addChild('netdefense');
            }
            if (!isset($config->OPNsense->netdefense->settings)) {
                $config->OPNsense->netdefense->addChild('settings');
            }

            $settings = $config->OPNsense->netdefense->settings;
            $settings->apiKey = $keyResult['key'];
            $settings->apiSecret = $keyResult['secret'];
            $settings->apiConfigured = '1';

            Config::getInstance()->save();
            Config::getInstance()->unlock();

            // Sync user to system
            $backend = new Backend();
            $backend->configdpRun('auth sync user', [self::NETDEFENSE_USERNAME]);

            // Regenerate templates to write credentials to ndagent.conf
            $backend->configdRun('template reload OPNsense/NetDefense');

            return [
                "result" => "ok",
                "message" => "API credentials configured successfully",
                "api_key" => $keyResult['key'],
            ];

        } catch (\Exception $e) {
            Config::getInstance()->unlock();
            return ["result" => "failed", "message" => $e->getMessage()];
        }
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

        try {
            Config::getInstance()->lock();

            $userMdl = new User();
            $existingUser = null;

            // Find user
            foreach ($userMdl->user->iterateItems() as $uuid => $user) {
                if ((string)$user->name === self::NETDEFENSE_USERNAME) {
                    $existingUser = $user;
                    break;
                }
            }

            if ($existingUser === null) {
                Config::getInstance()->unlock();
                // User doesn't exist, just run setup
                return $this->setupApiCredsAction();
            }

            // Delete ALL existing API keys for this user (proper rotation)
            // The all() method returns array of ['key' => '...', ...] arrays
            $existingKeys = $existingUser->apikeys->all();
            $deletedCount = 0;
            foreach ($existingKeys as $keyData) {
                // Extract the key identifier from the array
                if (is_array($keyData) && isset($keyData['key'])) {
                    if ($existingUser->apikeys->del($keyData['key'])) {
                        $deletedCount++;
                    }
                } elseif (is_string($keyData)) {
                    // Fallback if it's already a string
                    if ($existingUser->apikeys->del($keyData)) {
                        $deletedCount++;
                    }
                }
            }

            // Generate new API key
            $keyResult = $existingUser->apikeys->add();
            if (empty($keyResult) || !isset($keyResult['key']) || !isset($keyResult['secret'])) {
                Config::getInstance()->unlock();
                return ["result" => "failed", "message" => "Failed to generate new API key"];
            }

            // Save user model
            $userMdl->serializeToConfig(false, true);

            // Store credentials directly in config XML (bypass model validation)
            $config = Config::getInstance()->object();
            if (isset($config->OPNsense->netdefense->settings)) {
                $settings = $config->OPNsense->netdefense->settings;
                $settings->apiKey = $keyResult['key'];
                $settings->apiSecret = $keyResult['secret'];
                $settings->apiConfigured = '1';
            }

            Config::getInstance()->save();
            Config::getInstance()->unlock();

            // Regenerate templates
            $backend = new Backend();
            $backend->configdRun('template reload OPNsense/NetDefense');

            // Restart service to pick up new credentials
            $backend->configdRun('netdefense restart');

            return [
                "result" => "ok",
                "message" => "API credentials regenerated successfully. Service restarted.",
            ];

        } catch (\Exception $e) {
            Config::getInstance()->unlock();
            return ["result" => "failed", "message" => $e->getMessage()];
        }
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