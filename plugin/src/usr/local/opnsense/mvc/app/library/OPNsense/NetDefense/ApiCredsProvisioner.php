<?php

/**
 * Copyright (C) 2026 NetDefense
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
 */

namespace OPNsense\NetDefense;

use OPNsense\Core\Config;
use OPNsense\Auth\User;

/**
 * Shared OPNsense API credential provisioning for NetDefense.
 *
 * Used by both the web UI controller (Api\SettingsController) and the
 * unattended-install CLI helper (scripts/OPNsense/NetDefense/configure.php).
 *
 * The caller owns the Config lock + save + Backend triggers (configdpRun
 * 'auth sync user' and configdRun 'template reload OPNsense/NetDefense').
 * That separation lets the CLI persist token + deviceId + API creds in a
 * single Config save, while the web controller keeps its own transaction.
 */
class ApiCredsProvisioner
{
    /** Username for the auto-created OPNsense user that owns the API key. */
    const NETDEFENSE_USERNAME = 'netdefense-agent';

    /**
     * Report current state of the netdefense-agent user + API key.
     *
     * @return array{configured:bool,user_exists:bool,has_api_key:bool,key_count:int,message:string}
     */
    public static function status(): array
    {
        $status = [
            'configured' => false,
            'user_exists' => false,
            'has_api_key' => false,
            'key_count' => 0,
            'message' => '',
        ];

        $userMdl = new User();
        foreach ($userMdl->user->iterateItems() as $user) {
            if ((string)$user->name === self::NETDEFENSE_USERNAME) {
                $status['user_exists'] = true;
                $keys = $user->apikeys->all();
                if (!empty($keys)) {
                    $status['has_api_key'] = true;
                    $status['key_count'] = count($keys);
                }
                break;
            }
        }

        $config = Config::getInstance()->object();
        $apiConfigured = '0';
        $apiKey = '';
        if (isset($config->OPNsense->netdefense->settings)) {
            $apiConfigured = (string)$config->OPNsense->netdefense->settings->apiConfigured;
            $apiKey = (string)$config->OPNsense->netdefense->settings->apiKey;
        }

        $status['configured'] = ($apiConfigured === '1' && !empty($apiKey));
        $status['message'] = $status['configured']
            ? 'API credentials are configured and ready.'
            : 'API credentials not configured.';

        return $status;
    }

    /**
     * Provision (or rotate) the netdefense-agent user + API key.
     *
     * Caller is responsible for: Config::getInstance()->lock(), the matching
     * unlock(), save(), and Backend triggers. This method only mutates the
     * in-memory Config tree and the User model.
     *
     * Idempotency: when $rotateExisting=false and the user already has at
     * least one API key, returns ['result'=>'skipped',...] without touching
     * the user model. When $rotateExisting=true, deletes all existing keys
     * for the user before generating a new one.
     *
     * Failure compensation: if a fresh user is created here but key
     * generation fails, the just-added user is removed before returning so
     * a retry starts clean.
     *
     * The generated key + secret are written directly into the config XML
     * (so the Volt template renders them into ndagent.conf) but are never
     * returned to the caller — the operator should not see, log, or
     * screenshot the credential. Only the locally running agent needs it.
     *
     * @param bool $rotateExisting force key rotation (delete existing keys)
     * @return array{result:string,message:string}
     */
    public static function provision(bool $rotateExisting = false): array
    {
        $userMdl = new User();
        $existingUser = null;
        $existingUserUuid = null;
        $createdFreshUser = false;

        foreach ($userMdl->user->iterateItems() as $uuid => $user) {
            if ((string)$user->name === self::NETDEFENSE_USERNAME) {
                $existingUser = $user;
                $existingUserUuid = $uuid;
                break;
            }
        }

        // Idempotent skip: same op as setup, user+key already present.
        if (!$rotateExisting && $existingUser !== null) {
            $existingKeys = $existingUser->apikeys->all();
            if (!empty($existingKeys)) {
                $config = Config::getInstance()->object();
                $apiConfigured = isset($config->OPNsense->netdefense->settings)
                    ? (string)$config->OPNsense->netdefense->settings->apiConfigured
                    : '0';
                if ($apiConfigured === '1') {
                    return [
                        'result' => 'skipped',
                        'message' => 'API credentials already configured; no change.',
                    ];
                }
                // User has key but config XML lost track — fall through to
                // re-attach the existing key info to settings via a fresh add.
            }
        }

        // Create user if it doesn't exist.
        if ($existingUser === null) {
            $existingUser = $userMdl->user->Add();
            if ($existingUser === null) {
                return ['result' => 'failed', 'message' => 'Failed to create user'];
            }
            $existingUser->name = self::NETDEFENSE_USERNAME;
            $existingUser->disabled = '0';
            $existingUser->scope = 'user';
            $existingUser->descr = 'NetDefense Agent API User (auto-generated)';
            // Phase 1: full admin privileges (matches existing controller behavior).
            $existingUser->priv = 'page-all';
            $createdFreshUser = true;
        }

        // For rotation, delete every existing key first so the saved set
        // contains only the freshly generated one.
        if ($rotateExisting) {
            $existingKeys = $existingUser->apikeys->all();
            foreach ($existingKeys as $keyData) {
                if (is_array($keyData) && isset($keyData['key'])) {
                    $existingUser->apikeys->del($keyData['key']);
                } elseif (is_string($keyData)) {
                    $existingUser->apikeys->del($keyData);
                }
            }
        }

        $keyResult = $existingUser->apikeys->add();
        if (empty($keyResult) || !isset($keyResult['key']) || !isset($keyResult['secret'])) {
            // If we just created this user, undo that so the next attempt is clean.
            if ($createdFreshUser && $existingUserUuid === null) {
                // Locate the freshly-added user by name and remove it.
                foreach ($userMdl->user->iterateItems() as $uuid => $user) {
                    if ((string)$user->name === self::NETDEFENSE_USERNAME) {
                        $userMdl->user->del($uuid);
                        break;
                    }
                }
            }
            return ['result' => 'failed', 'message' => 'Failed to generate API key'];
        }

        $userMdl->serializeToConfig(false, true);

        // Write apiKey/apiSecret/apiConfigured directly into the config XML
        // rather than going through the Settings model. The model marks
        // token + deviceId as Required=Y, but the unattended-install path
        // may set those in the same transaction (or they may be empty for a
        // standalone web-UI "Setup API" click). Direct XML write bypasses
        // that validation; the model's Apply path validates on the next
        // user-driven save.
        $config = Config::getInstance()->object();
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

        return [
            'result' => 'ok',
            'message' => 'API credentials configured successfully',
        ];
    }
}
