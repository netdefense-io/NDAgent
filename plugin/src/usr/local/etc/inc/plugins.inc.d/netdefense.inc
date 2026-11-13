<?php

/*
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

function netdefense_configure()
{
    return [
        'bootup' => ['netdefense_bootup'],
    ];
}

/*
 * The read-only group holds what the running OPNsense knows, which a reboot
 * can change (a major upgrade, a plugin installed since). Detached, so boot
 * does not wait for it, and through the action that reloads the template only
 * when a Settings default was written: a render rewrites ndagent.conf in place
 * and could overlap the agent starting. plugins_configure() catches only
 * \Error: an exception escaping here would abort rc.bootup, so nothing may.
 */
function netdefense_bootup($verbose = false)
{
    try {
        configd_run('netdefense reconcile-readonly', true);
    } catch (\Throwable $e) {
        error_log($e);
    }
}

function netdefense_enabled()
{
    return !empty((string)(new \OPNsense\NetDefense\Settings())->enabled);
}

function netdefense_services()
{
    $services = [];

    if (!netdefense_enabled()) {
        return $services;
    }

    $services[] = [
        'description' => gettext('NetDefense Agent'),
        'pidfile' => '/var/run/ndagent.pid',
        'configd' => [
            'restart' => ['netdefense restart'],
            'start' => ['netdefense start'],
            'stop' => ['netdefense stop'],
        ],
        'name' => 'netdefense',
    ];

    return $services;
}