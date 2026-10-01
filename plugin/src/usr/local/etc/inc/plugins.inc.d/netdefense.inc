<?php

/*
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