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

/**
 * A write of config.xml by the plugin: take OPNsense's config lock, save with
 * a revision description that says what changed, unlock.
 *
 * Config::save() truncates config.xml and writes it again in place, so a
 * process killed during it leaves the file cut short. In a CLI run with pcntl,
 * begin() therefore waits a bounded time for the lock (a lock held elsewhere
 * throws instead of hanging a pkg hook or the agent) and ignores SIGTERM,
 * SIGINT, SIGHUP and SIGQUIT until end(): the last two reach a pkg hook run
 * from a terminal, when the session drops or someone presses Ctrl-\. Whoever
 * starts a script that uses it stops it with SIGTERM only, never SIGKILL. In
 * the web GUI, or without pcntl, begin() is Config::lock() as it is.
 *
 * begin(), then commit($description) to save, or end() to leave config.xml as
 * it is. end() is also what an error path calls: it does nothing when no
 * transaction is open.
 */
final class ConfigTransaction
{
    public const LOCK_WAIT_SECONDS = 30;

    private static $open = false;

    /** The signals ignored while the lock is held. */
    private const IGNORED_SIGNALS = ['SIGTERM', 'SIGINT', 'SIGHUP', 'SIGQUIT'];

    /** The handlers begin() replaced, for end() to put back. */
    private static $savedHandlers = null;

    public static function begin(int $waitSeconds = self::LOCK_WAIT_SECONDS): void
    {
        if (self::$open) {
            throw new \LogicException('a config transaction is already open');
        }
        $signals = self::signalsAvailable();
        if ($signals) {
            $async = pcntl_async_signals(true);
            $alarmHandler = pcntl_signal_get_handler(SIGALRM);
            // Not restarted, so the alarm interrupts the flock() wait inside lock().
            pcntl_signal(SIGALRM, function () use ($waitSeconds) {
                throw new \RuntimeException(sprintf('the config lock was not available within %d seconds', $waitSeconds));
            }, false);
            pcntl_alarm($waitSeconds);
        }
        try {
            Config::getInstance()->lock();
            if ($signals) {
                pcntl_alarm(0);
            }
        } catch (\Throwable $e) {
            if ($signals) {
                pcntl_alarm(0);
            }
            // The alarm can go off after flock() returned, while lock() reloads.
            Config::getInstance()->unlock();
            throw $e;
        } finally {
            if ($signals) {
                pcntl_signal(SIGALRM, $alarmHandler);
                pcntl_async_signals($async);
            }
        }
        self::$open = true;
        if ($signals) {
            self::$savedHandlers = [];
            foreach (self::IGNORED_SIGNALS as $name) {
                $signal = constant($name);
                self::$savedHandlers[$signal] = pcntl_signal_get_handler($signal);
                pcntl_signal($signal, SIG_IGN);
            }
        }
    }

    /**
     * Save, with $description as the revision description in place of
     * OPNsense's "<script> made changes", then end(). The revision keeps
     * OPNsense's own user and time.
     */
    public static function commit(string $description): void
    {
        if (!self::$open) {
            throw new \LogicException('no config transaction is open');
        }
        try {
            Config::getInstance()->save(['description' => $description]);
        } finally {
            self::end();
        }
    }

    public static function end(): void
    {
        if (self::$open) {
            self::$open = false;
            Config::getInstance()->unlock();
        }
        if (self::$savedHandlers !== null) {
            foreach (self::$savedHandlers as $signal => $handler) {
                pcntl_signal($signal, $handler);
            }
            self::$savedHandlers = null;
        }
    }

    private static function signalsAvailable(): bool
    {
        return PHP_SAPI === 'cli'
            && function_exists('pcntl_signal')
            && function_exists('pcntl_signal_get_handler')
            && function_exists('pcntl_alarm')
            && function_exists('pcntl_async_signals')
            && defined('SIGALRM');
    }
}
