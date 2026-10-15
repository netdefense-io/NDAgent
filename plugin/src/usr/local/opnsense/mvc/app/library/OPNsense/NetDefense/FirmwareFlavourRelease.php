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

/**
 * The decision behind release_firmware_flavour.php: whether the firmware flavour
 * on the device is a pin the agent wrote, and what to put back.
 *
 * The agent pins a device by setting OPNsense's firmware flavour to
 * `<series>/MINT/<dir>/latest` and keeps a record of what it wrote
 * (/var/db/ndagent/firmware-track.json). When the agent cannot take the pin off
 * itself (the package is being removed, the device is being decommissioned and
 * its API user is gone), this compares the setting with that record and puts the
 * original value back, only when the setting is still what the agent wrote: a
 * flavour somebody set by hand is not the agent's to change.
 *
 * Pure: no Config, no Phalcon, no file but the one it is given. The record's
 * field names are the Go side's (internal/firmware/track/state.go); the golden
 * file in plugin/tests/fixtures/firmware is the shape both sides test against.
 */
final class FirmwareFlavourRelease
{
    public const RESULT_RELEASED = 'released';
    public const RESULT_NOT_OURS = 'not_ours';
    public const RESULT_ALREADY_RESTORED = 'already_restored';
    public const RESULT_NOTHING_PINNED = 'nothing_pinned';
    public const RESULT_NO_STATE = 'no_state';

    public const STATE_FORMAT = 1;

    /**
     * Read the agent's record. Null when there is none: the agent never pinned
     * this device, or its state was removed.
     *
     * @throws \RuntimeException when the file exists and cannot be understood: a
     *     device that may hold a pin is not touched on a guess.
     */
    public static function readState(string $path): ?array
    {
        if (!is_file($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            throw new \RuntimeException("cannot read {$path}");
        }
        $state = json_decode($raw, true);
        if (!is_array($state)) {
            throw new \RuntimeException("{$path} is not a JSON object");
        }
        if (($state['v'] ?? null) !== self::STATE_FORMAT) {
            throw new \RuntimeException("{$path} has format " . var_export($state['v'] ?? null, true) . ', not ' . self::STATE_FORMAT);
        }
        return $state;
    }

    /**
     * What to do about the setting $current, given the agent's record.
     *
     * @return array{result:string,restore_to:?string}
     */
    public static function decide(?array $state, string $current): array
    {
        if ($state === null) {
            return ['result' => self::RESULT_NO_STATE, 'restore_to' => null];
        }

        $owned = [];
        if (($state['pinned'] ?? false) === true && self::text($state, 'pinned_flavour') !== '') {
            $owned[] = self::text($state, 'pinned_flavour');
        }
        $pending = $state['pending'] ?? null;
        if (is_array($pending) && self::text($pending, 'to_flavour') !== '') {
            $owned[] = self::text($pending, 'to_flavour');
        }
        if ($owned === []) {
            return ['result' => self::RESULT_NOTHING_PINNED, 'restore_to' => null];
        }

        $original = self::text($state, 'original_flavour');
        if ($current === $original) {
            return ['result' => self::RESULT_ALREADY_RESTORED, 'restore_to' => null];
        }
        if (in_array($current, $owned, true)) {
            return ['result' => self::RESULT_RELEASED, 'restore_to' => $original];
        }
        return ['result' => self::RESULT_NOT_OURS, 'restore_to' => null];
    }

    private static function text(array $from, string $key): string
    {
        $value = $from[$key] ?? '';
        return is_string($value) ? $value : '';
    }
}
