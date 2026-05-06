{#
 # Copyright (C) 2024 NetDefense
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<style>
    /* Minimal theme-compatible styles - no hardcoded colors */
    .nd-enable-section.disabled {
        opacity: 0.6;
        pointer-events: none;
    }
    .nd-btn-group .btn {
        margin-right: 10px;
    }
    /* Ensure warning buttons have readable text */
    .btn-warning {
        color: #fff !important;
    }
    /* Validation error highlighting */
    .has-error input,
    .has-error select {
        border-color: #a94442 !important;
        box-shadow: inset 0 1px 1px rgba(0,0,0,.075), 0 0 6px #ce8483 !important;
    }
</style>

<script type="text/javascript">
    // State
    var apiConfigured = false;

    // Generate UUID v4 function
    function generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    // Update enable section based on API status
    function updateEnableSection() {
        var enableSection = $('#enableSection');
        var enableCheckbox = $('#settings\\.enabled');
        var enableWarning = $('#enableWarning');

        if (apiConfigured) {
            enableSection.removeClass('disabled');
            enableCheckbox.prop('disabled', false);
            enableWarning.hide();
        } else {
            enableSection.addClass('disabled');
            enableCheckbox.prop('disabled', true).prop('checked', false);
            enableWarning.show();
        }
    }

    // Check API status
    function checkApiStatus() {
        $.ajax({
            url: '/api/netdefense/settings/getApiStatus',
            type: 'GET',
            success: function(data) {
                apiConfigured = data.configured;
                updateApiStatusDisplay(data);
                updateEnableSection();
                updateStatusPanel(data);
            },
            error: function() {
                $('#apiStatusText').html('<i class="fa fa-exclamation-circle"></i> Error checking status').removeClass().addClass('text-danger');
                apiConfigured = false;
                updateEnableSection();
            }
        });
    }

    // Load available shells and current value for Pathfinder dropdown
    function loadPathfinderShells() {
        // Fetch both shells list and current settings
        $.when(
            $.ajax({ url: '/api/netdefense/settings/getShells', type: 'GET' }),
            $.ajax({ url: '/api/netdefense/settings/get', type: 'GET' })
        ).done(function(shellsResponse, settingsResponse) {
            var shells = shellsResponse[0];
            var settings = settingsResponse[0];

            var shellSelect = $('#pathfinderShellSelect');
            var shellHidden = $('#settings\\.pathfinderShell');
            shellSelect.empty();

            // Populate options
            $.each(shells, function(path, label) {
                shellSelect.append($('<option></option>').val(path).text(label));
            });

            // Set current value from settings
            var currentShell = '';
            if (settings && settings.settings && settings.settings.pathfinderShell) {
                currentShell = settings.settings.pathfinderShell;
            }
            if (currentShell) {
                shellSelect.val(currentShell);
                shellHidden.val(currentShell);
            }

            // Sync hidden input when select changes
            shellSelect.on('change', function() {
                shellHidden.val($(this).val());
            });

            shellSelect.selectpicker('refresh');
        }).fail(function(xhr, status, error) {
            console.error('Failed to load shells:', status, error);
        });
    }

    // Check service status
    function checkServiceStatus() {
        $.ajax({
            url: '/api/netdefense/service/status',
            type: 'GET',
            success: function(data) {
                var statusEl = $('#statusService');
                if (data.status === 'running') {
                    statusEl.html('<span class="text-success"><i class="fa fa-check-circle"></i> Running</span>');
                } else {
                    statusEl.html('<span class="text-warning"><i class="fa fa-stop-circle"></i> Stopped</span>');
                }
            },
            error: function() {
                $('#statusService').html('<span class="text-danger"><i class="fa fa-question-circle"></i> Unknown</span>');
            }
        });
    }

    function updateStatusPanel(data) {
        // Update status panel
        var apiStatus = $('#statusApiCreds');
        if (data.configured) {
            apiStatus.html('<i class="fa fa-check-circle"></i> Configured').removeClass().addClass('text-success');
        } else {
            apiStatus.html('<i class="fa fa-times-circle"></i> Not Configured').removeClass().addClass('text-danger');
        }
    }

    function updateApiStatusDisplay(data) {
        var statusText = $('#apiStatusText');
        var setupBtn = $('#setupApiCredsBtn');
        var regenBtn = $('#regenerateApiCredsBtn');
        var badge = $('#apiBadge');

        if (data.configured) {
            statusText.html('<i class="fa fa-check-circle"></i> API credentials are configured and ready.').removeClass().addClass('text-success');
            badge.text('Configured').removeClass('label-warning label-danger').addClass('label-success');
            setupBtn.hide();
            regenBtn.show();
        } else {
            statusText.html('<i class="fa fa-exclamation-triangle"></i> API credentials not configured.').removeClass().addClass('text-warning');
            badge.text('Required').removeClass('label-success label-danger').addClass('label-warning');
            setupBtn.show();
            regenBtn.hide();
        }
    }

    $(document).ready(function() {
        // Load form data (pathfinderShell is handled separately)
        mapDataToFormUI({'frmSettings':"/api/netdefense/settings/get"}).done(function(data) {
            $('.selectpicker').selectpicker('refresh');

            // Auto-generate Device ID UUID if field is empty
            var deviceIdField = $('#settings\\.deviceId');
            if (deviceIdField.length > 0 && (!deviceIdField.val() || deviceIdField.val().trim() === '')) {
                var newUUID = generateUUID();
                deviceIdField.val(newUUID);
            }
        });

        // Load shells dropdown separately (not part of standard form binding)
        loadPathfinderShells();

        // Check API status and service status on page load
        checkApiStatus();
        checkServiceStatus();

        // Initialize standard OPNsense service control buttons (Start/Stop/Restart)
        updateServiceControlUI('netdefense');

        // Setup API Credentials button handler
        $('#setupApiCredsBtn').click(function() {
            var btn = $(this);
            btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Setting up...');

            $.ajax({
                url: '/api/netdefense/settings/setupApiCreds',
                type: 'POST',
                success: function(data) {
                    if (data.result === 'ok') {
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_SUCCESS,
                            title: 'API Credentials Configured',
                            message: 'API credentials have been set up successfully. You can now enable the NetDefense agent.',
                            buttons: [{
                                label: 'OK',
                                cssClass: 'btn-success',
                                action: function(dialog) {
                                    dialog.close();
                                    checkApiStatus();
                                }
                            }]
                        });
                    } else {
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_DANGER,
                            title: 'Setup Failed',
                            message: data.message || 'Failed to set up API credentials.'
                        });
                    }
                    btn.prop('disabled', false).html('<i class="fa fa-key"></i> Setup API Credentials');
                },
                error: function() {
                    BootstrapDialog.show({
                        type: BootstrapDialog.TYPE_DANGER,
                        title: 'Error',
                        message: 'An error occurred while setting up API credentials.'
                    });
                    btn.prop('disabled', false).html('<i class="fa fa-key"></i> Setup API Credentials');
                }
            });
        });

        // Regenerate API Credentials button handler
        $('#regenerateApiCredsBtn').click(function() {
            BootstrapDialog.confirm({
                title: 'Rotate API Credentials',
                message: '<p>This will:</p><ul><li>Delete <strong>all</strong> existing API keys for the netdefense-agent user</li><li>Generate new API credentials</li><li>Restart the NetDefense service</li></ul><p>Continue?</p>',
                type: BootstrapDialog.TYPE_WARNING,
                btnOKLabel: 'Rotate Credentials',
                btnOKClass: 'btn-warning',
                callback: function(result) {
                    if (result) {
                        var btn = $('#regenerateApiCredsBtn');
                        btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Rotating...');

                        $.ajax({
                            url: '/api/netdefense/settings/regenerateApiCreds',
                            type: 'POST',
                            success: function(data) {
                                if (data.result === 'ok') {
                                    BootstrapDialog.show({
                                        type: BootstrapDialog.TYPE_SUCCESS,
                                        title: 'Credentials Rotated',
                                        message: 'API credentials have been rotated successfully. All old keys have been revoked.'
                                    });
                                    checkApiStatus();
                                } else {
                                    BootstrapDialog.show({
                                        type: BootstrapDialog.TYPE_DANGER,
                                        title: 'Rotation Failed',
                                        message: data.message || 'Failed to rotate API credentials.'
                                    });
                                }
                                btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> Rotate Credentials');
                            },
                            error: function() {
                                BootstrapDialog.show({
                                    type: BootstrapDialog.TYPE_DANGER,
                                    title: 'Error',
                                    message: 'An error occurred.'
                                });
                                btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> Rotate Credentials');
                            }
                        });
                    }
                }
            });
        });

        // Reset Device ID button handler
        $('#resetDeviceIdBtn').click(function() {
            var deviceIdField = $('#settings\\.deviceId');
            var newUUID = generateUUID();
            deviceIdField.val(newUUID);

            var btn = $(this);
            btn.html('<i class="fa fa-check"></i> Generated!').removeClass('btn-default').addClass('btn-success');
            setTimeout(function() {
                btn.html('<i class="fa fa-refresh"></i> Reset ID').removeClass('btn-success').addClass('btn-default');
            }, 2000);
        });

        // Apply button handler
        $("#applyBtn").click(function() {
            var btn = $(this);

            // Client-side validation
            var errors = [];
            var uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

            var token = $('#settings\\.token').val().trim();
            var deviceId = $('#settings\\.deviceId').val().trim();

            if (!token) {
                errors.push('Registration Token is required');
                $('#settings\\.token').closest('tr').addClass('has-error');
            } else if (!uuidPattern.test(token)) {
                errors.push('Registration Token must be a valid UUID format');
                $('#settings\\.token').closest('tr').addClass('has-error');
            } else {
                $('#settings\\.token').closest('tr').removeClass('has-error');
            }

            if (!deviceId) {
                errors.push('Device ID is required');
                $('#settings\\.deviceId').closest('td').addClass('has-error');
            } else if (!uuidPattern.test(deviceId)) {
                errors.push('Device ID must be a valid UUID format');
                $('#settings\\.deviceId').closest('td').addClass('has-error');
            } else {
                $('#settings\\.deviceId').closest('td').removeClass('has-error');
            }

            if (errors.length > 0) {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_WARNING,
                    title: 'Validation Error',
                    message: '<ul><li>' + errors.join('</li><li>') + '</li></ul>',
                    buttons: [{
                        label: 'OK',
                        cssClass: 'btn-warning',
                        action: function(dialog) { dialog.close(); }
                    }]
                });
                return;
            }

            btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Applying...');

            saveFormToEndpoint("/api/netdefense/settings/set", 'frmSettings', function() {
                // Settings saved, now reconfigure
                $.ajax({
                    url: '/api/netdefense/service/reconfigure',
                    type: 'POST',
                    success: function(data) {
                        // Refresh status displays after applying
                        setTimeout(function() {
                            checkServiceStatus();
                            updateServiceControlUI('netdefense');
                        }, 1000);
                        btn.prop('disabled', false).html('<i class="fa fa-save"></i> Apply');
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_SUCCESS,
                            title: 'Settings Applied',
                            message: 'NetDefense settings have been saved and applied.',
                            buttons: [{
                                label: 'OK',
                                cssClass: 'btn-success',
                                action: function(dialog) { dialog.close(); }
                            }]
                        });
                    },
                    error: function() {
                        btn.prop('disabled', false).html('<i class="fa fa-save"></i> Apply');
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_DANGER,
                            title: 'Error',
                            message: 'Failed to apply settings.'
                        });
                    }
                });
            }, true, function() {
                btn.prop('disabled', false).html('<i class="fa fa-save"></i> Apply');
            });
        });
    });
</script>

<!-- Status Panel -->
<div class="content-box __mb">
    <table class="table table-striped">
        <thead>
            <tr>
                <th colspan="2"><i class="fa fa-shield"></i> {{ lang._('NetDefense Agent Status') }}</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td style="width: 22%;"><strong>{{ lang._('API Credentials') }}</strong></td>
                <td id="statusApiCreds"><i class="fa fa-spinner fa-spin"></i> {{ lang._('Checking...') }}</td>
            </tr>
            <tr>
                <td><strong>{{ lang._('Service') }}</strong></td>
                <td id="statusService"><i class="fa fa-spinner fa-spin"></i> {{ lang._('Checking...') }}</td>
            </tr>
        </tbody>
    </table>
</div>

<!-- Step 1: API Configuration -->
<div class="content-box __mb">
    <table class="table table-striped">
        <thead>
            <tr>
                <th><i class="fa fa-key"></i> {{ lang._('Step 1: API Configuration') }}</th>
                <th style="text-align: right;"><span id="apiBadge" class="label label-warning">{{ lang._('Required') }}</span></th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td colspan="2">
                    <p id="apiStatusText">
                        <i class="fa fa-spinner fa-spin"></i> {{ lang._('Checking API status...') }}
                    </p>
                    <div class="nd-btn-group">
                        <button type="button" class="btn btn-primary" id="setupApiCredsBtn" style="display:none;">
                            <i class="fa fa-key"></i> {{ lang._('Setup API Credentials') }}
                        </button>
                        <button type="button" class="btn btn-warning" id="regenerateApiCredsBtn" style="display:none;">
                            <i class="fa fa-refresh"></i> {{ lang._('Rotate Credentials') }}
                        </button>
                    </div>
                    <div class="alert alert-info" style="margin-top: 15px; margin-bottom: 0;">
                        <i class="fa fa-info-circle"></i>
                        {{ lang._('API credentials allow the NetDefense agent to manage the system. A user "netdefense-agent" with the required privileges is automatically created.') }}
                    </div>
                </td>
            </tr>
        </tbody>
    </table>
</div>

<!-- Step 2: Service Settings -->
<div class="content-box">
    <form id="frmSettings">
        <table class="table table-striped">
            <thead>
                <tr>
                    <th colspan="2"><i class="fa fa-cog"></i> {{ lang._('Step 2: Service Configuration') }}</th>
                </tr>
            </thead>
            <tbody>
                <!-- Enable Section -->
                <tr>
                    <td style="width: 22%;"><strong>{{ lang._('Enable Agent') }}</strong></td>
                    <td>
                        <div id="enableSection" class="nd-enable-section disabled">
                            <label class="checkbox-inline">
                                <input type="checkbox" id="settings.enabled"> {{ lang._('Enable NetDefense Agent') }}
                            </label>
                            <div class="help-block">{{ lang._('Activates the NetDefense Agent service to connect to the central server.') }}</div>
                            <div id="enableWarning" class="alert alert-warning" style="display:none; margin-top: 10px; margin-bottom: 0;">
                                <i class="fa fa-exclamation-triangle"></i>
                                {{ lang._('You must configure API credentials before enabling the service.') }}
                            </div>
                        </div>
                    </td>
                </tr>
                <tr>
                    <td><strong>{{ lang._('Registration Token') }}</strong></td>
                    <td>
                        <input type="text" class="form-control" id="settings.token" name="settings.token" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
                        <div class="help-block">{{ lang._('Organization token for NetDefense registration.') }}</div>
                    </td>
                </tr>
                <tr>
                    <td><strong>{{ lang._('Device ID') }}</strong></td>
                    <td>
                        <table class="table table-condensed" style="margin-bottom: 0; background: transparent;">
                            <tr style="border: none;">
                                <td style="padding: 0; border: none;">
                                    <input type="text" class="form-control" id="settings.deviceId" name="settings.deviceId">
                                </td>
                                <td style="padding: 0 0 0 10px; width: 1%; border: none;">
                                    <button type="button" class="btn btn-default" id="resetDeviceIdBtn">
                                        <i class="fa fa-refresh"></i> {{ lang._('Reset ID') }}
                                    </button>
                                </td>
                            </tr>
                        </table>
                        <div class="help-block">{{ lang._('Unique identifier for this device (auto-generated if empty).') }}</div>
                    </td>
                </tr>
            </tbody>
        </table>

        <!-- Advanced Settings (Collapsible) -->
        <table class="table table-striped">
            <thead>
                <tr style="cursor: pointer;" data-toggle="collapse" data-target="#advancedSettings">
                    <th>
                        <i class="fa fa-sliders"></i> {{ lang._('Advanced Settings') }}
                        <i class="fa fa-chevron-down pull-right" id="advancedToggle"></i>
                    </th>
                </tr>
            </thead>
        </table>
        <div id="advancedSettings" class="collapse">
            <table class="table table-striped">
                <tbody>
                    <tr>
                        <td style="width: 22%;"><strong>{{ lang._('Server Address') }}</strong></td>
                        <td>
                            <input type="text" class="form-control" id="settings.serverAddress" name="settings.serverAddress" placeholder="https://hub.netdefense.io">
                            <div class="help-block">{{ lang._('NetDefense server URL (e.g., https://hub.netdefense.io or https://example.com:8443).') }}</div>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('SSL Verification') }}</strong></td>
                        <td>
                            <label class="checkbox-inline">
                                <input type="checkbox" id="settings.sslVerify" name="settings.sslVerify" checked> {{ lang._('Enable SSL certificate verification') }}
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('Pathfinder Address') }}</strong></td>
                        <td>
                            <input type="text" class="form-control" id="settings.pathfinderHost" name="settings.pathfinderHost" placeholder="https://pathfinder.netdefense.io">
                            <div class="help-block">{{ lang._('Pathfinder server URL for remote shell connections.') }}</div>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('Pathfinder SSL Verification') }}</strong></td>
                        <td>
                            <label class="checkbox-inline">
                                <input type="checkbox" id="settings.pathfinderTlsVerify" name="settings.pathfinderTlsVerify" checked> {{ lang._('Enable SSL certificate verification for Pathfinder') }}
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('Pathfinder Shell') }}</strong></td>
                        <td>
                            <select class="form-control selectpicker" id="pathfinderShellSelect">
                                <!-- Options populated dynamically via JavaScript -->
                            </select>
                            <input type="hidden" id="settings.pathfinderShell" name="settings.pathfinderShell" value="">
                            <div class="help-block">{{ lang._('Shell to use for Pathfinder remote sessions.') }}</div>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('Log Level') }}</strong></td>
                        <td>
                            <select class="form-control selectpicker" id="settings.logLevel" name="settings.logLevel">
                                <option value="DEBUG">DEBUG</option>
                                <option value="INFO" selected>INFO</option>
                                <option value="WARNING">WARNING</option>
                                <option value="ERROR">ERROR</option>
                            </select>
                            <div class="help-block">{{ lang._('Logging verbosity for the NetDefense Agent.') }}</div>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>{{ lang._('Re-bind Token') }}</strong></td>
                        <td>
                            <input type="text" class="form-control" id="settings.bootstrapToken" name="settings.bootstrapToken" placeholder="" autocomplete="off">
                            <div class="help-block">
                                {{ lang._('One-time token from your NetDefense administrator (issued via "ndcli device rebind-token <name>"). Paste here to re-bind the device signing key after a suspected leak, hardware replacement, or routine rotation. The agent rotates its keypair automatically when this field is set. Clear this field once the device shows ENABLED again.') }}
                            </div>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Actions -->
        <table class="table">
            <tbody>
                <tr>
                    <td>
                        <button type="button" class="btn btn-primary" id="applyBtn">
                            <i class="fa fa-save"></i> {{ lang._('Apply') }}
                        </button>
                    </td>
                </tr>
            </tbody>
        </table>
    </form>
</div>

<script>
    // Toggle chevron for advanced settings
    $('#advancedSettings').on('show.bs.collapse', function () {
        $('#advancedToggle').removeClass('fa-chevron-down').addClass('fa-chevron-up');
    }).on('hide.bs.collapse', function () {
        $('#advancedToggle').removeClass('fa-chevron-up').addClass('fa-chevron-down');
    });
</script>
