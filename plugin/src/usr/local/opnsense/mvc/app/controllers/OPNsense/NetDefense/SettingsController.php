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

namespace OPNsense\NetDefense;

use OPNsense\Base\IndexController;

/**
 * Class SettingsController
 * @package OPNsense\NetDefense
 */
class SettingsController extends IndexController
{
    /**
     * Settings page
     */
    public function indexAction()
    {
        $this->view->pick('OPNsense/NetDefense/settings');
        $this->view->settingsForm = $this->getForm('settings');
    }
}