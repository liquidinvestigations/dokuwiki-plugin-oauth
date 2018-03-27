<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\Liquid;

class LiquidAdapter extends AbstractAdapter {

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'mail', 'name' and optional 'grps'
     *
     * @return array
     */
    public function getUser() {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = array();

        /** var OAuth\OAuth2\Service\Generic $this->oAuth */
        $hlp = plugin_load('helper', 'oauth');
        $liquid_core_url = $hlp->getConf('liquid-core-url');
        $result = $JSON->decode($this->oAuth->request($liquid_core_url . '/accounts/profile'));

        $data['user'] = $result['login'];
        $data['mail'] = $result['login'] . '@localhost';

        return $data;
    }

    /**
     * We make use of the "Generic" oAuth 2 Service as defined in
     * phpoauthlib/src/OAuth/OAuth2/Service/Generic.php
     *
     * @return string
     */
    public function getServiceName() {
        return 'Liquid';
    }

    public function getScope() {
        return array('read');
    }

}
