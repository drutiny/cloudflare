<?php

namespace Drutiny\Cloudflare;

use Drutiny\Plugin;

class CloudflareApiPlugin extends Plugin {

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'cloudflare:api';
    }

    public function configure()
    {
        $this->addField(
            'email',
            "The email address you use to login to Cloudflare with:",
            static::FIELD_TYPE_CREDENTIAL
            )
          ->addField(
            'key',
            'The Cloudflare API key. This can be obtained from the Cloudflare UI:',
            static::FIELD_TYPE_CREDENTIAL
          );
    }
}

 ?>
