<?php

namespace Drutiny\Cloudflare;

use Psr\Cache\CacheItemInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\EventDispatcher\GenericEvent;
use Symfony\Contracts\Cache\CacheInterface;

class EventsSubscriber implements EventSubscriberInterface {

    public function __construct(protected Client $client, protected CacheInterface $cache, protected LoggerInterface $logger)
    {
        
    }

    public static function getSubscribedEvents() {
        return [
            'target.load' => 'loadTargetListener'
        ];
    }

    /**
     * Load Acquia Cloud API information from a drush alias.
     */
    public function loadTargetListener(GenericEvent $event) {
        if (!$this->client->isInstalled()) {
            $this->logger->warning("Cloudflare plugin is not installed. Please run 'plugin:setup cloudflare:api' to Cloudflare zone information on target.");
            return;
        }
        /* @var Drutiny\Target\TargetInterface $target */
        $target = $event->getArgument('target');

        $domain = explode('.', $target['domain']);

        do {
            $zone = implode('.', $domain);
            if (empty($zone)) {
                break;
            }
            $this->logger->notice("Fetching Cloudflare zone information for $zone.");
            // Attempt to find a matching Cloudflare zone.

            $response = $this->cache->get('cloudflare.zone.'.$zone, function (CacheItemInterface $cache) use ($zone) {
                $cache->expiresAfter(3600);
                return $this->client->request('GET', 'zones', [
                    'name' => $zone
                ]);
            });

            if (!empty($response['result'])) {
                foreach ($response['result'][0] as $key => $value) {
                    $target['cloudflare.zone.'.$key] = $value;
                }
                break;
            }

            // Perhaps this domain is a sub-domain of another zone.
            array_pop($domain);
        }
        while (count($domain) > 2);

        $target['cloudflare.hasZone'] = $target->hasProperty('cloudflare.zone');
    }
}