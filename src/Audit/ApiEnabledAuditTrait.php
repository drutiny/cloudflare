<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Cloudflare\Client;
use Drutiny\Credential\Manager;
use Drutiny\Container;
use GuzzleHttp\Exception\RequestException;

trait ApiEnabledAuditTrait {

  public function requireApiCredentials()
  {
      return Manager::load('cloudflare') ? TRUE : FALSE;
  }

  protected function api()
  {
    $creds = Manager::load('cloudflare');
    return new Client($creds['email'], $creds['key']);
  }

  protected function zoneInfo($zone)
  {
    $original_zone = $zone;
    $names = explode('.', $zone);

    while ($zone = implode('.', $names)) {

      try {
        Container::getLogger()->debug("Trying to load zone: $zone");
        $results = $this->api()->request('GET', 'zones', ['query' => [
            'page' => 1,
            'name' => $zone,
            'per_page' => 20
        ]]);
        $number_of_matches = count($results['result']);
      }
      catch (RequestException $e) {
        $number_of_matches = 0;
      }
      // If zone passed is actually a subdomain, then pop a name of the domain
      // and reattempt to find the zone.
      if ($number_of_matches !== 1) {
        array_shift($names);
        continue;
      }
      return $results['result'][0];
    }
    throw new \Exception("There is no zone with that name: {$original_zone}.");
  }
}

 ?>
