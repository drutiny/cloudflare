<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Cloudflare\Client;
use GuzzleHttp\Exception\RequestException;

trait ApiEnabledAuditTrait {

  protected Client $client;

  public function setClient(Client $client) {
    $this->client = $client;
  }

  /**
   * @deprecated use client property.
   */
  protected function api():Client
  {
    return $this->client;
  }

  protected function zoneInfo($zone, Client $client = null)
  {
    $original_zone = $zone;
    $names = explode('.', $zone);

    while ($zone = implode('.', $names)) {

      try {
        $this->logger->debug("Trying to load zone: $zone");
        $results = ($client ??= $this->client)->request('GET', 'zones', ['query' => [
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
