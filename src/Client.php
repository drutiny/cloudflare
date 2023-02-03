<?php

namespace Drutiny\Cloudflare;

use GuzzleHttp\Exception\RequestException;
use Symfony\Component\Console\Output\OutputInterface;
use Drutiny\Http\Client as HttpClient;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\TransferStats;
use Symfony\Component\DependencyInjection\ContainerInterface;


class Client {

  /**
   * API base URL for Cloudflare.
   */
  const API_BASE = 'https://api.cloudflare.com/client/v4/';

  /**
   * Email used for API authentication.
   */
  protected $email;

  /**
   * API key used for authentication.
   */
  protected $key;

  protected ClientInterface $client;

  /**
   * API constructor.
   */
  public function __construct(CloudflareApiPlugin $plugin, HTTPClient $http, ContainerInterface $container) {
    $config = $plugin->load();
    $this->client = $http->create([
      'base_uri' => self::API_BASE,
      'headers' => [
        'X-Auth-Email' => $config['email'],
        'X-Auth-Key' => $config['key'],
        'User-Agent' => 'drutiny-cloudflare/4.x',
        'Accept' => 'application/json',
        'Accept-Encoding' => 'gzip'
      ],
      'decode_content' => 'gzip',
      'allow_redirects' => FALSE,
      'connect_timeout' => 10,
      'timeout' => 300,
    ]);
  }

  /**
   * Perform an API request to Cloudflare.
   *
   * @param string $method
   *   The HTTP method to use.
   * @param string $endpoint
   *   The API endpoint to hit. The endpoint is prefixed with the API_BASE.
   * @param array $payload
   *
   * @param bool $decodeBody
   *   Whether the body should be JSON decoded.
   * @return array|string
   *   Decoded JSON body of the API request, if the request was successful.
   *
   * @throws \Exception
   */
  public function request($method, $endpoint, array $options = [], $decodeBody = TRUE) {

    $response = $this->client->request($method, $endpoint, $options);

    if (!in_array($response->getStatusCode(), [200, 204])) {
      throw new \Exception('Error: ' . (string) $response->getBody());
    }

    if ($decodeBody) {
      return json_decode($response->getBody(), TRUE);
    }
    return (string) $response->getBody();
  }

}
