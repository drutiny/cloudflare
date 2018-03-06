<?php

namespace Drutiny\Cloudflare\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;
use Drutiny\Cloudflare\Audit\ApiEnabledAudit;

class SetupCommand extends Command {

  /**
   * @inheritdoc
   */
  protected function configure() {
    $this
      ->setName('setup:cloudflare')
      ->setDescription('Add API credentials for Drutiny to talk to Cloudflare.');
  }

  /**
   * @inheritdoc
   */
  protected function execute(InputInterface $input, OutputInterface $output) {
    $io = new SymfonyStyle($input, $output);
    $helper = $this->getHelper('question');

    $data = [];

    // Title.
    $question = new Question('email: ');
    $data['email'] = $helper->ask($input, $output, $question);

    // Name.
    $question = new Question('key: ');
    $data['key'] = $helper->ask($input, $output, $question);

    $filepath = ApiEnabledAudit::credentialFilepath();
    $dir = dirname($filepath);

    if (!file_exists($dir) && !mkdir($dir, 0744, TRUE)) {
      $io->error("Could not create $dir");
      return FALSE;
    }

    file_put_contents($filepath, json_encode($data));
    $io->success("Credentials written to $filepath.");
  }
}
 ?>
