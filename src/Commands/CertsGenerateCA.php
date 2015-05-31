<?php namespace Igorgoroshit\Certs\Commands;

use Illuminate\Console\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;

class CertsGenerateCA extends Command {

    protected $name = 'certs:generateca';
    protected $description = "Generate root CA cert";


    public function fire()
    {

    }
}