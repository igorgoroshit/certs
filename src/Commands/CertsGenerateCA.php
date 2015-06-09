<?php namespace Igorgoroshit\Certs\Commands;

use Illuminate\Console\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;
use App;
use Config;

class CertsGenerateCA extends Command {

    protected $name = 'certs:generateca';
    protected $description = "Generate root CA cert";


    public function fire()
    {
    	$cert = App::make('l4cert');
      $options = Config::get('certs::subject');
    
      if($cert->hasRoot())
      {
        $this->info('Root Certificate Existes!');
        exit(0);
      }

      $this->info('Root Certificate Generation Proccess:');
      $this->info('Press ENTER to preserve current value');
      $data = [];
      foreach($options as $key => $value)
      {
        $newvalue = $this->ask("Please enter $key [".$value."]:");
        if(empty($newvalue))
        {
          $data[$key] = $options[$key];
        }else{
          $data[$key] = $newvalue;
        }
      }

      $root = $cert->create($data, false);
      $cert->save($root, Config::get('certs::rootSerial'));
      $cert->setRoot($root);
      $cert->sign($root, 1825);

      if($root->getValidUntilDate())
        $this->info('Root certificate generated successfully');
    }
}