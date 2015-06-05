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

      //$cert = Certificate::find('rootca');

    	$cert = App::make('l4cert');
      $options = Config::get('certs::subject');
      
      $new = $cert->create($options);
      print_r($new); die();

      $data = [];
    	if(!$cert->ca_exists())
    	{

        //putenv('RANDFILE=~/.rand');
            $this->info('CA Cert Generation:');

            foreach ($options as $key => $value) {
              $newvalue = $this->ask("Enter $key"." [$value]:");

              if(!empty($newvalue))
              {
                $data[$key] = $newvalue;
              }else{
                $data[$key] = $value;
              }

            }

            $keySettings  = Config::get('certs::keySettings');
            $certSettings = Config::get('certs::certSettings');
           
            list($caPKey, $caCSR, $caroot) = $cert->genRootCa($data, $keySettings, $certSettings);
            print_r($cert->export($caroot));

            $this->info('CA Cert Generation:');

            foreach ($options as $key => $value) {
              $newvalue = $this->ask("Enter $key"." [$value]:");

              if(!empty($newvalue))
              {
                $data[$key] = $newvalue;
              }else{
                $data[$key] = $value;
              }

            }

            $keySettings  = Config::get('certs::keySettings');
            $certSettings = Config::get('certs::certSettings');

            $certificate = $cert->certificate($data, $keySettings, $certSettings, $caPKey, $caroot);
            print_r($cert->export($certificate));
    	}else{
    		print "CA Cert exists!\n";
    	}
    }
}