<?php

namespace Igorgoroshit\Certs\Providers;

use Illuminate\Support\ServiceProvider;
use Igorgoroshit\Certs\SSLCert;
use Igorgoroshit\Certs\Commands;
use Igorgoroshit\Certs\Storage\StorageDB;
use Config;

class L4CertsServiceProvider extends ServiceProvider
{

    protected $defer = false;

    public function boot()
    {
        $this->package('igorgoroshit/certs');
    }

    public function register()
    {
        $this->app->bind('l4cert', function () {

            $storage = new StorageDB(
                Config::get('certs::serialKey'),
                Config::get('certs::table')
            );

            $certs = new SSLCert($storage);

            $certs->setAlgo(Config::get('certs::algo'));
            $certs->setBits(Config::get('certs::bits'));
            $certs->setType(Config::get('certs::type'));

            if (!empty($_ENV['OPEN_SSL_CONF'])) {
                $certs->setConfig('config', getenv('OPEN_SSL_CONF'));
            }

            $root = $certs->find(Config::get('certs::rootSerial'));

            //set root certificate if exists
            if ($root) {
                $certs->setRoot($root);
            }

            return $certs;
        });


        $this->app['certs.generateCA'] = $this->app->share(function ($app) {
            return new Commands\CertsGenerateCA();
        });

        $this->commands('certs.generateCA');
    }

    public function provides()
    {
        return ['l4cert'];
    }
}
