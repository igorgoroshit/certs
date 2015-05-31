<?php namespace Igorgoroshit\Certs\Providers;

use Illuminate\Support\ServiceProvider;
use Igorgoroshit\Certs\SSLCert;
use Igorgoroshit\Certs\Commands;

class L4CertsServiceProvider extends ServiceProvider {

	protected $defer = false;

	public function boot()
	{
		$this->package('igorgoroshit/certs');
	}

	public function register()
	{
		$this->app->bind('l4cert', function()
		{
			$certs = new SSLCert($this->app['config']['certs::storagePath']);

			//print_r($certs);die();

			return $certs;
		});

		$this->app['certs.generateCA'] = $this->app->share(function($app)
		{
			return new Commands\CertsGenerateCA;
		});

		$this->commands('certs.generateCA');
	}

	public function provides()
	{
		return ['l4cert'];
	}

}