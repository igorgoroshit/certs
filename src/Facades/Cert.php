<?php namespace Igorgoroshit\Certs\Facades;

use Illuminate\Support\Facades\Facade;

class Cert extends Facade {

	  protected static function getFacadeAccessor()
    {
        return 'l4cert';
    }

}