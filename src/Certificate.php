<?php namespace Igorgoroshit\Certs;

use Igorgoroshit\Certs\Interfaces\CertificateInterface;
use Exception;

class Certificate implements CertificateInterface {

	protected $priKey 					= NULL;
	protected $pubKey 					= NULL;
	protected $csr							= NULL;
	protected $certificate 			= NULL;
	protected $data 						= NULL;
	protected $serial 					= NULL;
	protected $new							= true;
	protected $validUntilDate   = NULL;

	protected $keys					= [
			"countryName" 							=> true,
			"stateOrProvinceName" 			=> true,
			"localityName" 							=> true,
			"organizationName" 					=> true,
			"organizationalUnitName" 		=> true,
			"commonName" 								=> true,
			"emailAddress" 							=> true
	];

	protected $validity 		= NULL;
	protected $password   	= NULL;


	//setters
	public function setPrivateKey($key)
	{
		$this->priKey = $key;
	}

	public function setCsr($csr)
	{
		$this->csr = $csr;
	}

	public function setCertificate($cert)
	{
		$this->certificate = $cert;
		$this->data = $this->parse($cert);

		if(isset($this->data['validTo_time_t']))
		{
			$this->validUntilDate = gmdate('Y-m-d H:i:s', $this->data['validTo_time_t']);
		}
	}

	public function setPassword($password = '')
	{
		$this->password = $password;
	}

	public function setSerial($serial)
	{
		$this->serial = $serial;
	}
	//getters

	public function getPrivateKey()
	{
		return $this->priKey;
	}

	public function getPublicKey()
	{
		return $this->pubKey;
	}

	public function getCsr()
	{
		return $this->csr;
	}

	public function getCertificate()
	{
		return $this->certificate;
	}

	public function getValidUntilDate()
	{
		return $this->validUntilDate;
	}

	public function getPassword()
	{
		return $this->password;
	}

	public function setNew($val)
	{
		$this->new = $val;
	}

	public function isNew()
	{
		return $this->new;
	}

	public function getSerial()
	{
		return $this->serial;
	}

	private function parse($data)
	{
		return openssl_x509_parse ($data, false);
	}

	public function __get($key)
	{
		if(!isset($this->keys[$key]))
		{
			throw new Exception("Unknown key $key", 1);
		}

		return $this->data[$key];
	}

	public function __set($key, $value)
	{
		if(!isset($this->keys[$key]))
		{
			throw new Exception("Unknown key $key", 1);
		}

		$this->data[$key] = $value;
	}

}
