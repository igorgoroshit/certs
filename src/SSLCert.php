<?php namespace Igorgoroshit\Certs;

use Igorgoroshit\Certs\Interfaces\StorageInterface;
use Igorgoroshit\Certs\Interfaces\CertificateInterface;
use Igorgoroshit\Certs\Certificate;
use Exception;

class SSLCert{

	protected $storage;
	protected $algo;
	protected $bits;
	protected $type;
	protected $root;
	protected $validity = 365;
	protected $password = '';

	public function __construct(StorageInterface $storage)
	{
		$this->storage = $storage;
	}

	public function setRoot(CertificateInterface $cert)
	{
		$this->root = $cert;
	}

	public function hasRoot()
	{
		return $this->root !== NULL;
	}

	public function setAlgo($algo)
	{
		$this->algo = $algo;
	}

	public function setBits($bits)
	{
		$this->bits = (int)$bits;
	}

	public function setType($type)
	{
		$this->type = $type;
	}

	public function setValidity($validity)
	{
		$this->validity = (int)$validity;
	}

	public function setPassword($password)
	{
		$this->password = $password;
	}

	public function find($serial)
	{
		try {
			$cert = new Certificate();
			$this->storage->find($cert, $serial);
			return $cert;
		} catch (Exception $e) {
			return NULL;
		}	
	}

	public function save(CertificateInterface $cert, $serial = NULL)
	{
		return $this->storage->save($cert, $serial);
	}

	public function create($data, $save = true)
	{

		//create private/public key pair
		$key = openssl_pkey_new([
			'digest_alg' 				=> $this->algo,
			'private_key_bits' 	=> $this->bits,
			'private_key_type' 	=> $this->type
		]);

		//export private key
		$priKeyOut = NULL;
		openssl_pkey_export($key, $priKeyOut);

		//create and export new csr
		$csr = openssl_csr_new($data, $priKey);
		$csrOut = NULL;
		openssl_csr_export($csr, $csrOut);


		$cert = new Certificate();
		$cert->setPrivateKey($priKeyOut);
		$cert->setCsr($csrOut);

		if($save)
			$this->save($cert);

		return $cert;
	}

	public function sign(CertificateInterface $cert, $validity = NULL, $save = true)
	{
		$csr 	= $cert->getCsr();

		$days = $validity ? (int)$validity : $this->validity;

		$signed = openssl_csr_sign(
			$csr,
			$this->root->getCertificate(),
			$this->root->getPrivateKey(),
			$days
		);

		$cert->setCertificate($this->export($signed));
		
		if($save)
			$this->save($cert);

		return $cert;
	}


	public function validate($cert, $key, $password = "")
	{
		return openssl_x509_check_private_key(
			$cert,
			array(
				$key,
				$password,
			)
		);
	}

	public function export($cert, $type = 'X509', $format = 'der')
	{
		$format = strtolower($format);
		$output = FALSE;

		switch(strtoupper($type)){
			case 'X509':
				openssl_x509_export($cert, $output);
				break;
			case 'CSR':
				$format = 'csr';
			case 'PKCS10':
				$format = 'p10';
				openssl_csr_export($cert, $output);
				break;
			case 'PKCS12':
				$format = 'p12';
				openssl_pkcs12_export($cert, $output);
				break;
		}
		
		if(strtolower($format) === 'pem')
		{
			$output = $this->_der2pem($output);
		}

		return $output;
	}

	private function _pem2der($pem_data) {
		$begin = "CERTIFICATE-----";
		$end   = "-----END";
		$pem_data = substr($pem_data, strpos($pem_data, $begin)+strlen($begin));    
		$pem_data = substr($pem_data, 0, strpos($pem_data, $end));
		$der = base64_decode($pem_data);
		return $der;
	}


	private function _der2pem($der_data) {
		$pem = chunk_split(base64_encode($der_data), 64, "\n");
		$pem = "-----BEGIN CERTIFICATE-----\n".$pem."-----END CERTIFICATE-----\n";
		return $pem;
	}

}