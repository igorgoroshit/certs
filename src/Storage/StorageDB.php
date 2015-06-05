<?php namespace Igorgoroshit\Certs\Storage;

use Igorgoroshit\Certs\Interfaces\StorageInterface;
use Igorgoroshit\Certs\Interfaces\CertificateInterface;
use Exception;

class StorageDB implements StorageInterface {

	protected $serialKey;
	protected $table;


	public function __construct($serialKey, $table)
	{
		$this->serialKey = $serialKey;
		$this->table = $table;
	}
	//find certificate by serial number
	//return CertificateInterface
	public function find($serial)
	{
		$row = DB::table($this->table)->where($this->serialKey, $serial)->first();
	
		if(!$row)
		{
			throw new Exception("Certificate with serial number $serial not found!", 1);
		}

		$cert = new Certificate();
		$cert->setPrivateKey($row['privateKey']);
		$cert->setCsr($row['csr']);
		$cert->setCertificate($row['certificate']);
	}

	//store certificate 
	//return true on success of false on failer
	public function save(CertificateInterface $cert)
	{
		$priKey 			= $cert->getPrivateKey();
		$csr    			= $cert->getCsr();
		$certificate 	= $cert->getCertificate();

		if($cert->isNew())
		{
			$id = DB::table($this->table)->insertGetId([
				'private' 		=> $priKey,
				'csr'					=> $csr,
				'certificate' => $certificate
				//'validUntil'  => $validUntil;
			]);			

			$cert->setNew(false);

			return $cert;
		}

		DB::table($this->table)->update([
			'private' 		=> $priKey,
			'csr'					=> $csr,
			'certificate' => $certificate
			//'validUntil'  => $validUntil;
		])->where($this->serialKey, $cert->getSerial());	

		return $cert;
	}

}