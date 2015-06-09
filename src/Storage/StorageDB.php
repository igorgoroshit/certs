<?php namespace Igorgoroshit\Certs\Storage;

use Igorgoroshit\Certs\Interfaces\StorageInterface;
use Igorgoroshit\Certs\Interfaces\CertificateInterface;
use Exception;
use DB;

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
	public function find(CertificateInterface $cert, $serial)
	{
		$row = DB::table($this->table)->where($this->serialKey, $serial)->first();
	
		if(!$row)
		{
			throw new Exception("Certificate with serial number $serial not found!", 1);
		}

		$cert->setPrivateKey($row->private);
		$cert->setCsr($row->csr);
		$cert->setCertificate($row->certificate);
	}

	//store certificate 
	//return true on success of false on failer
	public function save(CertificateInterface $cert, $serial = null)
	{
		$priKey 						= $cert->getPrivateKey();
		$csr    						= $cert->getCsr();
		$certificate 				= $cert->getCertificate();
		$validUntilDate			= $cert->getValidUntilDate();

		if($cert->isNew())
		{	
			$columns = [
				'private' 					=> $priKey,
				'csr'								=> $csr,
				'certificate' 			=> $certificate,
				'validUntilDate'  	=> $validUntilDate
			];

			if($serial)
				$columns[$this->serialKey] = $serial;

			$id = DB::table($this->table)->insertGetId($columns);			

			$cert->setSerial($id);
			$cert->setNew(false);

			return $cert;
		}

		DB::table($this->table)
			->where($this->serialKey, $cert->getSerial())
			->update([
				'csr'								=> $csr,
				'certificate' 			=> $certificate,
				'validUntilDate'  	=> $validUntilDate
			]);	

		return $cert;
	}

}