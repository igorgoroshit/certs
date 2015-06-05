<?php namespace Igorgoroshit\Certs\Interfaces;


interface StorageInterface {

	//find certificate by serial number
	//return CertificateInterface
	public function find($serial);

	//store certificate 
	//return true on success of false on failer
	public function save(CertificateInterface $cert);

}