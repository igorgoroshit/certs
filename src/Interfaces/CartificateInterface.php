<?php namespace Igorgoroshit\Certs\Interfaces;


interface CertificateInterface {

	//setters
	public function setPrivateKey($key);
	public function setCsr($csr);
	public function setCertificate($cert);
	public function setValidity($days);
	public function setPassword($password = '');
	public function setSerial($serial);

	//getters

	public function getPrivateKey();
	public function getPublicKey();
	public function getCsr();
	public function getCertificate();
	public function getValidity();
	public function getPassword();
	public function getSerial();
	public function isNew();

}