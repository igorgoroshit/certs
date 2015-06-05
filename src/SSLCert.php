<?php namespace Igorgoroshit\Certs;

use Exception;

class SSLCert{

	public function __construct(){
	//	$this->storagePath = $path;
	//	$this->load_ca();
	}

	/*
		csrData:
			"countryName"            => "XX",              // 2-digit country code
			"stateOrProvinceName"    => "Province",        // Province
			"localityName"           => "Locality",        // Locality
			"organizationName"       => "EnterpriseName",  // Organization Name
			"organizationalUnitName" => "DepartmentName",  // Organization Department Name
			"commonName"             => "localhost",       // FQDN for certificate requests
			"emailAddress"           => "email@domain.com" // Email address for certificate
	*/

	/*
		certSettings:
			"password" 							 => "string",   				// Password for private key sign
			"validity" 							 => 365,                // Cert validity time
	*/

	/*
		keySettings
			"digest_alg" 						 => "sha512",            // Cert Digest Algorythm
			"private_key_bits" 			 => 4096,                // Private Key Size
			"private_key_type" 			 => OPENSSL_KEYTYPE_RSA, // Private Key Tipe
	*/


	public function genRootCa($data, $keySettings, $certSettings)
	{
      //Generate Private Key
      $privateKey = $this->privateKey($keySettings['algorithm'], $keySettings['bits'], $keySettings['type']);
           
	    //Generate CSR
	    $csr = $this->csr($data, $privateKey);

	    //Sign CSR
	    $certificate = $this->sign($csr, $certSettings, $privateKey);

	    return [$privateKey, $csr, $certificate];
	}

	public function certificate($data, $keySettings, $certSettings, $rootpk, $rootca)
	{
      //Generate Private Key
      $privateKey = $this->privateKey($keySettings['algorithm'], $keySettings['bits'], $keySettings['type']);
           
	    //Generate CSR
	    $csr = $this->csr($data, $privateKey);

	    //Sign CSR
	    $certificate = $this->sign($csr, $certSettings, $rootpk, $rootca);

	    return $certificate;		
	}


	public function ca_exists()
	{
		return false;
	}

	
	public function privateKey($alg, $bits, $type)
	{
		return openssl_pkey_new([
			'digest_alg' 				=> $alg,
			'private_key_bits' 	=> $bits,
			'private_key_type' 	=> $type
		]);
	}

	public function csr($csr, $privateKey)
	{
		return openssl_csr_new($csr, $privateKey);
	}

	public function sign($csr, $certSettings, $privateKey, $cacert = NULL){

		$output = NULL;
		if($cacert !== NULL){
			openssl_x509_export($cacert, $output);
		}
				
		return openssl_csr_sign(
			$csr,
			$output,
			$privateKey,
			$certSettings['validity']
		);
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