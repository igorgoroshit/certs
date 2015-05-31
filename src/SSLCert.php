<?php namespace Igorgoroshit\Certs;

use Exception;

class SSLCert{

	private $storagePath;

	private $current_path;
	private $private_key;
	private $public_key;

	private $caroot_cert;
	

	private $store   = 'store';
	private $ca_root = 'CA';


	public function __construct($path){
		$this->storagePath = $path;
		$this->load_ca();
	}

	public function generate_cacert($csr_config, $cert_config, $pkey_config){
		if(!$this->ca_exists()){
			$priv_key = $this->generate_priv_key($pkey_config);
			$csr_data = $this->generate_csr($csr_config, $priv_key);
			$cert     = $this->sign_csr($csr_data, $cert_config);
			
			$this->store_private_key($priv_key);
			$this->store_pem_cert($cert);

			return TRUE;
		}
		return FALSE;
	}
	

	public function ca_exists()
	{
		return
			file_exists($this->get_store_path('private_key')) &&
			file_exists($this->get_store_path('pem_cert')) &&
			file_exists($this->get_store_path('der_cert'));
	}
	

	public function load_ca($pkey_passphrase = ""){
		if($this->ca_exists()){
			if(empty($pkey_passphrase)){
				$this->private_key = openssl_pkey_get_private(
					file_get_contents($this->get_store_path('private_key'))
				);
			}
			else{
				$this->private_key = openssl_pkey_get_private(
					array(
						file_get_contents($this->get_store_path('private_key')),
						$pkey_passphrase
					)
				);
			}
			$this->caroot_cert = openssl_x509_read(file_get_contents($this->get_store_path('pem_cert')));
			
			var_dump($this->get_store_path('private_key'));
			
			return
				!empty($this->private_key) &&
				!empty($this->caroot_cert);
		}
		return FALSE;
	}


	public function get_key_private(){
		return $this->private_key;
	}
	

	public function get_key_public(){
		return $this->public_key;
	}
	

	public function store_private_key($data){
		$this->_store_private_key($data);
	}

	public function store_csr_data($data, $filename = ""){
		$this->_store_csr_data($data, $filename);
	}

	public function store_pem_cert($data, $filename = FALSE){
		$this->_store_pem_cert($data, $filename);
	}	

	public function pem2der($pem_file){
		return $this->_pem2der(file_get_contents($pem_file));
	}

	public function der2pem($der_file){
		return $this->der2pem(file_get_contents($der_file));
	}
	
	public function generate_priv_key($key_data = FALSE, $force = FALSE){
		if(empty($this->private_key) || $force){
			$this->_generate_priv_key($key_data);
		}
		return $this->private_key;
	}
	

	public function check_ssl()
	{
		return extension_loaded('openssl');
	}
	

	public function check_cert($cert, $key, $passphrase = "")
	{
		return openssl_x509_check_private_key(
			$cert,
			array(
				$key,
				$passphrase,
			)
		);
	}
	

	public function generate_csr($request_data = FALSE, $private_key = FALSE){
		if($request_data !== FALSE && is_array($request_data)){
			foreach($request_data as $request_data_field=>$request_data_value){
				if(!empty($this->defaults['csr_data'][$request_data_field])){
					$this->defaults['csr_data'][$request_data_field] = $request_data_value;
				}
			}
		}
		if($private_key === FALSE){
			$private_key = $this->private_key;
		}
		return openssl_csr_new($this->defaults['csr_data'], $private_key);
	}
	

	public function download_cert($cert, $cert_name = 'signed_certificate_', $type = 'X509', $outformat = 'der'){
		$outformat = strtolower($outformat);
		$cert_ext = FALSE;

		switch(strtoupper($type)){
			case 'X509':
				header('Content-type: application/x-x509-ca-cert');
				openssl_x509_export($cert, $cert_ext);
				break;
			case 'CSR':
				$outformat = 'csr';
			case 'PKCS10':
				$outformat = 'p10';
				header('Content-type: application/pkcs10 ');
				openssl_csr_export($cert, $cert_ext);
				break;
			case 'PKCS12':
				$outformat = 'p12';
				header('Content-type: application/x-pkcs12');
				openssl_pkcs12_export($cert, $cert_ext);
				break;
		}
		
		if(strtolower($outformat) === 'pem'){
			header('Content-type: application/x-pem-file', TRUE);
			$cert_ext = $this->_der2pem($cert_ext);
		}

		header('Content-Disposition: attachment; filename="'.$cert_name.strtoupper($type).'.'.$outformat.'"');
		echo $cert_ext;
	}
	

	public function get_exportable_cert($cert = FALSE){
		if($cert === FALSE){
			return FALSE;
		}
		$exportable_cert = FALSE;
		openssl_x509_export($cert, $exportable_cert);
		return $exportable_cert;
	}
	

	public function get_exportable_key_private($key = FALSE){
		if($key === FALSE){
			$key = $this->private_key;
		}
		$exportable_key = FALSE;
		openssl_pkey_export($key, $exportable_key);
		return $exportable_key;
	}
	

	public function get_exportable_key_public($key = FALSE){
		if($key === FALSE){
			$key = $this->private_key;
		}
		$public_key = openssl_pkey_get_details($key);
		$exportable_key = $public_key["key"];
		return $exportable_key;
	}
	

	public function get_exportable_key_public_from_cert($cert = FALSE){
		if($cert === FALSE){
			return FALSE;
		}
		$public_key = openssl_pkey_get_public($cert);
		$public_key_data = openssl_pkey_get_details($public_key);
		$exportable_key = $public_key_data['key'];
		return $exportable_key;
	}


	private function _store_private_key($data){
		$private_key_file = $this->get_store_path('private_key');
		openssl_pkey_export_to_file($data, $private_key_file, $this->defaults['cert_data']['password']);
	}


	private function _store_csr_data($data, $filename = ""){
		$csr_data_file = $this->get_store_path('csr_data', $filename);
		openssl_csr_export_to_file($data, $csr_data_file);
	}

	private function _store_pem_cert($data, $filename = FALSE){
		$pem_cert_file = '';
		if($filename === FALSE){
			$pem_cert_file = $this->get_store_path('pem_cert');
		}else{
			$pem_cert_file = $this->get_store_path().$filename.".pem";
		}
		openssl_x509_export_to_file($data, $pem_cert_file);
		
		$this->_store_der_cert($this->pem2der($pem_cert_file));
	}


	private function _store_der_cert($data, $filename = FALSE){
		$der_cert_file = '';
		if($filename === FALSE){
			$der_cert_file = $this->get_store_path('der_cert');
		}else{
			$der_cert_file = $this->get_store_path().$filename.".der";
		}
		file_put_contents($der_cert_file, $data);
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


	private function get_store_path($file = FALSE, $custom_filename = FALSE){
		$basepath = $this->storagePath.DIRECTORY_SEPARATOR;
		switch($file){
			case 'private_key':
				$filename = !empty($custom_filename) ? $custom_filename.DIRECTORY_SEPARATOR : '';
				$filename = $filename . 'private';
				return $basepath.$this->ca_root.DIRECTORY_SEPARATOR.$filename.'.key';
				break;
			case 'public_key':
				$filename = !empty($custom_filename) ? $custom_filename.DIRECTORY_SEPARATOR : '';
				$filename = $filename . 'public';
				return $basepath.$this->ca_root.DIRECTORY_SEPARATOR.$filename.'.key';
				break;
			case 'pem_cert':
				$filename = !empty($custom_filename) ? $custom_filename.DIRECTORY_SEPARATOR : '';
				$filename = $filename . 'caroot';
				return $basepath.$this->ca_root.DIRECTORY_SEPARATOR.$filename.'.pem';
				break;
			case 'der_cert':
				$filename = !empty($custom_filename) ? $custom_filename.DIRECTORY_SEPARATOR : '';
				$filename = $filename . 'caroot';
				return $basepath.$this->ca_root.DIRECTORY_SEPARATOR.$filename.'.der';
				break;
			case 'csr_data':
				$filename = !empty($custom_filename) ? $custom_filename.DIRECTORY_SEPARATOR : '';
				$filename = $filename . 'caroot';
				return $basepath.$this->store.DIRECTORY_SEPARATOR.$filename.'.csr';
				break;
			case 'openssl_conf':
				return $basepath.$this->store.DIRECTORY_SEPARATOR."openssl.conf";
				break;
			case 'store':
				return $basepath.$this->store.DIRECTORY_SEPARATOR;
				break;
			default:
				return $basepath;
				break;
		}
	}
	

	private function _generate_priv_key($key_data = FALSE){
		if($key_data !== FALSE && is_array($key_data)){
			foreach($key_data as $key_data_field=>$key_data_value){
				if(!empty($this->defaults['pkey_data'][$key_data_field])){
					$this->defaults['pkey_data'][$key_data_field] = $key_data_value;
				}
			}
		}
	
		$this->private_key = openssl_pkey_new($this->defaults['pkey_data']);
	}
	

	public function sign_csr($csr_data = FALSE, $cert_data = FALSE, $cacert = NULL){
		if($cert_data !== FALSE && is_array($cert_data)){
			foreach($cert_data as $cert_data_field=>$cert_data_value){
				if(!empty($this->defaults['cert_data'][$cert_data_field])){
					$this->defaults['cert_data'][$cert_data_field] = $cert_data_value;
				}
			}
		}

		if($cacert === NULL){
			if(!empty($this->caroot_cert)){
				$cacert = $this->caroot_cert;
			}
		}
		
		$cacert_exportable = NULL;
		if($cacert !== NULL){
			openssl_x509_export($cacert, $cacert_exportable);
		}
				
		return openssl_csr_sign(
			$csr_data,
			$cacert_exportable,
			$this->get_key_private(),
			$this->defaults['cert_data']['validity']
		);
	}
}