<?php

return [

		"storagePath" 							=> app_path().DIRECTORY_SEPARATOR.'CAStorage',
		"model"											=> "Certificate",

		"subject" => [
			"countryName"            	=> "IL",              		// 2-digit country code
			"stateOrProvinceName"    	=> "Northern District", 	// Province
			"localityName"           	=> "Kiryat Shmona",     	// Locality
			"organizationName"       	=> "Web Tech",  					// Organization Name
			"organizationalUnitName" 	=> "Web Tech CA",  				// Organization Department Name
			"commonName"             	=> "*.webt.co.il",     		// FQDN for certificate requests
			"emailAddress"           	=> "igor@webt.co.il"			// Email address for certificate
		], 

		"certSettings" => [
			"password" 								=> '',                		// Password for private key sign
			"validity" 								=> 365,                 	// Cert validity time
		],

		"keySettings" => [
			"algorithm" 							=> "sha512",             	// Cert Digest Algorythm
			"bits" 										=> 2048,                 	// Private Key Size
			"type" 										=> OPENSSL_KEYTYPE_RSA,  	// Private Key Tipe
		]

];