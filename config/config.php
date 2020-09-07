<?php

return [

        "table"                                         => "certificates",
        "serialKey"                                 => "id",

        "rootSerial"                                => 1000000,

        "subject" => [
            "countryName"               => "IL",                    // 2-digit country code
            "stateOrProvinceName"       => "Northern District",     // Province
            "localityName"              => "Kiryat Shmona",         // Locality
            "organizationName"          => "Web Tech",                      // Organization Name
            "organizationalUnitName"    => "CA",                                // Organization Department Name
            "commonName"                => "Web Tech",                  // FQDN for certificate requests
            "emailAddress"              => "admin@webt.co.il"           // Email address for certificate
        ],

        "password"                              => '',                      // Password for private key sign
        "validity"                              => 365,                     // Cert validity time

        "algo"                                      => "sha512",                // Cert Digest Algorythm
        "bits"                                      => 2048,                    // Private Key Size
        "type"                                      => OPENSSL_KEYTYPE_RSA,     // Private Key Tipe

];
