<?php

namespace Igorgoroshit\Certs;

use Igorgoroshit\Certs\Interfaces\StorageInterface;
use Igorgoroshit\Certs\Interfaces\CertificateInterface;
use Igorgoroshit\Certs\Certificate;
use Exception;

class SSLCert
{

    protected $storage;
    protected $algo;
    protected $bits;
    protected $type;
    protected $root;
    protected $validity = 365;
    protected $password = '';
    protected $config = [];

    public function __construct(StorageInterface $storage)
    {
        $this->storage = $storage;
    }

    public function setConfig($key, $value)
    {
        $this->config[$key] = $value;
    }

    public function setRoot(CertificateInterface $cert)
    {
        $this->root = $cert;
    }

    public function hasRoot()
    {
        return $this->root !== null;
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
            return null;
        }
    }

    public function save(CertificateInterface $cert, $serial = null)
    {
        return $this->storage->save($cert, $serial);
    }

    public function create($data, $save = true)
    {

        if (empty($this->config)) {
            $config = null;
        } else {
            $config = $this->config;
        }

        //create private/public key pair
        $key = openssl_pkey_new([
            'digest_alg'                => $this->algo,
            'private_key_bits'  => $this->bits,
            'private_key_type'  => $this->type
        ]);

        //export private key
        $priKeyOut = null;
        openssl_pkey_export($key, $priKeyOut, null, $config);

        //create and export new csr
        $csr = openssl_csr_new($data, $key, $config);
        $csrOut = null;
        openssl_csr_export($csr, $csrOut);


        $cert = new Certificate();
        $cert->setPrivateKey($priKeyOut);
        $cert->setCsr($csrOut);

        if ($save) {
            $this->save($cert);
        }

        return $cert;
    }

    public function sign(CertificateInterface $cert, $validity = null, $save = true)
    {
        if (empty($this->config)) {
            $config = null;
        } else {
            $config = $this->config;
        }

        $csr    = $cert->getCsr();

        $days = $validity ? (int)$validity : $this->validity;

        $signed = openssl_csr_sign(
            $csr,
            $this->root->getCertificate(),
            $this->root->getPrivateKey(),
            $days,
            $config,
            $cert->getSerial()
        );

        $cert->setCertificate($this->export($signed));
        
        if ($save) {
            $this->save($cert);
        }

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
        $output = false;

        switch (strtoupper($type)) {
            case 'X509':
                openssl_x509_export($cert, $output);
                break;
            case 'CSR':
                $format = 'csr';
                openssl_csr_export($cert, $output);
                break;
            case 'PKCS10':
                $format = 'p10';
                openssl_csr_export($cert, $output);
                break;
            case 'PKCS12':
                $format = 'p12';
                openssl_pkcs12_export($cert, $output);
                break;
        }
        
        if (strtolower($format) === 'pem') {
            $output = $this->der2pem($output);
        }

        return $output;
    }

    protected function pem2der($pem_data)
    {
        $begin = "CERTIFICATE-----";
        $end   = "-----END";
        $pem_data = substr($pem_data, strpos($pem_data, $begin) + strlen($begin));
        $pem_data = substr($pem_data, 0, strpos($pem_data, $end));
        $der = base64_decode($pem_data);
        return $der;
    }


    protected function der2pem($der_data)
    {
        $pem = chunk_split(base64_encode($der_data), 64, "\n");
        $pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
        return $pem;
    }
}
