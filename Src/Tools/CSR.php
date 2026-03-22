<?php
//� 2018 Martin Madsen
namespace MTM\Certs\Tools;

class CSR
{
	public function get($keyObj=null, $commonName=null, $orgName=null, $orgUnit=null, $country=null, $state=null, $local=null, $email=null, $format="pem")
	{
		if (strlen($commonName) > 64) {
			throw new \Exception("Common Name cannot be more than 64 chars", 5555);
		}
		
		$lines		= \MTM\Certs\Factories::getTools()->getOpenSsl()->getCSR($commonName, $orgName, $orgUnit, $country, $state, $local, $email);
		$tmpFile	= \MTM\FS\Factories::getFiles()->getTempFile("cnf");
		$tmpFile->setContent(implode("\n", $lines));

		try {
			
			//create the CSR
			$keyRes		= openssl_pkey_get_private($keyObj->get(), $keyObj->getPassPhrase());//pass by ref only
			$rData		= openssl_csr_new(array(), $keyRes, array("config" => $tmpFile->getPathAsString(), "x509_extensions" => "v3_req"));
			if (
				$rData instanceof \OpenSSLCertificateSigningRequest === false
				&& is_resource($rData) === false
			) {
				throw new \Exception("Failed to generate CSR", 5555);
			}
			
			if ($format == "pem") {
				$valid	= openssl_csr_export($rData, $certStr);
				if ($valid !== true) {
					throw new \Exception("Failed to export CSR as PEM", 5555);
				}
			} else {
				throw new \Exception("Invalid format: " . $format, 5555);
			}
		
			$tmpFile->delete();
			return \MTM\Certs\Factories::getCerts()->getCSR($certStr, $keyObj);
			
		} catch (\Exception $e) {
			$tmpFile->delete();
			throw $e;
		}
	}
	public function getDetail($csrObj)
	{
		$detail	  = openssl_csr_get_subject($csrObj->get());
		if ($detail === false) {
			throw new \Exception("Failed to extract details for CSR", 5555);
		}
		$pubRes	= openssl_csr_get_public_key($csrObj->get());
		if ($pubRes === false) {
			throw new \Exception("Failed to extract public key for CSR", 5555);
		}
		$pubKey	= openssl_pkey_get_details($pubRes);
		if (isset($pubKey["key"]) === false || strlen($pubKey["key"]) < 1) {
			throw new \Exception("Failed to extract public key");
		}

		$rObj				= new \stdClass();
		$rObj->commonName	= null;
		$rObj->country		= null;
		$rObj->state		= null;
		$rObj->city			= null;
		$rObj->orgName		= null;
		$rObj->orgUnit		= null;
		$rObj->emailAddress	= null;
		$rObj->pubKey		= $pubKey["key"];
		
		if (isset($detail["CN"]) !== false) {
			$rObj->commonName	= $detail["CN"];
		}
		if (isset($detail["C"]) !== false) {
			$rObj->country	= $detail["C"];
		}
		if (isset($detail["ST"]) !== false) {
			$rObj->state	= $detail["ST"];
		}
		if (isset($detail["L"]) !== false) {
			$rObj->city	= $detail["L"];
		}
		if (isset($detail["O"]) !== false) {
			$rObj->orgName	= $detail["O"];
		}
		if (isset($detail["OU"]) !== false) {
			$rObj->orgUnit	= $detail["OU"];
		}
		if (isset($detail["emailAddress"]) !== false) {
			$rObj->emailAddress	= $detail["emailAddress"];
		}
		return $rObj;
	}
	public function getTest()
	{
		$keyObj		= \MTM\Encrypt\Factories::getRSA()->getTool()->createPrivateKey(4096);
		$commonName	= "My Company Root CA";
		$orgName	= "My Company";
		$orgUnit	= "My Company Certificate Authority";
		$country	= "US";
		$state		= "Florida";
		$local		= "Tampa";
		$email		= "postmaster@mycompany.com";
		$format		= "pem";

		return $this->get($keyObj, $commonName, $orgName, $orgUnit, $country, $state, $local, $email, $format);
	}	
}