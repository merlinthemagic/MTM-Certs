<?php
//© 2018 Martin Madsen
namespace MTM\Certs\Tools;

class CSR
{
	public function get($keyObj=null, $commonName=null, $orgName=null, $orgUnit=null, $country=null, $state=null, $local=null, $email=null, $format="pem")
	{
		$lines		= \MTM\Certs\Factories::getTools()->getOpenSsl()->getCSR($commonName, $orgName, $orgUnit, $country, $state, $local, $email);
		$tmpFile	= \MTM\FS\Factories::getFiles()->getTempFile("cnf");
		$tmpFile->setContent(implode("\n", $lines));

		try {
			
			//create the CSR
			$keyRes		= openssl_pkey_get_private($keyObj->get(), $keyObj->getPassPhrase());//pass by ref only
			$certRes	= openssl_csr_new(array(), $keyRes, array("config" => $tmpFile->getPathAsString(), "x509_extensions" => "v3_req"));
	
			if (is_resource($certRes) === false) {
				throw new \Exception("Failed to generate CSR");
			}
			
			if ($format == "pem") {
				$valid	= openssl_csr_export($certRes, $certStr);
				if ($valid !== true) {
					throw new \Exception("Failed to export CSR as PEM");
				}
			} else {
				throw new \Exception("Invalid format: " . $format);
			}
		
			$tmpFile->delete();
			return \MTM\Certs\Factories::getCerts()->getCSR($certStr, $keyObj);
			
		} catch (\Exception $e) {
			$tmpFile->delete();
			throw $e;
		}
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