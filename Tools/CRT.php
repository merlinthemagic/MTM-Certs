<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs\Tools;

class CRT
{
	public function getCA($csrObj, $validDays=7300)
	{
		$lines		= \MTM\Certs\Factories::getTools()->getOpenSsl()->getCA();
		$tmpFile	= \MTM\FS\Factories::getFiles()->getTempFile("cnf");
		$tmpFile->setContent(implode("\n", $lines));
		
		try {
			$serial		= str_replace(".", "",  \MTM\Utilities\Factories::getTime()->getMicroEpoch());
			$x509Res	= openssl_csr_sign($csrObj->get(), null, array($csrObj->getPrivateKey()->get(), $csrObj->getPrivateKey()->getPassPhrase()), $validDays, array("config" => $tmpFile->getPathAsString(), "x509_extensions" => "v3_ca", "digest_alg" => "sha256"), $serial);
			if (is_resource($x509Res) === false) {
				throw new \Exception("Failed to sign CSR");
			}
			$valid	= @openssl_x509_export($x509Res, $certStr);
			if ($valid !== true) {
				throw new \Exception("Failed to export Signed CSR");
			}
			
			$tmpFile->delete();
			return \MTM\Certs\Factories::getCerts()->getCA($certStr, $csrObj->getPrivateKey());
			
		} catch (\Exception $e) {
			$tmpFile->delete();
			throw $e;
		}
	}
	public function getIntermediateCA($csrObj, $caObj, $validDays=7300)
	{
		$lines		= \MTM\Certs\Factories::getTools()->getOpenSsl()->getIntermediate();
		$tmpFile	= \MTM\FS\Factories::getFiles()->getTempFile("cnf");
		$tmpFile->setContent(implode("\n", $lines));
		
		try {
			$serial		= str_replace(".", "",  \MTM\Utilities\Factories::getTime()->getMicroEpoch());
			$x509Res	= openssl_csr_sign($csrObj->get(), $caObj->get(), array($caObj->getPrivateKey()->get(), $caObj->getPrivateKey()->getPassPhrase()), $validDays, array("config" => $tmpFile->getPathAsString(), "x509_extensions" => "v3_intermediate_ca", "digest_alg" => "sha256"), $serial);
			if (is_resource($x509Res) === false) {
				throw new \Exception("Failed to sign CSR");
			}
			$valid	= @openssl_x509_export($x509Res, $certStr);
			if ($valid !== true) {
				throw new \Exception("Failed to export Signed CSR");
			}
			
			$tmpFile->delete();
			return \MTM\Certs\Factories::getCerts()->getCA($certStr, $csrObj->getPrivateKey());
			
		} catch (\Exception $e) {
			$tmpFile->delete();
			throw $e;
		}
	}
	public function getServerCRT($csrObj, $caObj, $validDays=365, $altDns=array())
	{
		$detail		= openssl_csr_get_subject($csrObj->get());
		//common name must be included in the alt DNS as the first item
		array_unshift($altDns, $detail["CN"]);
		$altDns		= array_unique($altDns);

		$lines		= \MTM\Certs\Factories::getTools()->getOpenSsl()->getServer($altDns);
		$tmpFile	= \MTM\FS\Factories::getFiles()->getTempFile("cnf");
		$tmpFile->setContent(implode("\n", $lines));

		try {
			$serial		= str_replace(".", "",  \MTM\Utilities\Factories::getTime()->getMicroEpoch(false));
			$x509Res	= openssl_csr_sign($csrObj->get(), $caObj->get(), array($caObj->getPrivateKey()->get(), $caObj->getPrivateKey()->getPassPhrase()), $validDays, array("config" => $tmpFile->getPathAsString(), "x509_extensions" => "server_cert", "digest_alg" => "sha256"), $serial);
			if (is_resource($x509Res) === false) {
				throw new \Exception("Failed to sign CSR");
			}
			$valid	= @openssl_x509_export($x509Res, $certStr);
			if ($valid !== true) {
				throw new \Exception("Failed to export Signed CSR");
			}
			
			$tmpFile->delete();
			return \MTM\Certs\Factories::getCerts()->getCRT($certStr, $csrObj->getPrivateKey());
			
		} catch (\Exception $e) {
			$tmpFile->delete();
			throw $e;
		}
	}
	public function getClientCRT($csrObj, $caObj, $validDays=365, $altDns=array())
	{
		$detail		= openssl_csr_get_subject($csrObj->get());
		//common name must be included in the alt DNS as the first item
		array_unshift($altDns, $detail["CN"]);
		$altDns		= array_unique($altDns);
		
		$lines		= \MTM\Certs\Factories::getTools()->getOpenSsl()->getClient($altDns);
		$tmpFile	= \MTM\FS\Factories::getFiles()->getTempFile("cnf");
		$tmpFile->setContent(implode("\n", $lines));
		
		try {
			
			$serial		= str_replace(".", "",  \MTM\Utilities\Factories::getTime()->getMicroEpoch(false));
			$x509Res	= openssl_csr_sign($csrObj->get(), $caObj->get(), array($caObj->getPrivateKey()->get(), $caObj->getPrivateKey()->getPassPhrase()), $validDays, array("config" => $tmpFile->getPathAsString(), "x509_extensions" => "client_cert", "digest_alg" => "sha256"), $serial);
			if (is_resource($x509Res) === false) {
				throw new \Exception("Failed to sign CSR");
			}
			$valid	= @openssl_x509_export($x509Res, $certStr);
			if ($valid !== true) {
				throw new \Exception("Failed to export Signed CSR");
			}
			
			$tmpFile->delete();
			return \MTM\Certs\Factories::getCerts()->getCRT($certStr, $csrObj->getPrivateKey());
			
		} catch (\Exception $e) {
			$tmpFile->delete();
			throw $e;
		}
	}
	public function x509ToPkcs12($crtObj, $password=null)
	{
		if ($crtObj instanceof \MTM\Certs\Models\CRT === false) {
			throw new \Exception("Invalid input");
		} elseif ($crtObj->getParent() !== null) {
			//can be done, just have no need currently: https://www.php.net/manual/en/function.openssl-pkcs12-export.php
			throw new \Exception("Cannot handle parent certs");
		}
		$x509Res	= openssl_x509_read($crtObj->get());
		if (is_resource($x509Res) === false) {
			throw new \Exception("Failed to get certificate resource");
		}
		$valid		= openssl_pkcs12_export($x509Res, $pkcs, array($crtObj->getPrivateKey()->get(), $crtObj->getPrivateKey()->getPassPhrase()), $password);
		if ($valid !== true) {
			throw new \Exception("Failed to export as PKCS#12");
		}
		return \MTM\Certs\Factories::getCerts()->getPKCS12(base64_encode($pkcs), $password);
	}
	public function getDetail($crtObj)
	{
		$d	= openssl_x509_parse($crtObj->get(), true);
		if (is_array($d) === true && array_key_exists("serialNumber", $d) === true) {
			
			//append as needed, there is alot of data 
			$rObj				= new \stdClass();
			$rObj->serial		= $d["serialNumber"];
			$rObj->commonName	= null;
			$rObj->country		= null;
			$rObj->state		= null;
			$rObj->city			= null;
			$rObj->orgName		= null;
			$rObj->orgUnit		= null;
			
			if (array_key_exists("subject", $d) === true && is_array($d["subject"]) === true ) {
				$s		= $d["subject"];
				if (array_key_exists("CN", $s) === true) {
					$rObj->commonName	= $s["CN"];
				}
				if (array_key_exists("C", $s) === true) {
					$rObj->country		= $s["C"];
				}
				if (array_key_exists("ST", $s) === true) {
					$rObj->state		= $s["ST"];
				}
				if (array_key_exists("L", $s) === true) {
					$rObj->city			= $s["L"];
				}
				if (array_key_exists("O", $s) === true) {
					$rObj->orgName		= $s["O"];
				}
				if (array_key_exists("OU", $s) === true) {
					$rObj->orgUnit		= $s["OU"];
				}
			}
			
			return $rObj;
			
		} else {
			throw new \Exception("Failed to get details, maybe not a valid certificate, or maybe protected");
		}
	}
}