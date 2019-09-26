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
}