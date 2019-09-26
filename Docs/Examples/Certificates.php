<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs\Docs\Examples;

class Certificates
{
	public function getCA()
	{
		$path		= __DIR__ . DIRECTORY_SEPARATOR . "Certs" .  DIRECTORY_SEPARATOR . "CA" . DIRECTORY_SEPARATOR;
		$certFile	=  $path . "certificate.pem";
		$keyFile	=  $path . "key.pem";
		
		$keyObj		= \MTM\Encrypt\Factories::getRSA()->getPrivateKey(file_get_contents($keyFile));
		$certObj	= \MTM\Certs\Factories::getCerts()->getCA(file_get_contents($certFile), $keyObj);
		return $certObj;
	}
	public function getIntermediate()
	{
		$path		= __DIR__ . DIRECTORY_SEPARATOR . "Certs" .  DIRECTORY_SEPARATOR . "Intermediate" . DIRECTORY_SEPARATOR;
		$certFile	=  $path . "certificate.pem";
		$keyFile	=  $path . "key.pem";
		
		$keyObj		= \MTM\Encrypt\Factories::getRSA()->getPrivateKey(file_get_contents($keyFile));
		$certObj	= \MTM\Certs\Factories::getCerts()->getCA(file_get_contents($certFile), $keyObj);
		$certObj->setParent($this->getCA());
		
		return $certObj;
	}
	public function getServer1()
	{
		$path		= __DIR__ . DIRECTORY_SEPARATOR . "Certs" .  DIRECTORY_SEPARATOR . "Server1" . DIRECTORY_SEPARATOR;
		$certFile	=  $path . "certificate.pem";
		$keyFile	=  $path . "key.pem";
		
		$keyObj		= \MTM\Encrypt\Factories::getRSA()->getPrivateKey(file_get_contents($keyFile));
		$certObj	= \MTM\Certs\Factories::getCerts()->getCRT(file_get_contents($certFile), $keyObj);
		$certObj->setParent($this->getIntermediate());
		
		return $certObj;
	}
	public function getServer2()
	{
		$path		= __DIR__ . DIRECTORY_SEPARATOR . "Certs" .  DIRECTORY_SEPARATOR . "Server2" . DIRECTORY_SEPARATOR;
		$certFile	=  $path . "certificate.pem";
		$keyFile	=  $path . "key.pem";
		
		$keyObj		= \MTM\Encrypt\Factories::getRSA()->getPrivateKey(file_get_contents($keyFile));
		$certObj	= \MTM\Certs\Factories::getCerts()->getCRT(file_get_contents($certFile), $keyObj);
		$certObj->setParent($this->getIntermediate());
		
		return $certObj;
	}
	public function getClient1()
	{
		$path		= __DIR__ . DIRECTORY_SEPARATOR . "Certs" .  DIRECTORY_SEPARATOR . "Client1" . DIRECTORY_SEPARATOR;
		$certFile	=  $path . "certificate.pem";
		$keyFile	=  $path . "key.pem";
		
		$keyObj		= \MTM\Encrypt\Factories::getRSA()->getPrivateKey(file_get_contents($keyFile));
		$certObj	= \MTM\Certs\Factories::getCerts()->getCRT(file_get_contents($certFile), $keyObj);
		$certObj->setParent($this->getIntermediate());
		
		return $certObj;
	}
	public function getClient2()
	{
		$path		= __DIR__ . DIRECTORY_SEPARATOR . "Certs" .  DIRECTORY_SEPARATOR . "Client2" . DIRECTORY_SEPARATOR;
		$certFile	=  $path . "certificate.pem";
		$keyFile	=  $path . "key.pem";
		
		$keyObj		= \MTM\Encrypt\Factories::getRSA()->getPrivateKey(file_get_contents($keyFile));
		$certObj	= \MTM\Certs\Factories::getCerts()->getCRT(file_get_contents($certFile), $keyObj);
		$certObj->setParent($this->getIntermediate());
		
		return $certObj;
	}
	public function getClient3()
	{
		$path		= __DIR__ . DIRECTORY_SEPARATOR . "Certs" .  DIRECTORY_SEPARATOR . "Client3" . DIRECTORY_SEPARATOR;
		$certFile	=  $path . "certificate.pem";
		$keyFile	=  $path . "key.pem";
		
		$keyObj		= \MTM\Encrypt\Factories::getRSA()->getPrivateKey(file_get_contents($keyFile));
		$certObj	= \MTM\Certs\Factories::getCerts()->getCRT(file_get_contents($certFile), $keyObj);
		$certObj->setParent($this->getIntermediate());
		
		return $certObj;
	}
}