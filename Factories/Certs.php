<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs\Factories;

class Certs extends Base
{
	//use: $certObj	= \MTM\Certs\Factories::getCerts()->__METHOD__();
	
	public function getCSR($str=null, $key=null)
	{
		$rObj	= new \MTM\Certs\Models\CSR();
		if ($str !== null) {
			$rObj->set($str);
		}
		if ($key !== null) {
			$rObj->setPrivateKey($key);
		}
		return $rObj;
	}
	public function getCRT($str=null, $key=null)
	{
		$rObj	= new \MTM\Certs\Models\CRT();
		$rObj->setTool(\MTM\Certs\Factories::getTools()->getCrt());
		if ($str !== null) {
			$rObj->set($str);
		}
		if ($key !== null) {
			$rObj->setPrivateKey($key);
		}
		return $rObj;
	}
	public function getCA($str=null, $key=null)
	{
		$rObj	= new \MTM\Certs\Models\CA();
		if ($str !== null) {
			$rObj->set($str);
		}
		if ($key !== null) {
			$rObj->setPrivateKey($key);
		}
		return $rObj;
	}
	public function getPKCS12($str=null, $password=null)
	{
		$rObj	= new \MTM\Certs\Models\PKCS12();
		if ($str !== null) {
			$rObj->set($str);
		}
		if ($password !== null) {
			$rObj->setPassPhrase($password);
		}
		return $rObj;
	}
}