<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs\Factories;

class Certs extends Base
{
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
}