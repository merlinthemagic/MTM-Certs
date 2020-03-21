<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs\Factories;

class Tools extends Base
{
	//use: $toolObj	= \MTM\Certs\Factories::getTools()->__METHOD__();
	
	public function getCsr()
	{
		if (array_key_exists(__FUNCTION__, $this->_cStore) === false) {
			$this->_cStore[__FUNCTION__]	= new \MTM\Certs\Tools\CSR();
		}
		return $this->_cStore[__FUNCTION__];
	}
	public function getCrt()
	{
		if (array_key_exists(__FUNCTION__, $this->_cStore) === false) {
			$this->_cStore[__FUNCTION__]	= new \MTM\Certs\Tools\CRT();
		}
		return $this->_cStore[__FUNCTION__];
	}
	public function getOpenSsl()
	{
		if (array_key_exists(__FUNCTION__, $this->_cStore) === false) {
			$this->_cStore[__FUNCTION__]	= new \MTM\Certs\Tools\OpenSSL();
		}
		return $this->_cStore[__FUNCTION__];
	}
}