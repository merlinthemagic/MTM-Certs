<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs\Models;

class CSR extends Base
{
	private $_pKey=null;
	
	public function setPrivateKey($keyObj)
	{
		$this->_pKey	= $keyObj;
		return $this;
	}
	public function getPrivateKey()
	{
		return $this->_pKey;
	}
}