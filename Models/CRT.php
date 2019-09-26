<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs\Models;

class CRT extends Base
{
	//Generic Certificate
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