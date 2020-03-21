<?php
//� 2019 Martin Peter Madsen
namespace MTM\Certs\Models;

class CRT extends Base
{
	//Generic Certificate
	protected $_pKey=null;
	protected $_toolObj=null;
	
	public function setPrivateKey($keyObj)
	{
		$this->_pKey	= $keyObj;
		return $this;
	}
	public function getPrivateKey()
	{
		return $this->_pKey;
	}
	public function getAsPkcs12($password=null)
	{
		return $this->getTool()->x509ToPkcs12($this, $password);
	}
	public function setTool($obj)
	{
		$this->_toolObj	= $obj;
		return $this;
	}
	public function getTool()
	{
		return $this->_toolObj;
	}
}