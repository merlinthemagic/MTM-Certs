<?php
//© 2019 Martin Peter Madsen
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
	public function getSerialNumber()
	{
		return $this->getDetail()->serial;
	}
	public function getDetail()
	{
		return $this->getTool()->getDetail($this);
	}
	public function validateKey($throw=false)
	{
		$keyObj	= $this->getPrivateKey();
		if ($keyObj !== null) {
			$bool	= $this->getTool()->validateKey($this, $keyObj);
			if ($bool === true || $throw === false) {
				return $bool;
			} else {
				throw new \Exception("Key is invalid");
			}
		} else {
			throw new \Exception("No key set, cannot validate");
		}
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