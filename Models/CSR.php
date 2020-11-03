<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs\Models;

class CSR extends Base
{
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
	public function getDetail()
	{
		return $this->getTool()->getDetail($this);
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