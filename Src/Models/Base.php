<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs\Models;

class Base
{		
	protected $_parent=null;
	protected $_cert=null;
	
	public function set($str)
	{
		//get rid of the differnet variations of line breaks so the data
		//does not depend on the platform and can be compared as strings
		$str			= str_replace(array("\r\n", "\n\r", "\r"), "\n", $str);
		$this->_cert	= trim($str);
		return $this;
	}
	public function get()
	{
		return $this->_cert;
	}
	public function setParent($obj)
	{
		$this->_parent	= $obj;
		return $this;
	}
	public function getParent()
	{
		return $this->_parent;
	}
	public function getChainAsString()
	{
		$strCert	= $this->get();
		if ($this->getParent() !== null) {
			$strCert	.= "\n" . $this->getParent()->getChainAsString();
		}
		return $strCert;
	}
}