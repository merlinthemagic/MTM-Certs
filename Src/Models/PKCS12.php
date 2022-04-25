<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs\Models;

class PKCS12 extends Base
{
	//PKCS12 formatted cert
	
	private $_passPhrase=null;
	
	public function setPassPhrase($str)
	{
		$this->_passPhrase	= $str;
		return $this;
	}
	public function getPassPhrase()
	{
		return $this->_passPhrase;
	}
}