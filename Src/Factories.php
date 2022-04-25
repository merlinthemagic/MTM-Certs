<?php
//© 2019 Martin Peter Madsen
namespace MTM\Certs;

class Factories
{
	private static $_cStore=array();
	
	//USE: $aFact		= \MTM\Certs\Factories::$METHOD_NAME();
	
	public static function getCerts()
	{
		if (array_key_exists(__FUNCTION__, self::$_cStore) === false) {
			self::$_cStore[__FUNCTION__]	= new \MTM\Certs\Factories\Certs();
		}
		return self::$_cStore[__FUNCTION__];
	}
	public static function getTools()
	{
		if (array_key_exists(__FUNCTION__, self::$_cStore) === false) {
			self::$_cStore[__FUNCTION__]	= new \MTM\Certs\Factories\Tools();
		}
		return self::$_cStore[__FUNCTION__];
	}
}