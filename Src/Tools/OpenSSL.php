<?php
//� 2019 Martin Peter Madsen
namespace MTM\Certs\Tools;

//src: https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html
//src: https://www.phildev.net/ssl/opensslconf.html

class OpenSSL
{
	public function getCSR($commonName, $orgName, $orgUnit, $country, $state, $local, $email)
	{
		$pName		= "policy_strict";
		$segs		= array();
		$segs[]		= $this->getPolicy("strict", $pName);
		$segs[]		= $this->getCaMinimal();
		$segs[]		= $this->getCaDefault($pName);
		$segs[]		= $this->getReq();
		$segs[]		= $this->getReqX509();
		$segs[]		= $this->getReqDn($commonName, $orgName, $orgUnit, $country, $state, $local, $email);
		
		return $this->stitchSegments($segs);
	}
	public function getCA()
	{
		$pName		= "policy_strict";
		$segs		= array();
		$segs[]		= $this->getPolicy("strict", $pName);
		$segs[]		= $this->getCaMinimal();
		$segs[]		= $this->getCaDefault($pName);
		$segs[]		= $this->getCaX509();
		
		return $this->stitchSegments($segs);
	}
	public function getIntermediate()
	{
		$pName		= "policy_loose";
		$segs		= array();
		$segs[]		= $this->getPolicy("loose", $pName);
		$segs[]		= $this->getCaMinimal();
		$segs[]		= $this->getCaDefault($pName);
		$segs[]		= $this->getIntermediateX509();
		
		return $this->stitchSegments($segs);
	}
	public function getServer($altDns=array())
	{
		$pName		= "policy_loose";
		$segs		= array();
		$segs[]		= $this->getPolicy("loose", $pName);
		$segs[]		= $this->getCaMinimal();
		$segs[]		= $this->getCaDefault($pName);
		
		$altGrp	= null;
		if (count($altDns) > 0) {
			$altGrp		= "alt_names";
			$segs[]		= $this->getAltNames($altGrp, $altDns);
		}
		$segs[]		= $this->getServerX509($altGrp);
		
		return $this->stitchSegments($segs);
	}
	public function getClient($altDns=array())
	{
		$pName		= "policy_loose";
		$segs		= array();
		$segs[]		= $this->getPolicy("loose", $pName);
		$segs[]		= $this->getCaMinimal();
		$segs[]		= $this->getCaDefault($pName);
		
		$altGrp	= null;
		if (count($altDns) > 0) {
			$altGrp		= "alt_names";
			$segs[]		= $this->getAltNames($altGrp, $altDns);
		}
		$segs[]		= $this->getClientX509($altGrp);
		
		return $this->stitchSegments($segs);
	}
	public function getServerAndClient($altDns=array())
	{
		$pName		= "policy_loose";
		$segs		= array();
		$segs[]		= $this->getPolicy("loose", $pName);
		$segs[]		= $this->getCaMinimal();
		$segs[]		= $this->getCaDefault($pName);
		
		$altGrp	= null;
		if (count($altDns) > 0) {
			$altGrp		= "alt_names";
			$segs[]		= $this->getAltNames($altGrp, $altDns);
		}
		$segs[]		= $this->getServerX509($altGrp);
		$segs[]		= $this->getClientX509($altGrp);
		
		return $this->stitchSegments($segs);
	}
	private function getCaMinimal()
	{
		//ca - sample minimal CA application
		$lines											= array();
		$lines[]	= "[ ca ]";
		$lines[]	= "default_ca						= CA_default";
		return $lines;
	}
	private function getCaDefault($policyName)
	{
		//ca - default config
		$lines											= array();
		$lines[]	= "[ CA_default ]";
		$lines[]	= "dir								= /root/ca/intermediate";
		$lines[]	= "certs							= \$dir/certs";
		$lines[]	= "crl_dir							= \$dir/crl";
		$lines[]	= "new_certs_dir					= \$dir/newcerts";
		$lines[]	= "database							= \$dir/index.txt";
		$lines[]	= "serial							= \$dir/serial";
		$lines[]	= "RANDFILE							= \$dir/private/.rand";
		$lines[]	= "private_key						= \$dir/private/intermediate.key.pem";
		$lines[]	= "certificate						= \$dir/certs/intermediate.cert.pem";
		$lines[]	= "crlnumber						= \$dir/crlnumber";
		$lines[]	= "crl								= \$dir/crl/intermediate.crl.pem";
		$lines[]	= "crl_extensions					= crl_ext";
		$lines[]	= "default_crl_days					= 30";
		$lines[]	= "default_md						= sha256";
		$lines[]	= "name_opt							= ca_default";
		$lines[]	= "cert_opt							= ca_default";
		$lines[]	= "default_days						= 7300";
		$lines[]	= "preserve							= no";
		$lines[]	= "policy							= " . $policyName;
		
		return $lines;
	}
	private function getRevocationList()
	{
		//Extension for CRLs (`man x509v3_config`).
		$lines		= array();
		$lines[]	= "[ crl_ext ]";
		$lines[]	= "authorityKeyIdentifier			= keyid:always";
		
		return $lines;
	}
	private function getReqDn($commonName, $orgName, $orgUnit, $country, $state, $local, $email, $altGrpName=null)
	{
		//https://en.wikipedia.org/wiki/Certificate_signing_request
		$lines		= array();
		$lines[]	= "[ req_distinguished_name ]";
		$lines[]	= "commonName_default				= " . $commonName;
		$lines[]	= "countryName_default				= " . $country;
		$lines[]	= "stateOrProvinceName_default		= " . $state;
		$lines[]	= "localityName_default				= " . $local;
		$lines[]	= "organizationName_default			= " . $orgName;
		$lines[]	= "organizationalUnitName_default	= " . $orgUnit;
		$lines[]	= "emailAddress_default				= " . $email;
		
		if ($altGrpName !== null) {
			$lines[]	= "subjectAltName					= @" . $altGrpName;
		}
		
		return $lines;
	}
	private function getReq()
	{
		//req - PKCS#10 certificate request and certificate generating utility.
		$lines[]	= "[ req ]";
		$lines[]	= "default_bits						= 2048";
		$lines[]	= "distinguished_name				= req_distinguished_name";
		$lines[]	= "string_mask						= utf8only";
		$lines[]	= "default_md						= sha256";
		$lines[]	= "x509_extensions					= v3_ca";
		$lines[]	= "req_extensions					= v3_req";
		
		return $lines;
	}
	private function getReqX509()
	{
		$lines[]	= "[ v3_req ]";
		$lines[]	= "basicConstraints 				= CA:FALSE";
		$lines[]	= "keyUsage 						= digitalSignature, nonRepudiation, keyEncipherment";
		
		return $lines;
	}
	private function getCaX509()
	{
		//Extensions for a typical CA (`man x509v3_config`).
		$lines											= array();
		$lines[]	= "[ v3_ca ]";
		$lines[]	= "subjectKeyIdentifier				= hash";
		$lines[]	= "authorityKeyIdentifier			= keyid:always,issuer";
		$lines[]	= "basicConstraints					= critical, CA:true";
		$lines[]	= "keyUsage							= critical, digitalSignature, cRLSign, keyCertSign";
		
		return $lines;
	}
	private function getIntermediateX509()
	{
		//Extensions for a typical Intermediate CA (`man x509v3_config`).
		$lines[]	= "[ v3_intermediate_ca ]";
		$lines[]	= "subjectKeyIdentifier				= hash";
		$lines[]	= "authorityKeyIdentifier			= keyid:always,issuer";
		$lines[]	= "basicConstraints					= critical, CA:true, pathlen:0";
		$lines[]	= "keyUsage							= critical, digitalSignature, cRLSign, keyCertSign";
		
		return $lines;
	}
	private function getServerX509($altGrpName=null)
	{
		$lines[]	= "[ server_cert ]";
		$lines[]	= "basicConstraints					= CA:FALSE";
		$lines[]	= "nsCertType						= server";
		$lines[]	= "nsComment						= \"MTM Server Certificate\"";
		$lines[]	= "subjectKeyIdentifier				= hash";
		$lines[]	= "authorityKeyIdentifier			= keyid,issuer:always";
		$lines[]	= "keyUsage							= critical, digitalSignature, keyEncipherment";
		$lines[]	= "extendedKeyUsage					= serverAuth";
		if ($altGrpName !== null) {
			$lines[]	= "subjectAltName					= @" . $altGrpName;
		}
		
		return $lines;
	}
	private function getClientX509($altGrpName=null)
	{
		$lines[]	= "[ client_cert ]";
		$lines[]	= "basicConstraints					= CA:FALSE";
		$lines[]	= "nsCertType						= client, email";
		$lines[]	= "nsComment						= \"MTM Client Certificate\"";
		$lines[]	= "subjectKeyIdentifier				= hash";
		$lines[]	= "authorityKeyIdentifier			= keyid,issuer";
		$lines[]	= "keyUsage							= critical, nonRepudiation, digitalSignature, keyEncipherment";
		$lines[]	= "extendedKeyUsage					= clientAuth, emailProtection";
		if ($altGrpName !== null) {
			$lines[]	= "subjectAltName					= @" . $altGrpName;
		}
		
		return $lines;
	}
	private function getPolicy($type, $grpName="policy")
	{
		$lines		= array();
		if ($type == "strict") {
			
			//The root CA should only sign intermediate certificates that match.
			$lines[]	= "[ ".$grpName." ]";
			$lines[]	= "countryName			 			= match";
			$lines[]	= "stateOrProvinceName	 			= match";
			$lines[]	= "organizationName					= match";
			$lines[]	= "organizationalUnitName  			= optional";
			$lines[]	= "commonName			  			= supplied";
			$lines[]	= "emailAddress						= optional";
			
		} elseif ($type == "loose") {
			
			//Allow the intermediate CA to sign a more diverse range of certificates.
			$lines[]	= "[ ".$grpName." ]";
			$lines[]	= "countryName					 	= optional";
			$lines[]	= "stateOrProvinceName			 	= optional";
			$lines[]	= "localityName		   				= optional";
			$lines[]	= "organizationName	   		 		= optional";
			$lines[]	= "organizationalUnitName  			= optional";
			$lines[]	= "commonName			 			= supplied";
			$lines[]	= "emailAddress						= optional";
			
		} else {
			throw new \Exception("Invalid type: " . $type);
		}

		return $lines;
	}
	private function getOnlineStatus($altGrpName=null)
	{
		//Extension for OCSP signing certificates (`man ocsp`).
		$lines[]	= "[ ocsp ]";
		$lines[]	= "basicConstraints					= CA:FALSE";
		$lines[]	= "subjectKeyIdentifier				= hash";
		$lines[]	= "authorityKeyIdentifier			= keyid,issuer";
		$lines[]	= "keyUsage							= critical, digitalSignature";
		$lines[]	= "extendedKeyUsage					= critical, OCSPSigning";
		return $lines;
	}
	private function getAltNames($altGrp, $altNames)
	{
		$lines[]	= "[ ".$altGrp." ]";
		$n=0;
		foreach ($altNames as $altName) {
			$n++;
			$lines[]	= "DNS." . $n . "\t\t= " . $altName . "\n";
		}
		return $lines;
	}
	private function stitchSegments($segs=array())
	{
		$lines	= array();
		foreach ($segs as $seg) {
			$lines		= array_merge($lines, $seg);
			$lines[]	= "";
		}
		return $lines;
	}
}