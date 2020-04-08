### What is this?

A way to create and work with certificates


#### Create a new self signed root CA
```
$keyObj		= \MTM\Encrypt\Factories::getRSA()->getTool()->createPrivateKey(4096);
$csrObj		= \MTM\Certs\Factories::getTools()->getCSR()->get($keyObj, "My Company Root CA", "My Company", "My Company Certificate Authority", "US", "FL", "Tampa", "certificates@mycompany.com");
$caObj			= \MTM\Certs\Factories::getTools()->getCRT()->getCA($csrObj, 7300);
```
#### Make a Intermediate Certificate, signed by the root cert
```
$keyObj		= \MTM\Encrypt\Factories::getRSA()->getTool()->createPrivateKey(4096);
$csrObj		= \MTM\Certs\Factories::getTools()->getCSR()->get($keyObj, "My Company Intermediate", "My Company", "My Company Certificate Authority", "US", "FL", "Tampa", "certificates@mycompany.com");
$iCaObj		= \MTM\Certs\Factories::getTools()->getCRT()->getIntermediateCA($csrObj, $caObj, 7300);
```
#### Make a Server Certificate, signed by the intermediate cert
```
$keyObj		= \MTM\Encrypt\Factories::getRSA()->getTool()->createPrivateKey(2048);
$csrObj		= \MTM\Certs\Factories::getTools()->getCSR()->get($keyObj, "server1.mycompany.com", "My Company", "My Company Certificate Authority", "US", "FL", "Tampa", "certificates@mycompany.com");
$sCrtObj	= \MTM\Certs\Factories::getTools()->getCRT()->getServerCRT($csrObj, $iCaObj, 7300, array("server111.mycompany.com"));
```
		
#### Make a Client Certificate, signed by the intermediate cert
```
$keyObj		= \MTM\Encrypt\Factories::getRSA()->getTool()->createPrivateKey(2048);
$csrObj		= \MTM\Certs\Factories::getTools()->getCSR()->get($keyObj, "client1.mycompany.com", "My Company", "My Company Certificate Authority", "US", "FL", "Tampa", "certificates@mycompany.com");
$cCrtObj		= \MTM\Certs\Factories::getTools()->getCRT()->getClientCRT($csrObj, $iCaObj, 7300, array("client11.mycompany.com"));
```
