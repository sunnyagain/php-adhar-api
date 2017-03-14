<?php
namespace Sunnyagain\Adhar;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
* Adhar Auth API wrapper
*/
class AdharAuth
{

	/**
	 * debug false;
	**/
	private $_debug;

	/**
	 * certificate file location
	**/
	private $_publicCertPath;
	
	/**
	 * certificate p12 file location
	**/
	private $_p12File;
		
	/**
	 * Defaults to 1.6;
	**/
	private $_apiVersion;
	
	/**
	 * For testing "MH4hSkrev2h_Feu0lBRC8NI-iqzT299_qPSSstOFbNFTwWrie29ThDo"
	**/
	private $_asaLicenceKey;
	
	/**
	 * “License Key For testing "MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg"
	**/
	private $_lk;
	
	/**
	 * Default "public"
	**/
	private $_ac;
	
	/**
	 * Default "public"
	**/
	private $_sa;
	
	/**
	 * Default ""
	**/
	private $_tid;
	
	/**
	 * private key file location
	**/
	private $_privateKeyPath;
	
	/**
	 * private certificate file location
	**/
	private $_privateCertPath;
	
	/**
	 *  AUA specific transaction identifier
	**/
	private $_txn;
	
	/**
	 * Timestamp at the time of capture of authentication input
	 * format “YYYY-MM-DDThh:mm:ss”
	**/
	private $_ts;
	
	/**
	 * Adhar API Auth End point
	 * format “YYYY-MM-DDThh:mm:ss”
	**/
	private $_authEndPoint;
	
	/**
	 * (mandatory) Aadhaar Number of the person being authenticated.
	**/
	private $_uid;
	
	/**
	 * matching strategy.
	**/
	private $_ms;
	
	/**
	 * matching strategy.
	**/
	private $_mv;
	
	/**
	 * matching strategy.
	**/
	private $_name;

	/**
	 * PID block to be sent to AUA server
	**/
	private $_pidBlock;
	
	/**
	 * Encrypted and encoded session key
	**/
	private $_sessionKey;
	
	/**
	 * XML data format for authentication API
	**/
	private $_authXml;
	
	public function __construct($arrData = array())
	{
		if (is_array($arrData)) {
            $this->setOptions($config);
        }
	}

	private function setPublicCertPath($arg){
		$this->_publicCertPath = $arg;
	}

	private function setP12File($arg){
		$this->_p12File = $arg;
	}

	private function setApiVersion($arg){
		$this->_apiVersion = $arg;
	}

	private function setAsaLicenceKey($arg){
		$this->_asaLicenceKey = $arg;
	}

	private function setLk($arg){
		$this->_lk = $arg;
	}

	private function setAc($arg){
		$this->_ac = $arg;
	}

	private function setSa($arg){
		$this->_sa = $arg;
	}

	private function setTid($arg){
		$this->_tid = $arg;
	}

	private function setPrivateKeyPath($arg){
		$this->_privateKeyPath = $arg;
	}

	private function setPrivateCertPath($arg){
		$this->_privateCertPath = $arg;
	}

	private function setTxn($arg){
		$this->_txn = $arg;
	}

	private function setTs($arg){
		$this->_ts = $arg;
	}

	private function setUid($arg){
		$this->_uid = $arg;
	}

	private function setMs($arg){
		$this->_ms = $arg;
	}

	private function setMv($arg){
		$this->_mv = $arg;
	}

	private function setName($arg){
		$this->_name = $arg;
	}

	private function setPidBlock($arg){
		$this->_pidBlock = $arg;
	}

	private function setSessionKey($arg){
		$this->_sessionKey = $arg;
	}

	private function setAuthXml($arg){
		$this->_authXml = $arg;
	}

	private function getPublicCertPath(){
		return $this->_publicCertPath;
	}

	private function getP12File(){
		return $this->_p12File;
	}

	private function getApiVersion(){
		return $this->_apiVersion;
	}

	private function getAsaLicenceKey(){
		return $this->_asaLicenceKey;
	}

	private function getLk(){
		return $this->_lk;
	}

	private function getAc(){
		return $this->_ac;
	}

	private function getSa(){
		return $this->_sa;
	}

	private function getTid(){
		return $this->_tid;
	}

	private function getPrivateKeyPath(){
		return $this->_privateKeyPath;
	}

	private function getPrivateCertPath(){
		return $this->_privateCertPath;
	}

	private function getTxn(){
		return $this->_txn;
	}

	private function getTs(){
		return $this->_ts;
	}

	private function getAuthEndPoint(){
		if(empty($this->_authEndPoint))
		{
			$this->_authEndPoint = $this->_authServer . $this->getApiVersion() . "/" . $this->_uid[0] . "/" . $this->_uid[1] . "/" . $this->getAsaLicenceKey();
		}
		return $this->_authEndPoint;
	}

	private function getUid(){
		return $this->_uid;
	}

	private function getMs(){
		return $this->_ms;
	}

	private function getMv(){
		return $this->_mv;
	}

	private function getName(){
		return $this->_name;
	}

	private function getPidBlock(){
		return $this->_pidBlock;
	}

	private function getSessionKey(){
		if(empty($this->_sessionKey))
		{
			$this->_sessionKey = openssl_random_pseudo_bytes(32);
		}

		return $this->_sessionKey;
	}

	private function getAuthXml($arg){
		$this->_authXml = $arg;
	}

	/**
     * setOptions()
     */
    public function setOptions(Array $options)
    {
        $methods = get_class_methods($this);

        foreach ($options as $key => $value) {
			$key = preg_replace_callback('/_(.)/', function($matches){ return ucfirst($matches[1]); } , $key);
            $method = 'set' . ucfirst($key);
            if (in_array($method, $methods)) {
                $this->_$method($value);
            }
        }
        return $this;
    }

    private function createPidBlock(){
    	$xml = '<?xml version="1.0"?><ns2:Pid ';
    	$xml .= 'ts="'.$this->getTs() .'" '
    	$xml .= 'xmlns:ns2="http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0"><ns2:Demo><ns2:Pi ';
    	$xml .= 'ms="'.$this->getMs().'" ';
    	$xml .= 'mv="'.$this->getMv().'" ';
    	$xml .= 'name="'.$this->getName().'" />';
    	$xml .= '</ns2:Demo></ns2:Pid>';
    	return $xml;
    }

    private function createAuthBlock(){
    	$xml = '<?xml version="1.0"?><Auth ';
    	$xml .= 'ac="'.$this->getAc();
    	$xml .= '" lk="'.$this->getLk();
    	$xml .= '" sa="'.$this->getSa();
    	$xml .= '" tid="'.$this->getTid();
    	$xml .= '" txn="'.$this->getTxn();
    	$xml .= '" uid="'.$this->getUid();
    	$xml .= '" ver="'.$this->getApiVersion();
    	$xml .= '" xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">';
    	$xml .= '<Uses bio="n" otp="n" pa="n" pfa="n" pi="y" pin="n"/><Meta fdc="NA" idc="NA" lot="P" lov="560094" pip="NA" udc="1122"/>';
    	$xml .= '<Skey ci="'.$this->_publicKeyValidity().'">'.$this->_encryptSessionKey().'</Skey>';
    	$xml .= '<Data type="X">'.$this->_encryptedPidBlock().'</Data><Hmac>'.$this->_createHmac().'</Hmac></Auth>';
    	return $xml;
    }

    private function _createHmac(){
    	return $this->_encryptBySessionKey(hash('sha256', $data, true));
    }

    private function _publicKeyValidity()
    {
    	$certinfo = openssl_x509_parse(file_get_contents($this->getPublicCertPath()));
    	return date('Ymd', $certinfo['validTo_time_t']);
    }

	private function _encryptSessionKey()
	{
		$pub_key = openssl_pkey_get_public(file_get_contents($this->getPublicCertPath()));
	    $keyData = openssl_pkey_get_details($pub_key);
	    openssl_public_encrypt($_encryptBySessionKey, $encrypted_session_key, $keyData['key'], OPENSSL_PKCS1_PADDING);
	    return base64_encode($encrypted_session_key);
	}

	private function _encryptedPidBlock()
	{
    	return $this->_encryptBySessionKey($this->createPidBlock());
	}

	private function _encryptBySessionKey($data)
	{
		$blockSize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
	    $pad = $blockSize - (strlen($data) % $blockSize);
	    return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->getSessionKey(), $data . str_repeat(chr($pad), $pad), MCRYPT_MODE_ECB));
	}

	private function createRequestXML()
	{
		$doc = new DOMDocument();
		$objDSig = new XMLSecurityDSig();
		$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type'=>'private'));

		$doc->loadXML($this->createAuthBlock());
		$objDSig->setCanonicalMethod(XMLSecurityDSig::C14N);

		$objDSig->addReference(
		    $doc,
		    XMLSecurityDSig::SHA256,
		    array(
		        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
		        'http://www.w3.org/2001/10/xml-exc-c14n#'
		    ),
		    array('force_uri' => true)
		);

		openssl_pkcs12_read(file_get_contents($this->getP12File()), $key, "public");
		$objKey->loadKey($key["pkey"]);
		$objDSig->add509Cert($key["cert"]);
		$objDSig->sign($objKey, $doc->documentElement);

		return $doc->saveXMl();
	}

	public function authenticate(Array $arrguments)
	{
		if(!empty($arrguments))
		{
			$this->setOptions($arrguments);
		}

		$requestXML = $this->createRequestXML();
		$ch = curl_init($this->getAuthEndPoint());
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $requestXML);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array(
		  "Accept: application/xml",
		  "Content-Type: application/xml"
		));
		return curl_exec($ch);
	}

}