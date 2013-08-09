<?php
    //-------------------------------------------------------------------------------------------------
    // <copyright file="Graph.php" company="Microsoft">
    //     Copyright (c) Microsoft Corporation.  All rights reserved.
    //
    //    Licensed under the Apache License, Version 2.0 (the "License");
    //    you may not use this file except in compliance with the License.
    //    You may obtain a copy of the License at
    //      http://www.apache.org/licenses/LICENSE-2.0
    //
    // THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
    // EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR 
    // CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
    //
    // See the Apache Version 2.0 License for specific language governing 
    // permissions and limitations under the License.
    // </copyright>
    //
    // <summary>
    //     
    //  Facilitates communicating with AAD Graph
    // </summary>
    //-------------------------------------------------------------------------------------------------
    if( !defined( 'MOODLE_INTERNAL' ) )
    {
        die( 'Direct access to this script is forbidden.' );    ///  It must be included from a Moodle page
    }

    require_once ($CFG->libdir . '/moodlelib.php');

/*
    class JWTToken
    {
        // Constanst for header 
        const HEADER_ALG = 'alg';
        const HEADER_ALGNAME = 'HS256';
        const HEADER_TYPE = 'typ';
        const HEADER_TYPENAME = 'JWT';
        const SECS_INDAY = 86400;
        const CLAIM_ISSUER = 'iss';
        const CLAIM_AUD = 'aud';
        const CLAIM_EXP = 'exp';
        const CLAIM_NBF = 'nbf';
        const SIGN_ALGO = 'sha256';
        const CODE_UTC = 'UTC';
        private $_header;
        private $_claims;
        private $_signature;


        static function base64url_encode($data) { 
            return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); 
        } 

        static function hack_json_encode($data)
        {
            $val = json_encode($data);
            // JSON will escape backslashes - unescape those
            $val = str_replace('\\/','/',$val);
            return $val;
        }

        static function base64url_decode($data) { 
            return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT)); 
        } 


        public function __construct($issuerPrincipalId,
            $tenantRealm,
            $audienceHostName,
            $audiencePrincipalId,
            $nbfTime,
            $validityInSeconds,$symmkey)    
        {
            //Create header - consists of token type, algo and cert hash


            $hdr = array(JWTToken::HEADER_TYPE=>JWTToken::HEADER_TYPENAME,JWTToken::HEADER_ALG=>JWTToken::HEADER_ALGNAME);
            $this->_header = JWTToken::base64url_encode(JWTToken::hack_json_encode($hdr));


            //Create claims
            $issuer = $issuerPrincipalId;
            $audience = $audiencePrincipalId.'/'.$audienceHostName.'@'.$tenantRealm;
            $dtz = new DateTimeZone(JWTToken::CODE_UTC);
            if (!isset($nbfTime))
                $nbfTime = new DateTime(NULL,dtz);
            $expTime = clone $nbfTime;    
            $expTime = $expTime->add(new DateInterval("PT".(string)$validityInSeconds."S"));
            //Convert the time into elapsed since 1/1/1970

            $nbfdiffsecs = (string)$nbfTime->getTimestamp();
            $expdiffsecs = (string)$expTime->getTimestamp();
            //$nbfdiffsecs = (string)1351118300;
            //$expdiffsecs = (string)($nbfdiffsecs + 3600);
            $claims = array(JWTToken::CLAIM_AUD=>$audience,JWTToken::CLAIM_ISSUER=>$issuer,JWTToken::CLAIM_NBF=>$nbfdiffsecs,JWTToken::CLAIM_EXP=>$expdiffsecs);
            $this->_claims = JWTToken::base64url_encode(JWTToken::hack_json_encode($claims));    

            //Generate the signature for the token
            $tok = $this->_header.".".$this->_claims;
            //Symmkey is 64bit encoded - get the raw key
            $rawKey = base64_decode($symmkey);

            //Make sure to not get a string but binary data back from hash_hmac for passing to encoder
            $this->_signature = JWTToken::base64url_encode(hash_hmac(JWTToken::SIGN_ALGO,$tok,$rawKey,true));


        }
        function getJWTToken()
        {
            return $this->_header.".".$this->_claims.".".$this->_signature;
        }
    }

    class STSJWTToken extends JWTToken
    {
        //Constants for audience - audience is the graph object 
        const URL_STS = "https://accounts.accesscontrol.windows.net/tokens/OAuth/2";
        const URL_ISSUER = "https://sts.windows.net";
        const URL_STSMETADATA = "https://accounts.accesscontrol.windows.net/FederationMetadata/2007-06/FederationMetadata.xml?realm=";
        const NAME_STS = "accounts.accesscontrol.windows.net";
        const SPN_STS = "00000001-0000-0000-c000-000000000000";
        const NAME_GRAPH = "graph.windows.net";
        const SPN_GRAPH = "00000002-0000-0000-c000-000000000000"; 
        const CLAIM_GRANTTYPE = "grant_type";
        const CLAIM_GRANTVALUE = "http://oauth.net/grant_type/jwt/1.0/bearer";
        const CLAIM_ASSERTION = "assertion";
        const CLAIM_RESOURCE = "resource";
        const BEARER_PREFIX = "Bearer ";
        const OAUTH_ACCESSTOKEN = "access_token";

        public function __construct($issuerPrincipalId,
            $tenantRealm,
            $nbfTime,
            $validityInSeconds,$symmkey)                                                                                                                        
        {
            parent::__construct($issuerPrincipalId,$tenantRealm,STSJWTToken::NAME_STS,STSJWTToken::SPN_STS,$nbfTime,$validityInSeconds,$symmkey);         

        }
        static function getAuthTokenWithSelf($stsURL,$self,$resource)
        {
            //Setup a call to STS 
            $fields = array(STSJWTToken::CLAIM_GRANTTYPE=>STSJWTToken::CLAIM_GRANTVALUE,STSJWTToken::CLAIM_ASSERTION=>$self,STSJWTToken::CLAIM_RESOURCE=>$resource);
            $response = http_post_fields($stsURL, $fields);
            if (!isset($response))
                return null;
            $resparr = http_parse_message($response);
            if (!isset($resparr) || $resparr->responseCode != 200 || !isset($resparr->body))
                return null;
            $respjson = json_decode($resparr->body,true);
            if (!isset($respjson) || !isset($respjson[STSJWTToken::OAUTH_ACCESSTOKEN]))
                return null;
            return STSJWTToken::BEARER_PREFIX.$respjson[STSJWTToken::OAUTH_ACCESSTOKEN];

        }
        static function getAuthToken($stsURL,$resource,$issuerPrincipalId,
            $tenantRealm,
            $nbfTime,
            $validityInSeconds,$symmkey)
        {
            $selftok = new STSJWTToken($issuerPrincipalId,$tenantRealm,$nbfTime,$validityInSeconds,$symmkey);
            if (isset($selftok))
            {
                return STSJWTToken::getAuthTokenWithSelf($stsURL,$selftok->getJWTToken(),$resource);    
            }
            return NULL;

        }
        static function getGraphAuthToken($issuerPrincipalId,
            $tenantRealm,
            $nbfTime,
            $validityInSeconds,$symmkey)

        {
            $graph = STSJWTToken::SPN_GRAPH."/".STSJWTToken::NAME_GRAPH."@".$tenantRealm;
            return STSJWTToken::getAuthToken(STSJWTToken::URL_STS,$graph,$issuerPrincipalId,$tenantRealm,$nbfTime,$validityInSeconds,$symmkey);
        }
    }                                     

*/

    class STSJWTToken
    {
        //Constants for audience - audience is the graph object 
        const URL_STS = "https://login.windows.net/%1/oauth2/token?api-version=1.0";
        const URL_ISSUER = "https://sts.windows.net";
        const URL_STSMETADATA = "https://login.windows.net/%1/2007-06/FederationMetadata.xml";
        const NAME_GRAPHRESOURCE = "https://graph.windows.net";
        const FIELD_CLAIMTYPE = "grant_type";
        const VALUE_CLAIMTYPE = "client_credentials";
        const FIELD_CLIENTID = "client_id";
        const FIELD_CLIENTSECRET = "client_secret";
        const FIELD_RESOURCE = "resource";
        const OAUTH_ACCESSTOKEN = "access_token"; 
        const OAUTH_TOKENTYPE = "token_type";
        
        
        private $_tenantURI;
        private $_clientid;
        private $_clientsecret;
                  
        public function __construct($tenantURI,
            $clientid,$clientsecret)                                                                                                                        
        {
            $this->_tenantURI = $tenantURI;
            $this->_clientid = $clientid;
            $this->_clientsecret = $clientsecret;
        }
        
        function getAccessToken()
        {
          
        
            // set url 
            $stsUrl = STSJWTToken::URL_STS;
            $stsUrl = str_ireplace("%1",$this->_tenantURI,$stsUrl);
            
            
            $fields = array(STSJWTToken::FIELD_CLAIMTYPE=>STSJWTToken::VALUE_CLAIMTYPE,STSJWTToken::FIELD_CLIENTID=>$this->_clientid,STSJWTToken::FIELD_CLIENTSECRET=>$this->_clientsecret,STSJWTToken::FIELD_RESOURCE=>STSJWTToken::NAME_GRAPHRESOURCE);
            $response = http_post_fields($stsUrl, $fields);
            if (!isset($response))
                return null;
            $resparr = http_parse_message($response);
            if (!isset($resparr) || $resparr->responseCode != 200 || !isset($resparr->body))
                return null;
            $respjson = json_decode($resparr->body,true);
            if (!isset($respjson) || !isset($respjson[STSJWTToken::OAUTH_ACCESSTOKEN]))
                return null;
            return $respjson[STSJWTToken::OAUTH_TOKENTYPE].' '.$respjson[STSJWTToken::OAUTH_ACCESSTOKEN];
        }
        static function getAuthTokenWithSelf($stsURL,$self,$resource)
        {
            //Setup a call to STS 
            $fields = array(STSJWTToken::CLAIM_GRANTTYPE=>STSJWTToken::CLAIM_GRANTVALUE,STSJWTToken::CLAIM_ASSERTION=>$self,STSJWTToken::CLAIM_RESOURCE=>$resource);
            $response = http_post_fields($stsURL, $fields);
            if (!isset($response))
                return null;
            $resparr = http_parse_message($response);
            if (!isset($resparr) || $resparr->responseCode != 200 || !isset($resparr->body))
                return null;
            $respjson = json_decode($resparr->body,true);
            if (!isset($respjson) || !isset($respjson[STSJWTToken::OAUTH_ACCESSTOKEN]))
                return null;
            return STSJWTToken::BEARER_PREFIX.$respjson[STSJWTToken::OAUTH_ACCESSTOKEN];

        }
        static function getAuthToken($stsURL,$resource,$issuerPrincipalId,
            $tenantRealm,
            $nbfTime,
            $validityInSeconds,$symmkey)
        {
            $selftok = new STSJWTToken($issuerPrincipalId,$tenantRealm,$nbfTime,$validityInSeconds,$symmkey);
            if (isset($selftok))
            {
                return STSJWTToken::getAuthTokenWithSelf($stsURL,$selftok->getJWTToken(),$resource);    
            }
            return NULL;

        }
        static function getGraphAuthToken($issuerPrincipalId,
            $tenantRealm,
            $nbfTime,
            $validityInSeconds,$symmkey)

        {
            $graph = STSJWTToken::SPN_GRAPH."/".STSJWTToken::NAME_GRAPH."@".$tenantRealm;
            return STSJWTToken::getAuthToken(STSJWTToken::URL_STS,$graph,$issuerPrincipalId,$tenantRealm,$nbfTime,$validityInSeconds,$symmkey);
        }
    }                                     



    /* Gets data back as JSON array by doing a http get request. Retries 2 times and then retries with altURL. $array denotes whether response is an object
    or an array */
    function getHttpJSON($url,$array,$hdr = null,$alturl=null)
    {
        $i = 0;
        while ($i < 3)
        {
            $i++;
            if (($i==2) && isset($alturl))
                $url = $alturl;
            $response = http_get($url,isset($hdr)?array('headers'=>$hdr):NULL,$out);
            if (!isset($response) || ($response == false)  )
                continue;
            $resparr = http_parse_message($response);
            if (!isset($resparr) || $resparr->responseCode != 200 || !isset($resparr->body))
                continue;
            $respjson = json_decode($resparr->body,$array);
            if (!isset($respjson))
                continue;
            return $respjson;   
        }
        return null;
    }
    function getAccessToken()
    {
        $key = get_config('block_azuread','symmkey');
        $appid = get_config('block_azuread','appid');
        $companydomain = get_config('block_azuread','companydomain');

        $tok = new STSJWTToken($companydomain,$appid,$key);
        return $tok->getAccessToken();

    }

    function getJSONResp($tok,$url,$accept,$array=true)
    {
        $compid = get_config('block_azuread','companydomain');
        $URL_GRAPH = "https://graph.windows.net"."/".$compid;        
        $urlsend = $URL_GRAPH.$url;
        if ((strpos($urlsend,"?")))
        {
            $urlsend = $urlsend."&api-version=2013-04-05";
        }else
        {
            $urlsend = $urlsend."?api-version=2013-04-05";
        }
        /*$tok =getAccessToken();*/
        if (!isset($accept))
            $accept = 'application/json;odata=minimalmetadata';

        $headers = array('authorization'=>$tok,'accept'=>$accept);
        $response = getHttpJSON($urlsend,$array,$headers);
        if ($response ==null)
            return null;
        return $response;

    }
    function getUserInfo($userobjid)
    {                    
        $tok = getAccessToken();                          
        $url = "/users/".$userobjid;
        return getJSONResp($tok,$url,null,true);
    }

    function getUserChanges($tok,$skipToken)
    {
        $url = "/directoryObjects";
        if (!empty($skipToken))
            $url.= "?deltaLink=".$skipToken;
        else
          $url.= "?deltaLink=";    
        $url=$url."&\$filter=isof('Microsoft.WindowsAzure.ActiveDirectory.User')";  
        return  getJSONResp($tok,$url,null,true);
    }


?>
