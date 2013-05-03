<?php

    /*******************************************************************************
    Copyright (C) 2009  Microsoft Corporation. All rights reserved.
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    *******************************************************************************/

    if( !defined( 'MOODLE_INTERNAL' ) )
    {
        die( 'Direct access to this script is forbidden.' );    ///  It must be included from a Moodle page
    }

    require_once( $CFG->dirroot . '/auth/azuread/utils.php' );
    require_once( $CFG->dirroot . '/auth/azuread/graph.php' );
    require_once( $CFG->libdir . '/authlib.php' );
    require_once ($CFG->libdir . '/moodlelib.php');

    /**
    * The auth_plugin_azuread class extends auth_plugin_base and provides azureAD authentication
    */

    if (!isset($_AzureADSecret)){
        /* Generate a random number for the key and covert to string*/
        $keyno = rand(1000000,PHP_INT_MAX);
        $_AzureADSecret =  (string) $keyno;
    } 
    class auth_plugin_azuread extends auth_plugin_base
    {

        /**
        * class constructor
        */
        function auth_plugin_azuread()
        {


            $this->authtype = 'azuread';
            $this->config = get_config( 'auth/azuread' );
            $pluginconfig = $this->config;
            foreach ($this->userfields as $field) {

                // Define some vars we'll work with
                if (!isset($pluginconfig->{"field_map_$field"})) {
                    $this->config->{"field_map_$field"} = '';
                }
                if (!isset($pluginconfig->{"field_updatelocal_$field"})) {
                    $this->config->{"field_updatelocal_$field"} = 'onlogin';
                }
                if (!isset($pluginconfig->{"field_updateremote_$field"})) {
                    $this->config->{"field_updateremote_$field"} = '';
                }
                if (!isset($pluginconfig->{"field_lock_$field"})) {
                    $this->config->{"field_lock_$field"} = 'unlockedifempty';
                }
            }

        }    

        function config_form($config, $err, $user_fields) {
            include 'config.html';
        }

        /**
        * Processes and stores configuration data for this authentication plugin.
        *
        * @param array $config
        * @return void
        */
        function process_config($config) {
            return true;
        }

        /* Should passwords be stored in Moodle */
        function prevent_local_passwords() {
            return true;
        }

        /**
        * Returns true if the username and password work and false if they are
        * wrong or don't exist.
        * @global <array> $CFG - the global configuration array
        * @param <string> $userName - the user name of the current user
        * @param <string> $password - the password of the current user
        * @return <bool> (success/failure)
        */

        function user_login( $userName, $password )
        {
            global $_AzureADSecret;
            /* The only time we should successfully log is when the user is logged in thru the logincallback.php 
            which will pass AzureADSecurt as the password*/


            if (isset($_AzureADSecret) && ($password == $_AzureADSecret))
                return true;
            else
                return false;   

        }
        /**
        * Provides cron services for the Azure AD Plug-in for Moodle block
        * @global <array> $CFG - the global configuration array
        */

        function sync_users()
        {
            global $disallowsync;
            if (!isset($disallowsync))
            {
                $disallowsync = get_config('block_azuread','azureadNotDoSync');
            }
            if ($disallowsync)
                return;
            
            /* First get the sync-token so that we get incremental chanegs only*/
            $skipToken = null;
            $azureadSyncToken = get_config('block_azuread','azureadSyncToken');
            if( $azureadSyncToken == "") 
                $azureadSyncToken = null;
            $tok = getAccessToken();
            $done = false;     
            do
            {
                $res = getUserChanges($tok,$azureadSyncToken);
                if (!isset($res)) 
                    return;
                /* Okay we have some changes. Note that the changes may already have been perfomed by us and so we have to make sure that they 
                are performed in an idempotent fashion*/
                foreach ($res['value'] as $change)
                {
                    $type = $change['odata.type'];
                    if (strtolower($type) == strtolower("Microsoft.WindowsAzure.ActiveDirectory.User")){

                        /* We only care about user objects*/
                        if (strtolower($change['objectType']) != strtolower('User'))
                            continue;
                        $upn = $change['objectId'];  
                        $user = get_complete_user_data('username',$upn);
                        if (isset($change['aad.isDeleted']))
                            $del =   $change['aad.isDeleted'];
                        if (!isset($del) || ($del==false)){
                            /* Eiter create or update */
                            if ($user != false){
                                $user = update_user_record($upn);
                                if (!isset($user)) 
                                    mtrace("AzureAD Sync: Error,Could not update user ".$upn);
                            }else{
                                $user = create_user_record($upn,"",'azuread');    
                                if (!isset($user)) 
                                    mtrace("AzureAD Sync: Error,Could not create user ".$upn);
                            }

                        }else{
                            /* Delete this sucker if he exists*/
                            if ($user == false){
                                mtrace("AzureADSync : Warning,Tried to delete already deleted user".$upn);
                                continue;
                            }
                            delete_user($user);    
                        }
                    }
                }
                if (isset($res['aad.nextLink']))
                    $azureadSyncToken = $res['aad.nextLink'];
                else
                    $azureadSyncToken = null;    
                if (!isset($azureadSyncToken) || empty($azureadSyncToken))
                {
                    $skipToken = $res['aad.deltaLink'];
                    $skipToken = substr($skipToken,strpos($skipToken,"deltaLink=")+strlen("deltaLink="));
                    $done = true;
                }
                else{
                    $done = false;
                }
            } while ($done == false);
            /* We reached here. If there is a skiptoken commit it*/
            if (isset($skipToken) && !empty($skipToken))
            {
                set_config('azureadSyncToken',$skipToken,'block_azuread');
            }
            return;

        }
        function cron(){
            $this->sync_users();
        }                  
        /* This function syncs up the users in Moodle DB to users in AzureAD*/



        function get_userinfo($userName)
        {                                 
            $res = getUserInfo($userName);
            if (!isset($res))
                return array();
            $info = array();
            /* Walk thru all the foelds set in the config for AzureAD and push them into info*/ 
            $info['firstname']  = $res['givenName'];
            $info['lastname']  = $res['surname'];
            $info['email']  = $res['userPrincipalName'];
            $info['city']  = $res['city'];
            $info['country']  = $res['country'];
            $info['description']  = $res['displayName'];
            $info['department']  = $res['department'];
            $info['phone1']  = $res['telephoneNumber'];
            $info['phone2']  = $res['mobile'];
            $info['address']  = $res['streetAddress']." ".$res['city']." ".$res['state']." ".$res['postalCode'];


            return $info;    
        }




        /**
        * We are not implementing the ability to update the password. Password updates
        * are controlled by Windows Live
        * @return <bool> - always false
        */
        function user_update_password( $user, $newpassword )
        {
            return false;
        }

        /**
        * Returns true if this authentication plugin is 'internal', false if 'external'
        * Since Windows Live is external, we return false.
        * @return <bool> - always false
        */
        function is_internal()
        {
            return false;
        }

        /**
        * eturns true if this authentication plugin can change the user's password.
        * @return <bool> - always false
        */
        function can_change_password()
        {
            return false;
        }

        /**
        * Returns the URL for changing the user's pw, or empty if the default can be used.
        * @return <string> - always empty
        */
        function change_password_url()
        {
            return '';
        }

        /**
        * Returns true if plugin allows resetting of internal password.
        * @return <bool> - always false
        */
        function can_reset_password()
        {
            return false;
        }

        /**
        * function that is called before logging out of Moodle
        * redirect to liveid logout if the webauthtoken is not empty
        * @global <array> $CFG - the global configuration array
        */
        function prelogout_hook()
        {
            global $USER; 

            unset($USER->aaduser);
        }
    } 

?>
