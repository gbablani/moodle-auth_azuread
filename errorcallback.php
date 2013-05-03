<html>
    <head>
        <title>Login Error
        </title>
    </head>
    <body>
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
            require_once(dirname(__FILE__).'/../../config.php');
    require_once( $CFG->dirroot . '/blocks/azuread/block_azuread.php' );

            $tok = $_POST['ErrorDetails'];
            $resp = json_decode($tok);
            if (isset($resp))
            {
                $lo = false;
                echo "Traceid: ". $resp->traceId."\n";
                $errorcode = get_signoutURL($signOutURL);

                foreach ($resp->errors as $e)
                {
                    if ($e == "ACS20016")
                    {
                        $lo = true;
                        if (!isset($errorcode))
                        {
                            echo "<p>".$errorcode."</p>";
                            echo "<p>The Office 365 account you are logged does not have an account in moodle. Please close your browser and login again</p>";
                        }
                        else
                        {
                            echo "<p>The Office 365 account you are logged does not have an account in moodle.</p>";
                            echo "<a href=".$signOutURL.">Click here to logout and sign in with an Office 365 account that is enabled for Moodle</a>";
                        }
                    }
                }

            }
            /* In all cases success or failure send user back to page they came from */
            if (!isset($lo)){
                if (!empty($SESSION->wantsurl)) {
                    $go = $SESSION->wantsurl;
                    unset($SESSION->wantsurl);
                }
                if (!isset($go))
                    $go = $CFG->wwwroot;

                echo "Please click on <a href=$go>Home Page</a> to go back";
            }
        ?>
    </body>
</html>
