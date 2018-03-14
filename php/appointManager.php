<?php
  	header('Access-Control-Allow-Origin: *');
	
	require_once('orm/User.php');
	require_once('orm/Site.php');
	
  	$siteID = $_GET["siteID"];
  	$managerEmail = $_GET["managerEmail"];
	$email = $_GET["email"];
	$salt = $_GET["salt"];
	
	$user = User::findBySignInKey($email, $salt);
	if(is_object($user) && get_class($user) == "User"){
    		$site = Site::findByID($siteID);
    		if(is_object($site) && get_class($site) == "Site" && $user->getID() == $site->getCreator()->getID()){
      			$manager = User::findByEmail($managerEmail);
      			if(is_object($manager) && get_class($manager) == "User"){
        			if($site->appointManager($manager)){
          				die("true|");
       				}
        			die("false|You are the creator of this site. There is no need to also appoint yourself as a manager.");
      			}
      			die("false|There is no Caterpillars Count! user associated with that email address.");
    		}
    		die("false|You did not create this site, so you cannot oversee its management.");
  	}
  	die("false|Your log in dissolved. Maybe you logged in on another device.");
?>
