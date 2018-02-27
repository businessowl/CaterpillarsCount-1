<?php
	header('Access-Control-Allow-Origin: *');
	
	require_once('orm/User.php');
	require_once('orm/Site.php');
	
	$email = $_GET["email"];
	$salt = $_GET["salt"];
	
	$user = User::findBySignInKey($email, $salt);
	if(is_object($user) && get_class($user) == "User"){
		$sites = $user->getSites();
		$sitesArray = array();
		for($i = 0; $i < count($sites); $i++){
			$sitesArray[$i] = array(
				"creator" => $sites[$i]->getCreator()->getEmail(),
				"name" => $sites[$i]->getName(),
				"description" => $sites[$i]->getDescription(),
				"latitude" => $sites[$i]->getLatitude(),
				"longitude" => $sites[$i]->getLongitude(),
				"region" => $sites[$i]->getRegion(),
				"plantCount" => count($sites[$i]->getPlants()),
				"id" => $sites[$i]->getID(),
				"openToPublic" => $sites[$i]->getOpenToPublic(),
			);
		}
		die("true|" . json_encode($sitesArray));
	}
	die("false|Your log in dissolved. Maybe you logged in on another device.");
?>
