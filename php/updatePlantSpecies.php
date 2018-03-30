<?php
	header('Access-Control-Allow-Origin: *');
	
	require_once('orm/User.php');
	require_once('orm/Plant.php');
	
	$email = $_GET["email"];
	$salt = $_GET["salt"];
	$plantData = json_decode($_GET["plantData"]);
	
	$user = User::findBySignInKey($email, $salt);
	if(is_object($user) && get_class($user) == "User"){
		if(count($plantData) < 1){
			die("false|No data provided.");
		}
		if(count($plantData[0]) < 1){
			die("false|Improperly formatted data provided.");
		}
		$plant = Plant::findByCode($plantData[0][0]);
		if(!is_object($plant) || get_class($plant) != "Plant"){
			die("false|Plant with code \"" . $plantData[0][0] . "\" could not be found.");
		}
		$site = $plant->getSite();
		if(!is_object($site) || get_class($site) != "Site"){
			die("false|Could not find site associated with these plants.");
		}
		if(!in_array($site, $user->getSites())){
			die("false|You do not have permission to edit the plants in this site.");
		}
		
		$plants = $site->getPlants();
		$associativePlants = array();
		for($i = 0; $i < count($plants); $i++){
			$associativePlants[$plants->getCode()] = $plants[$i];
		}
		
		for($i = 0; $i < count($plantData); $i++){
			if(count($plantData[$i]) == 2){
				if(array_key_exists($plantData[$i][0], $associativePlants)){
					$plant = $associativePlants[$plantData[$i][0]];
					if(is_object($plant) && get_class($plant) == "Plant"){
						$plant->setSpecies($plantData[$i][1]);
					}
					else{die("false|Plant with code \"" . $plantData[$i][0] . "\" could not be found in the \"" . $site->getName() . "\" site.");}
				}
				else{die("false|Plant with code \"" . $plantData[$i][0] . "\" could not be found in the \"" . $site->getName() . "\" site.");}
			}
			else{die("false|Improperly formatted data provided.");}
		}
		die("true|");
	}
	die("false|Your log in dissolved. Maybe you logged in on another device.");
?>
