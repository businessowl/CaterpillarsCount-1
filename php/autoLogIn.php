<?php
	require_once("orm/User.php");
	$user = User::findBySignInKey($_GET["email"], $_GET["salt"]);
	if(!is_null($user) && get_class($user) == "User"){
		die("true");
	}
	die("false");
?>
