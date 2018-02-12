<?php

require_once('resources/mailing.php');
require_once('resources/Keychain.php');
require_once('User.php');
require_once('Plant.php');

class Site
{
//PRIVATE VARS
	private $id;							//INT
	private $creator;							//User object
	private $name;					//STRING			email that has been signed up for but not necessarilly verified
	private $description;
	private $latitude;
	private $longitude;
	private $region;
	private $saltedPasswordHash;			//STRING			salted hash of password
	private $salt;							//STRING
	private $openToPublic;
	
	private $deleted;

//FACTORY
	public static function create($creator, $name, $description, $latitude, $longitude, $zoom, $region, $password, $openToPublic) {
		$dbconn = (new Keychain)->getDatabaseConnection();
		if(!$dbconn){
			return "Cannot connect to server.";
		}
		
		$validNameFormat = self::validNameFormat($dbconn, $name);
		$name = self::validName($dbconn, $name);
		$description = self::validDescription($dbconn, $description);
		$latitude = self::validLatitude($dbconn, $latitude);
		$longitude = self::validLongitude($dbconn, $longitude);
		$zoom = self::validZoom($dbconn, $zoom);
		$region = self::validRegion($dbconn, $region);
		$isWater = self::validLandPoint($dbconn, $latitude, $longitude, $zoom);
		$password = self::validPassword($dbconn, $password);
		$openToPublic = filter_var($openToPublic, FILTER_VALIDATE_BOOLEAN);
		
		$failures = "";
		
		if($name === false){
			if($validNameFormat === false){
				$failures .= "Enter a site name. ";
			}
			else{
				$failures .= "That site name is already in use. Choose a different one. ";
			}
		}
		if($description === false){
			$failures .= "Site description must be between 1 and 255 characters. ";
		}
		if($latitude === false){
			$failures .= "Latitude is invalid. ";
		}
		if($longitude === false){
			$failures .= "Longitude is invalid. ";
		}
		if($zoom === false){
			$failures .= "Zoom in more on map to select a more accurate location. ";
		}
		if(!($latitude === false || $longitude === false || $zoom === false) && !$isWater){
			$failures .= "Site location must be on land. ";
		}
		if($password === false){
			$failures .= "Password must be at least 4 characters with no spaces. ";
		}
		if($creator->passwordIsCorrect($password)){
			$failures .= "Password cannot be the same as your Caterpillars Count! account password because you may be sharing it with vistors at this site. ";
		}
		
		if($failures != ""){
			return $failures;
		}
		
		$salt = mysqli_real_escape_string($dbconn, hash("sha512", rand() . rand() . rand()));
		$saltedPasswordHash = mysqli_real_escape_string($dbconn, hash("sha512", $salt . $password));
		
		mysqli_query($dbconn, "INSERT INTO Site (`UserFKOfCreator`, `Name`, `Description`, `Latitude`, `Longitude`, `Region`, `Salt`, `SaltedPasswordHash`, `OpenToPublic`) VALUES ('" . $creator->getID() . "', '$name', '$description', '$latitude', '$longitude', '$region', '$salt', '$saltedPasswordHash', '$openToPublic')");
		$id = intval(mysqli_insert_id($dbconn));
		mysqli_close($dbconn);
		
		$publicPrivateString = "Private";
		if($openToPublic){$publicPrivateString = "Public";}
		email("plocharczykweb@gmail.com", "New Site Created", "<html> <head> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <style> body{ margin:0px; } table{ font-size:20px; } td{ padding:20px; box-sizing:border-box; word-break: break-word; } td:nth-of-type(2){ color:#777; } @media only screen and (max-width: 500px){ table{ font-size:16px; } } @media only screen and (max-width: 400px){ table{ font-size:13px; } } </style> </head> <body> <div style=\"padding:20px;text-align:center;border-radius:5px;font-family:'Segoe UI', Frutiger, 'Frutiger Linotype', 'Dejavu Sans', 'Helvetica Neue', Arial, sans-serif;\"> <div style=\"text-align:left;color:#777;margin-bottom:40px;font-size:20px;\"> <table style=\"width:100%;table-layout: fixed;border-collapse:collapse;background:#f7f7f7;font-family:'Segoe UI', Frutiger, 'Frutiger Linotype', 'Dejavu Sans', 'Helvetica Neue', Arial, sans-serif;color:#555;\"> <tr> <td colspan=\"2\" style=\"padding:0px;\"><iframe src=\"//www.google.com/maps/embed/v1/place?q=30,-70&zoom=17&key=AIzaSyCb2j5kS5bTHwCt32eZObS642NKiM6MPZY\" style=\"border:0px;width:100%;height:300px;\"></iframe></td> </tr> <tr> <td>Name: </td> <td>" . $name . "</td> </tr> <tr> <td>Description: </td> <td>" . $description . "</td> </tr> <tr> <td>Region: </td> <td>" . $region . "</td> </tr> <tr> <td>Coordinates: </td> <td><a href=\"https://www.google.com/maps/search/?api=1&query=" . $latitude . "," . $longitude . "\" style=\"color:#70c6ff;\">" . $latitude . "," . $longitude . "</a></td> </tr> <tr> <td>Visibility: </td> <td>" . $publicPrivateString . "</td> </tr> <tr> <td>Created by: </td> <td>" . $creator->getFullName() . "</td> </tr> <tr> <td>Email: </td> <td><a href=\"mailto:" . $creator->getEmail() . "\" style=\"color:#70c6ff;\">" . $creator->getEmail() . "</a></td> </tr> </table> </div> </div> </body></html>");
		return new Site($id, $creator, $name, $description, $latitude, $longitude, $region, $salt, $saltedPasswordHash, $openToPublic);
	}
	private function __construct($id, $creator, $name, $description, $latitude, $longitude, $region, $salt, $saltedPasswordHash, $openToPublic) {
		$this->id = intval($id);
		$this->creator = $creator;
		$this->name = $name;
		$this->description = $description;
		$this->latitude = $latitude;
		$this->region = $region;
		$this->longitude = $longitude;
		$this->salt = $salt;
		$this->saltedPasswordHash = $saltedPasswordHash;
		$this->openToPublic = $openToPublic;
		
		$this->deleted = false;
	}

//FINDERS
	public static function findByID($id) {
		$dbconn = (new Keychain)->getDatabaseConnection();
		$id = mysqli_real_escape_string($dbconn, $id);
		$query = mysqli_query($dbconn, "SELECT * FROM `Site` WHERE `ID`='$id' LIMIT 1");
		mysqli_close($dbconn);
		
		if(mysqli_num_rows($query) == 0){
			return null;
		}
		
		$siteRow = mysqli_fetch_assoc($query);
		
		$creator = User::findByID($siteRow["UserFKOfCreator"]);
		$name = $siteRow["Name"];
		$description = $siteRow["Description"];
		$latitude = $siteRow["Latitude"];
		$longitude = $siteRow["Longitude"];
		$region = $siteRow["Region"];
		$salt = $siteRow["Salt"];
		$saltedPasswordHash = $siteRow["SaltedPasswordHash"];
		$openToPublic = $siteRow["OpenToPublic"];
		
		return new Site($id, $creator, $name, $description, $latitude, $longitude, $region, $salt, $saltedPasswordHash, $openToPublic);
	}
	
	public static function findByName($name) {
		$dbconn = (new Keychain)->getDatabaseConnection();
		$name = self::validNameFormat($dbconn, $name);
		if($name === false){
			return null;
		}
		$query = mysqli_query($dbconn, "SELECT `ID` FROM `Site` WHERE `Name`='$name' LIMIT 1");
		mysqli_close($dbconn);
		if(mysqli_num_rows($query) == 0){
			return null;
		}
		return self::findByID(intval(mysqli_fetch_assoc($query)["ID"]));
	}
	
	public static function findSitesByCreator($creator){
		$dbconn = (new Keychain)->getDatabaseConnection();
		$query = mysqli_query($dbconn, "SELECT * FROM `Site` WHERE `UserFKOfCreator`='" . $creator->getID() . "'");
		mysqli_close($dbconn);
		
		$sitesArray = array();
		while($siteRow = mysqli_fetch_assoc($query)){
			$id = $siteRow["ID"];
			$name = $siteRow["Name"];
			$description = $siteRow["Description"];
			$latitude = $siteRow["Latitude"];
			$longitude = $siteRow["Longitude"];
			$region = $siteRow["Region"];
			$salt = $siteRow["Salt"];
			$saltedPasswordHash = $siteRow["SaltedPasswordHash"];
			$openToPublic = $siteRow["OpenToPublic"];
			$site = new Site($id, $creator, $name, $description, $latitude, $longitude, $region, $salt, $saltedPasswordHash, $openToPublic);
			
			array_push($sitesArray, $site);
		}
		return $sitesArray;
	}
	
	public static function findAllPublicSites(){
		$dbconn = (new Keychain)->getDatabaseConnection();
		$query = mysqli_query($dbconn, "SELECT * FROM `Site` WHERE `OpenToPublic`='1'");
		mysqli_close($dbconn);
		
		$sitesArray = array();
		while($siteRow = mysqli_fetch_assoc($query)){
			$id = $siteRow["ID"];
			$creator = User::findByID($siteRow["UserFKOfCreator"]);
			$name = $siteRow["Name"];
			$description = $siteRow["Description"];
			$latitude = $siteRow["Latitude"];
			$longitude = $siteRow["Longitude"];
			$region = $siteRow["Region"];
			$salt = $siteRow["Salt"];
			$saltedPasswordHash = $siteRow["SaltedPasswordHash"];
			$site = new Site($id, $creator, $name, $description, $latitude, $longitude, $region, $salt, $saltedPasswordHash, true);
			
			array_push($sitesArray, $site);
		}
		return $sitesArray;
	}
	
	public static function findAll(){
		$dbconn = (new Keychain)->getDatabaseConnection();
		$query = mysqli_query($dbconn, "SELECT `ID` FROM `Site`");
		mysqli_close($dbconn);
		
		$sitesArray = array();
		while($siteRow = mysqli_fetch_assoc($query)){
			$site = self::findByID($siteRow["ID"]);
			array_push($sitesArray, $site);
		}
		return $sitesArray;
	}

//GETTERS
	public function getID() {
		if($this->deleted){return null;}
		return intval($this->id);
	}
	
	public function getCreator() {
		if($this->deleted){return null;}
		return $this->creator;
	}
	
	public function getName() {
		if($this->deleted){return null;}
		return $this->name;
	}
	
	public function getDescription() {
		if($this->deleted){return null;}
		return $this->description;
	}
	
	public function getLatitude() {
		if($this->deleted){return null;}
		return $this->latitude;
	}
	
	public function getLongitude() {
		if($this->deleted){return null;}
		return $this->longitude;
	}
	
	public function getRegion() {
		if($this->deleted){return null;}
		return $this->region;
	}
	
	public function getPlants(){
		if($this->deleted){return null;}
		return Plant::FindPlantsBySite($this);
	}
	
	public function getSaltedHash($password){
		if($this->deleted){return null;}
		if($this->passwordIsCorrect($password)){
			return $this->saltedPasswordHash;
		}
		return false;
	}
	
	public function getOpenToPublic(){
		if($this->deleted){return null;}
		return filter_var($this->openToPublic, FILTER_VALIDATE_BOOLEAN);
	}
	
	public function getObservationMethodPreset($user){
		$dbconn = (new Keychain)->getDatabaseConnection();
		$query = mysqli_query($dbconn, "SELECT `ObservationMethod` FROM `SiteUserPreset` WHERE `UserFK`='" . intval($user->getID()) . "' AND `SiteFK`='" . $this->id . "' LIMIT 1");
		mysqli_close($dbconn);
		if(mysqli_num_rows($query) == 0){
			return "";
		}
		return mysqli_fetch_assoc($query)["ObservationMethod"];
	}
	
	public function getValidationStatus($user){
		$dbconn = (new Keychain)->getDatabaseConnection();
		$query = mysqli_query($dbconn, "SELECT `ID` FROM `SiteUserValidation` WHERE `UserFK`='" . intval($user->getID()) . "' AND `SiteFK`='" . $this->id . "' AND `SaltedSitePasswordHash`='" . $this->saltedPasswordHash . "' LIMIT 1");
		mysqli_close($dbconn);
		if(mysqli_num_rows($query) == 0){
			return false;
		}
		return true;
	}
	
//SETTERS
	public function setPassword($password) {
		if(!$this->deleted)
		{
			$dbconn = (new Keychain)->getDatabaseConnection();
			$password = self::validPassword($dbconn, $password);
			if($password != false){
				$saltedPasswordHash = mysqli_real_escape_string($dbconn, hash("sha512", $this->salt . $password));
				mysqli_query($dbconn, "UPDATE Site SET SaltedPasswordHash='$saltedPasswordHash' WHERE ID='" . $this->id . "'");
				mysqli_close($dbconn);
				$this->saltedPasswordHash = $saltedPasswordHash;
				return true;
			}
			mysqli_close($dbconn);
		}
		return false;
	}
	
	public function setObservationMethodPreset($user, $observationMethod){
		if($this->deleted){return false;}
		$dbconn = (new Keychain)->getDatabaseConnection();
		$query = mysqli_query($dbconn, "SELECT `ID` FROM `SiteUserPreset` WHERE `UserFK`='" . intval($user->getID()) . "' AND `SiteFK`='" . $this->id . "' LIMIT 1");
		if(mysqli_num_rows($query) == 1){
			$query = mysqli_query($dbconn, "UPDATE `SiteUserPreset` SET `ObservationMethod`='" . $observationMethod . "' WHERE `UserFK`='" . intval($user->getID()) . "' AND `SiteFK`='" . $this->id . "'");
			mysqli_close($dbconn);
			return true;
		}
		mysqli_query($dbconn, "INSERT INTO `SiteUserPreset`(`UserFK`, `SiteFK`, `ObservationMethod`) VALUES ('" . intval($user->getID()) . "', '" . $this->id . "', '" . $observationMethod . "')");
		mysqli_close($dbconn);
		return true;
	}
	
	public function addCircle(){
		if(!$this->deleted)
		{
			$numberOfPreexistingCircles = (count($this->getPlants()) / 5);
			Plant::create($this, ($numberOfPreexistingCircles + 1), "A");
			Plant::create($this, ($numberOfPreexistingCircles + 1), "B");
			Plant::create($this, ($numberOfPreexistingCircles + 1), "C");
			Plant::create($this, ($numberOfPreexistingCircles + 1), "D");
			Plant::create($this, ($numberOfPreexistingCircles + 1), "E");
			return true;
		}
		return false;
	}
	
	public function validateUser($user, $password){
		if($this->deleted){return false;}
		$dbconn = (new Keychain)->getDatabaseConnection();
		$query = mysqli_query($dbconn, "SELECT `ID` FROM `SiteUserValidation` WHERE `UserFK`='" . intval($user->getID()) . "' AND `SiteFK`='" . $this->id . "' AND `SaltedSitePasswordHash`='" . $this->saltedPasswordHash . "' LIMIT 1");
		if(mysqli_num_rows($query) == 1){
			mysqli_close($dbconn);
			return true;
		}
		else if($this->passwordIsCorrect($password)){
			mysqli_query($dbconn, "INSERT INTO `SiteUserValidation`(`UserFK`, `SiteFK`, `SaltedSitePasswordHash`) VALUES ('" . intval($user->getID()) . "', '" . $this->id . "', '" . $this->saltedPasswordHash . "')");
			mysqli_close($dbconn);
			return true;
		}
		mysqli_close($dbconn);
		return false;
	}
	
	
//REMOVER
	public function permanentDelete()
	{
		if(!$this->deleted)
		{
			$dbconn = (new Keychain)->getDatabaseConnection();
			mysqli_query($dbconn, "DELETE FROM `Site` WHERE `ID`='" . $this->id . "'");
			$this->deleted = true;
			mysqli_close($dbconn);
			return true;
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

//validity ensurance
	public static function validName($dbconn, $name){
		$name = self::validNameFormat($dbconn, $name);
		if($name === false || is_object(self::findByName($name))){
			return false;
		}
		return $name;
	}
	
	public static function validNameFormat($dbconn, $name){
		$name = mysqli_real_escape_string($dbconn, $name);
		
		if($name == ""){
			return false;
		}
		return $name;
	}
	
	public static function validDescription($dbconn, $description){
		$description = mysqli_real_escape_string($dbconn, $description);
		
		if(strlen($description) == 0 || strlen($description) > 255){
			return false;
		}
		return $description;
	}
	
	public static function validLatitude($dbconn, $latitude){
		$latitude = floatval(mysqli_real_escape_string($dbconn, preg_replace("/[^0-9.-]/", "", trim((string)$latitude))));
		if(abs($latitude) > 90){
			return false;
		}
		return $latitude;
	}
	
	public static function validLongitude($dbconn, $longitude){
		$longitude = floatval(mysqli_real_escape_string($dbconn, preg_replace("/[^0-9.-]/", "", trim((string)$longitude))));
		if(abs($longitude) > 180){
			return false;
		}
		return $longitude;
	}
	
	public static function validZoom($dbconn, $zoom){
		$zoom = intval(mysqli_real_escape_string($dbconn, preg_replace("/[^0-9]/", "", trim((string)$zoom))));
		if($zoom < 10){
			return false;
		}
		return $zoom;
	}
	
	public static function validRegion($dbconn, $region){
		$region = mysqli_real_escape_string($dbconn, $region);
		return $region;
	}
	
	public static function validLandPoint($dbconn, $latitude, $longitude, $zoom){
		$latitude = self::validLatitude($dbconn, $latitude);
		$longitude = self::validLongitude($dbconn, $longitude);
		$zoom = self::validZoom($dbconn, $zoom);
		
		if($latitude === false || $longitude === false || $zoom === false){
			return false;
		}
		
		$imgurl = "http://maps.googleapis.com/maps/api/staticmap?center=" . $latitude . "," . $longitude . "&zoom=" . $zoom . "&size=99x99&maptype=roadmap&sensor=false&style=element:labels|visibility:off&style=element:geometry.stroke|visibility:off&style=feature:landscape|element:geometry|saturation:-100&style=feature:water|saturation:-100|invert_lightness:true";
		$pathname = "images/map/lastCall.png";
		copy($imgurl, $pathname);
		return (imagecolorat(imagecreatefrompng($pathname) , 50, 50) > 7);
	}
	
	public static function validPassword($dbconn, $password){
		$spacelessPassword = mysqli_real_escape_string($dbconn, preg_replace('/ /', '', (string)$password));
		
		if(strlen($password) != strlen($spacelessPassword) || strlen($spacelessPassword) < 4){
			return false;
		}
		return $password;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

//FUNCTIONS
	public function emailPlantCodesToCreator(){
		$dbconn = (new Keychain)->getDatabaseConnection();
		//$headers  = 'MIME-Version: 1.0' . "\r\n";
		//$headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";

		//TODO
		$plants = $this->getPlants();
		$numberOfCircles = (count($plants) / 5);
		$root = (new Keychain)->getRoot();
		$message = "<div style=\"text-align:center;border-radius:5px;padding:20px;font-family:'Segoe UI', Frutiger, 'Frutiger Linotype', 'Dejavu Sans', 'Helvetica Neue', Arial, sans-serif;\"><div style=\"text-align:left;color:#777;margin-bottom:40px;font-size:20px;\">Congratulations on creating your new Caterpillars Count! site, \"" . $this->name . "\". Once you have located and identified your survey branches, you can click the \"Edit Survey Plants\" button on the <a href=\"" . $root . "/manageMySites\" style=\"color:#70c6ff;\">Manage My Sites</a> page of the website to enter the tree species names for each survey.<br/><br/>You can then <a href=\"" . $root . "/php/printPlantCodes.php?q=" . $this->id . "\" style=\"color:#70c6ff;\">click here</a> to print the Survey Plant Code tags to hang on each survey branch. (We recommend printing in color, then \"laminating\" by folding each tag in a strip of packing tape, then hanging by twist tie or other means.)<br/><br/>If you have entered the plant species names for each survey using the web link above, they will appear on the tags. Otherwise, the plant species will be listed as \"N/A\".</div><a href=\"" . $root . "/manageMySites\"><button style=\"border:0px none transparent;background:#fed136; border-radius:5px;padding:20px 40px;font-size:20px;color:#fff;font-family:'Segoe UI', Frutiger, 'Frutiger Linotype', 'Dejavu Sans', 'Helvetica Neue', Arial, sans-serif;font-weight:bold;cursor:pointer;\">MANAGE MY SITES</button></a><div style=\"padding-top:40px;margin-top:40px;margin-left:-40px;margin-right:-40px;border-top:1px solid #eee;color:#bbb;font-size:14px;\"><div>Alternatively, use this link and then click \"Edit Survey Plants\" to enter the tree species names for each survey: <a href=\"" . $root . "/manageMySites\" style=\"color:#70c6ff;\">" . $root . "/manageMySites</a></div><div>And then use this link to print the tags for your new site: <a href=\"" . $root . "/php/printPlantCodes.php?q=" . $this->id . "\" style=\"color:#70c6ff;\">" . $root . "/php/printPlantCodes.php?q=" . $this->id . "</a></div></div></div>";
		email($this->creator->getEmail(), "Your new Caterpillars Count! site", $message);//, $headers);
		
		mysqli_close($dbconn);
		return true;
	}
	
	public function passwordIsCorrect($password){
		$dbconn = (new Keychain)->getDatabaseConnection();
		$testSaltedPasswordHash = mysqli_real_escape_string($dbconn, hash("sha512", $this->salt . $password));
		if($testSaltedPasswordHash == $this->saltedPasswordHash){
			mysqli_close($dbconn);
			return true;
		}
		mysqli_close($dbconn);
		return false;
	}
}		
?>
