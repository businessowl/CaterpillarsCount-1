<?php

require_once('resources/mailing.php');
require_once('resources/Keychain.php');
require_once('Site.php');

class User
{
//PRIVATE VARS
	private $id;							//INT
	private $firstName;
	private $lastName;
	private $desiredEmail;					//STRING			email that has been signed up for but not necessarilly verified
	private $email;							//STRING			*@*.*, MUST GET VERIFIED
	private $saltedPasswordHash;			//STRING			salted hash of password
	private $salt;							//STRING
	
	private $deleted;

//FACTORY
	public static function create($firstName, $lastName, $email, $password) {
		$dbconn = (new Keychain)->getDatabaseConnection();
		if(!$dbconn){
			return "Cannot connect to server.";
		}
		
		$firstName = self::validFirstName($dbconn, $firstName);
		$lastName = self::validLastName($dbconn, $lastName);
		$desiredEmail = self::validEmail($dbconn, $email);
		$password = self::validPassword($dbconn, $password);
		
		$failures = "";
		
		if($firstName === false && strlen($firstName > 0)){
			$failures .= "Enter a shorter version of your first name. ";
		}
		else if($firstName === false){
			$failures .= "Enter your first name. ";
		}
		
		if($lastName === false && strlen($lastName > 0)){
			$failures .= "Enter a shorter version of your last name. ";
		}
		else if($lastName === false){
			$failures .= "Enter your last name. ";
		}
		
		if($desiredEmail === false){
			if(filter_var(filter_var($email, FILTER_SANITIZE_EMAIL), FILTER_VALIDATE_EMAIL) === false){
				$failures .= "Invalid email. ";
			}
			else{
				$failures .= "That email is already attached to an account. ";
			}
		}
		if($password === false){
			$failures .= "Password must be at least 8 characters with no spaces. ";
		}
		
		if($failures != ""){
			return $failures;
		}
		
		$salt = mysqli_real_escape_string($dbconn, hash("sha512", rand() . rand() . rand()));
		$saltedPasswordHash = mysqli_real_escape_string($dbconn, hash("sha512", $salt . $password));
		
		mysqli_query($dbconn, "INSERT INTO User (`FirstName`, `LastName`, `DesiredEmail`, `Salt`, `SaltedPasswordHash`) VALUES ('$firstName', '$lastName', '$desiredEmail', '$salt', '$saltedPasswordHash')");
		$id = intval(mysqli_insert_id($dbconn));
		mysqli_close($dbconn);
		
		return new User($id, $firstName, $lastName, $desiredEmail, "", $salt, $saltedPasswordHash);
	}
	private function __construct($id, $firstName, $lastName, $desiredEmail, $email, $salt, $saltedPasswordHash) {
		$this->id = intval($id);
		$this->firstName = $firstName;
		$this->lastName = $lastName;
		$this->desiredEmail = $desiredEmail;
		$this->email = $email;
		$this->salt = $salt;
		$this->saltedPasswordHash = $saltedPasswordHash;
		
		$this->deleted = false;
	}	

//FINDERS
	public static function findByID($id) {
		$dbconn = (new Keychain)->getDatabaseConnection();
		$id = mysqli_real_escape_string($dbconn, $id);
		$query = mysqli_query($dbconn, "SELECT * FROM `User` WHERE `ID`='$id' LIMIT 1");
		mysqli_close($dbconn);
		
		if(mysqli_num_rows($query) == 0){
			return null;
		}
		
		$userRow = mysqli_fetch_assoc($query);
		
		$firstName = $userRow["FirstName"];
		$lastName = $userRow["LastName"];
		$desiredEmail = $userRow["DesiredEmail"];
		$email = $userRow["Email"];
		$salt = $userRow["Salt"];
		$saltedPasswordHash = $userRow["SaltedPasswordHash"];
		
		return new User($id, $firstName, $lastName, $desiredEmail, $email, $salt, $saltedPasswordHash);
	}
	
	public static function findByEmail($email) {
		$dbconn = (new Keychain)->getDatabaseConnection();
		$email = self::validEmailFormat($dbconn, $email);
		if($email === false){
			return null;
		}
		$query = mysqli_query($dbconn, "SELECT `ID` FROM `User` WHERE `Email`='$email' LIMIT 1");
		mysqli_close($dbconn);
		if(mysqli_num_rows($query) == 0){
			return null;
		}
		return self::findByID(intval(mysqli_fetch_assoc($query)["ID"]));
	}
	
	public static function findBySignInKey($email, $salt){
		$dbconn = (new Keychain)->getDatabaseConnection();
		$email = self::validEmailFormat($dbconn, $email);
		if($email === false){
			return null;
		}
		$query = mysqli_query($dbconn, "SELECT `ID` FROM `User` WHERE `Email`='" . $email . "' AND `Salt`='" . $salt . "' LIMIT 1");
		mysqli_close($dbconn);
		if(mysqli_num_rows($query) == 0){
			return null;
		}
		return self::findByID(intval(mysqli_fetch_assoc($query)["ID"]));
	}
	
//SIGNERS
	public function signIn($password){
		$dbconn = (new Keychain)->getDatabaseConnection();
		if(!$this->deleted && $this->EmailHasBeenVerified()){
			$password = rawurldecode($password);
			if($this->passwordIsCorrect($password)){
				//sign in
				$salt = mysqli_real_escape_string($dbconn, hash("sha512", rand() . rand() . rand()));
				$saltedPasswordHash = mysqli_real_escape_string($dbconn, hash("sha512", $salt . $password));
				
				
				mysqli_query($dbconn, "UPDATE User SET `Salt`='$salt', `SaltedPasswordHash`='$saltedPasswordHash' WHERE `ID`='" . $this->id . "'");
				mysqli_close($dbconn);
				
				$this->salt = $salt;
				$this->saltedPasswordHash = $saltedPasswordHash;
				return $salt;
			}
			mysqli_close($dbconn);
			return false;
		}
	}
	
//GETTERS
	public function getID() {
		if($this->deleted){return null;}
		return intval($this->id);
	}
	
	public function getFirstName() {
		if($this->deleted){return null;}
		return $this->firstName;
	}
	
	public function getLastName() {
		if($this->deleted){return null;}
		return $this->lastName;
	}
	
	public function getFullName() {
		if($this->deleted){return null;}
		return $this->firstName . " " . $this->lastName;
	}
	
	public function getDesiredEmail() {
		if($this->deleted){return null;}
		return $this->desiredEmail;
	}
	
	public function getEmail() {
		if($this->deleted){return null;}
		return $this->email;
	}
	
	public function getSites(){
		if($this->deleted){return null;}
		
		//Super users
		if($this->email == "plocharczykweb@gmail.com" || $this->email == "hurlbert@bio.unc.edu"){
			return Site::findAll();
		}
		
		//Temporarily hard-coded Managers
		$temporarilyManagedSites = array();
		
		//"UNC Chapel Hill Campus" Managers
		if($this->email == "ssnell@live.unc.edu" || $this->email == "gdicecco@live.unc.edu"){
			$temporarilyManagedSites[] = Site::findByName("UNC Chapel Hill Campus");
		}
		
		//"GSM Institute at Tremont (TN)" Managers
		if($this->email == "science@gsmit.org"){
			$temporarilyManagedSites[] = Site::findByName("GSM Institute at Tremont");
		}
		
		//"East Carolina University (NC)" Managers
		if($this->email == "ecu.caterpillarscount@gmail.com" || $this->email == "vancechalcrafth@ecu.edu" || $this->email == "bunnella@ecu.edu" || $this->email == "dowa05@students.ecu.edu" || $this->email == "stanoe@ecu.edu"){
			$temporarilyManagedSites[] = Site::findByName("East Carolina University");
		}
		
		//Everyone else
		$managedSites = Site::findManagedSitesByManager($this);
		$ownedSites = Site::findSitesByCreator($this);
		return array_merge($ownedSites, $managedSites, $temporarilyManagedSites);
	}
	
	public function getValidationStatus($site){
		if($this->deleted){return null;}
		if(!is_object($site) || get_class($site) != "Site"){return false;}
		return $site->getValidationStatus($this);
	}
	
	public function getObservationMethodPreset($site){
		if($this->deleted){return null;}
		if(!is_object($site) || get_class($site) != "Site"){return false;}
		return $site->getObservationMethodPreset($this);
	}
	
//SETTERS
	public function setFirstName($firstName){
		if(!$this->deleted){
			$dbconn = (new Keychain)->getDatabaseConnection();
			$firstName = self::validFirstName($dbconn, $firstName);
			if($firstName !== false){
				mysqli_query($dbconn, "UPDATE User SET FirstName='$firstName' WHERE ID='" . $this->id . "'");
				mysqli_close($dbconn);
				$this->firstName = $firstName;
				return true;
			}
			mysqli_close($dbconn);
		}
		return false;
	}
	
	public function setLastName($lastName){
		if(!$this->deleted){
			$dbconn = (new Keychain)->getDatabaseConnection();
			$lastName = self::validLastName($dbconn, $lastName);
			if($lastName !== false){
				mysqli_query($dbconn, "UPDATE User SET LastName='$lastName' WHERE ID='" . $this->id . "'");
				mysqli_close($dbconn);
				$this->lastName = $lastName;
				return true;
			}
			mysqli_close($dbconn);
		}
		return false;
	}
	
	public function setEmail($email) {
		if(!$this->deleted){
			$dbconn = (new Keychain)->getDatabaseConnection();
			$email = self::validEmail($dbconn, $email);
			if($email !== false){
				mysqli_query($dbconn, "UPDATE User SET DesiredEmail='$email' WHERE ID='" . $this->id . "'");
				mysqli_close($dbconn);
				$this->desiredEmail = $email;
				self::sendEmailVerificationCodeToUser($this->id);
				return true;
			}
			mysqli_close($dbconn);
		}
		return false;
	}
	
	public function setPassword($password) {
		if(!$this->deleted){
			$dbconn = (new Keychain)->getDatabaseConnection();
			$password = self::validPassword($dbconn, $password);
			if($password !== false){
				$saltedPasswordHash = mysqli_real_escape_string($dbconn, hash("sha512", $this->salt . $password));
				mysqli_query($dbconn, "UPDATE User SET SaltedPasswordHash='$saltedPasswordHash' WHERE ID='" . $this->id . "'");
				mysqli_close($dbconn);
				$this->saltedPasswordHash = $saltedPasswordHash;
				return true;
			}
			mysqli_close($dbconn);
		}
		return false;
	}
	
	public function setValidStatus($site, $password){
		if($this->deleted){return null;}
		if(!is_object($site) || get_class($site) != "Site"){return false;}
		$password = rawurldecode($password);
		return $site->validateUser($this, $password);
	}
	
	public function setObservationMethodPreset($site, $observationMethod){
		if($this->deleted){return null;}
		if(!is_object($site) || get_class($site) != "Site"){return false;}
		$observationMethod = rawurldecode($observationMethod);
		return $site->setObservationMethodPreset($this, $observationMethod);
	}
	
	
//REMOVER
	public function permanentDelete()
	{
		if(!$this->deleted)
		{
			$dbconn = (new Keychain)->getDatabaseConnection();
			mysqli_query($dbconn, "DELETE FROM `User` WHERE `ID`='" . $this->id . "'");
			$this->deleted = true;
			mysqli_close($dbconn);
			return true;
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

//validity ensurance
	public static function validFirstName($dbconn, $firstName){
		$firstName = mysqli_real_escape_string($dbconn, ucfirst(trim(rawurldecode($firstName))));
		if(strlen($firstName) == 0 || strlen($firstName) > 255){
			return false;
		}
		return $firstName;
	}
	
	public static function validLastName($dbconn, $lastName){
		$lastName = mysqli_real_escape_string($dbconn, ucfirst(trim(rawurldecode($lastName))));
		if(strlen($lastName) == 0 || strlen($lastName) > 255){
			return false;
		}
		return $lastName;
	}
	
	public static function validEmail($dbconn, $email){
		$email = filter_var(rawurldecode($email), FILTER_SANITIZE_EMAIL);
		
		if (!filter_var($email, FILTER_VALIDATE_EMAIL) === false && mysqli_num_rows(mysqli_query($dbconn, "SELECT `ID` FROM `User` WHERE `Email`='" . $email . "' LIMIT 1")) == 0) {
			return mysqli_real_escape_string($dbconn, $email);
		}
		return false;
	}
	
	public static function validEmailFormat($dbconn, $email){
		$email = filter_var(rawurldecode($email), FILTER_SANITIZE_EMAIL);
		
		if (!filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
			return mysqli_real_escape_string($dbconn, $email);
		}
		return false;
	}
	
	public static function validPassword($dbconn, $password){
		$password = rawurldecode((string)$password);
		$spacelessPassword = mysqli_real_escape_string($dbconn, preg_replace('/ /', '', $password));
		
		if(strlen($password) != strlen($spacelessPassword) || strlen($spacelessPassword) < 8){
			return false;
		}
		return $password;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

//FUNCTIONS
	public function createSite($name, $description, $latitude, $longitude, $zoom, $location, $password, $openToPublic){
		return Site::create($this, $name, $description, $latitude, $longitude, $zoom, $location, $password, $openToPublic);
	}
	
	public static function sendEmailVerificationCodeToUser($usersId){
		$verificationCode = (string)rand(0, 9) . rand(0, 9) . rand(0, 9) . rand(0, 9);
		
		$dbconn = (new Keychain)->getDatabaseConnection();
		$usersId = mysqli_real_escape_string($dbconn, $usersId);
		$query = mysqli_query($dbconn, "SELECT `DesiredEmail` FROM `User` WHERE `ID`='$usersId' LIMIT 1");
		if(mysqli_num_rows($query) == 0){
			mysqli_close($dbconn);
			return false;
		}
		$usersEmail = mysqli_fetch_assoc($query)["DesiredEmail"];
		mysqli_query($dbconn, "UPDATE User SET `EmailVerificationCode`='$verificationCode' WHERE `ID`='$usersId'");
		
		$confirmationLink = hash("sha512", self::findByID($usersId)->getDesiredEmail() . "jisabfa") . "c" . intval($usersId . $verificationCode) * 7;
		
		email($usersEmail, "Verify your email for Caterpillars Count!", "<div style=\"text-align:center;padding:20px;font-family:'Segoe UI', Frutiger, 'Frutiger Linotype', 'Dejavu Sans', 'Helvetica Neue', Arial, sans-serif;\"><div style=\"color:#777;margin-bottom:40px;font-size:20px;\">Welcome to Caterpillars Count! You need to verify your email before you can use your account. Click the following button to confirm your email address.</div><a href=\"" . (new Keychain)->getRoot() . "/php/verifyemail.php?confirmation=$confirmationLink\"><button style=\"border:0px none transparent;background:#fed136; border-radius:5px;padding:20px 40px;font-size:20px;color:#fff;font-family:'Segoe UI', Frutiger, 'Frutiger Linotype', 'Dejavu Sans', 'Helvetica Neue', Arial, sans-serif;font-weight:bold;cursor:pointer;\">VERIFY EMAIL</button></a><div style=\"padding-top:40px;margin-top:40px;margin-left:-40px;margin-right:-40px;border-top:1px solid #eee;color:#bbb;font-size:14px;\">Alternatively, use link: <a href=\"" . (new Keychain)->getRoot() . "/php/verifyemail.php?confirmation=$confirmationLink\" style=\"color:#70c6ff;\">" . (new Keychain)->getRoot() . "/php/verifyemail.php?confirmation=$confirmationLink</a></div></div>");
		
		mysqli_close($dbconn);
		return true;
	}
	
	public function verifyEmail($verificationCode){
		$dbconn = (new Keychain)->getDatabaseConnection();
		$verificationCode = mysqli_real_escape_string($dbconn, rawurldecode($verificationCode));
		
		if(self::validEmail($dbconn, $this->desiredEmail) === false){
			return false;
		}
		
		$query = mysqli_query($dbconn, "SELECT `EmailVerificationCode` FROM `User` WHERE `ID`='" . $this->id . "' LIMIT 1");
		if(mysqli_num_rows($query) == 0){
			mysqli_close($dbconn);
			return false;
		}
		$usersEmailVerificationCode = mysqli_fetch_assoc($query)["EmailVerificationCode"];
		if($verificationCode == $usersEmailVerificationCode){
			mysqli_query($dbconn, "UPDATE User SET `Email`=`DesiredEmail` WHERE `ID`='" . $this->id . "'");
			mysqli_query($dbconn, "UPDATE User SET `EmailVerificationCode`='' WHERE `ID`='" . $this->id . "'");
			mysqli_close($dbconn);
			return true;
		}
		mysqli_close($dbconn);
		return false;
	}
	
	public function emailHasBeenVerified() {
		if($this->deleted){return null;}
		$dbconn = (new Keychain)->getDatabaseConnection();
		$query = mysqli_query($dbconn, "SELECT `Email` FROM `User` WHERE `ID`='" . $this->id . "' LIMIT 1");
		if(mysqli_num_rows($query) == 0){
			mysqli_close($dbconn);
			return false;
		}
		$usersEmail = mysqli_fetch_assoc($query)["Email"];
		return ($usersEmail != "");
	}
	
	public static function emailIsUnvalidated($desiredEmail) {
		$dbconn = (new Keychain)->getDatabaseConnection();
		$desiredEmail = self::validEmailFormat($dbconn, $desiredEmail);
		if($desiredEmail === false){
			return false;
		}
		$query = mysqli_query($dbconn, "SELECT `ID` FROM `User` WHERE `DesiredEmail`='$desiredEmail' LIMIT 1");
		mysqli_close($dbconn);
		if(mysqli_num_rows($query) == 0){
			return false;
		}
		return true;
	}
	
	public function passwordIsCorrect($password){
		$password = rawurldecode($password);
		$dbconn = (new Keychain)->getDatabaseConnection();
		$testSaltedPasswordHash = mysqli_real_escape_string($dbconn, hash("sha512", $this->salt . $password));
		if($testSaltedPasswordHash == $this->saltedPasswordHash){
			mysqli_close($dbconn);
			return true;
		}
		mysqli_close($dbconn);
		return false;
	}
	
	public function recoverPassword(){
		if($this->email != ""){
			$newPassword = bin2hex(openssl_random_pseudo_bytes(4));
			$this->setPassword($newPassword);
			email($this->email, "Caterpillars Count! password recovery", "Per your request, we here at Caterpillars Count! have reset the password associated with your email (" . $this->email . ") to: " . $newPassword . "\n\nPlease log in now and reset your password to something memorable. Thank you for using Caterpillars Count!");
			return true;
		}
		return false;
	}
}		
?>
