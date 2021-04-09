<?php
    $ip = $_SERVER['REMOTE_ADDR'];
    $fullhost = gethostbyaddr($ip);
    $host = preg_replace("/^[^.]+./", "*.", $fullhost);
?>

<strong>IP address <?=$ip?> | Host: <?=$host?> | Ticket# ANTI-ROBOTS-Bad 
<META HTTP-EQUIV=Refresh CONTENT="3; URL=https://yt3.ggpht.com/a/AGF-l7-BBIcC888A2qYc3rB44rST01IEYDG3uzbU_A=s48-c-k-c0xffffffff-no-rj-mo">



// *************************************************************************************************
// *************************************************************************************************
// **************************************  IMPORTANTE  *********************************************




$directory = $_SERVER['DOCUMENT_ROOT'] . '/simulador/';




// **************************************  IMPORTANTE  *********************************************
// *************************************************************************************************
// *************************************************************************************************


// Establish file path and name of the text file
// Establecer la ruta del archivo y el nombre del archivo de texto
$filename1 = $directory . 'robotfile.txt';


 
//  Extract the details of the the rogue robot hit 
//  Extrae los detalles del golpe del robot rebelde
$useragent = getenv("HTTP_USER_AGENT");
if ($useragent == "") { $useragent = "** unspecified **"; }
$ipaddress = getenv("REMOTE_ADDR");
$domainname = GetHostByAddr($ipaddress);
if ($domainname == "") {$domainname = "** unresolved **";}

//  Get the current date and time details
//  Obtener los detalles de fecha y hora actuales
	// Zona horaria del servidor
	date_default_timezone_set("America/New_York");
$date = date ('d/m/Y H:i:s');

//  Append the information to the robot file with the fields separated by a "|" character
//  Añade la información al archivo del robot con los campos separados por "|" carácter
$fp = fopen ($filename1, 'a+'); 
fwrite ($fp, "$date|$ipaddress|$domainname|$useragent|\n"); 
fclose ($fp);



//  Disabled Send the mail message to say that a robot has been trapped.
//  Desactivado Envía el mensaje de correo para decir que un robot ha sido atrapado.
$message  = "The following user agent has fallen into the robot trap: \n\n";
$message  = "  Date:           $date \n";
$message .= "  IP address:     $ipaddress \n";
$message .= "  Domain name:    $domainname \n";
$message .= "  User agent :    $useragent \n";


// Exit the transaction
exit;
?>





<?php
// Script escrito por by Noel
// VIDEO GUIDE - http://www.
// ----------------------------------------------------------------------------------------
// Obtain user agent which is a long string not meant for human reading
$agent = $_SERVER['HTTP_USER_AGENT']; 
// Get the user Browser now -----------------------------------------------------
// Create the Associative Array for the browsers we want to sniff out
$browserArray = array(
        'Windows Mobile'            => 'IEMobile',
        'Vivaldi'                   => 'Vivaldi',
	'Android Mobile'            => 'Android',
	'iPhone Mobile'             => 'iPhone',
	'Firefox'                   => 'Firefox',
        'Chrome o Vivaldi'          => 'Chrome',
        'Internet Explorer'         => 'MSIE',
        'Opera'                     => 'Opera',
        'Safari'                    => 'Safari',
        'motorola'                  => 'Motorola',        
        'nokia'                     => 'Nokia',        
        'palm' 	                    => 'Palm',        
        'iphone'                    => 'Apple iPhone',        
        'ipad' 	                    => 'iPad',        
        'ipod' 	                    => 'Apple iPod Touch',        
        'sony' 	                    => 'Sony Ericsson',        
        'ericsson'                  => 'Sony Ericsson',        
        'blackberry'                => 'BlackBerry',        
        'cocoon'                    => 'O2 Cocoon',        
        'blazer'                    => 'Treo',        
        'lg' 	                    => 'LG',        
        'amoi' 	                    => 'Amoi',        
        'xda' 	                    => 'XDA',        
        'mda' 	                    => 'MDA',        
        'vario'                     => 'Vario',        
        'htc' 	                    => 'HTC',        
        'samsung'                   => 'Samsung',        
        'sharp'                     => 'Sharp',        
        'sie-' 	                    => 'Siemens',        
        'alcatel'                   => 'Alcatel',        
        'benq' 	                    => 'BenQ',        
        'ipaq' 	                    => 'HP iPaq',        
        'mot-' 	                    => 'Motorola',        
        'playstation portable'      => 'PlayStation Portable',        
        'hiptop'                    => 'Danger Hiptop',        
        'nec-' 	                    => 'NEC',        
        'panasonic'                 => 'Panasonic',        
        'philips'                   => 'Philips',        
        'sagem' 	            => 'Sagem',        
        'sanyo' 	            => 'Sanyo',        
        'spv' 	                    => 'SPV',        
        'zte' 	                    => 'ZTE',        
        'sendo' 	            => 'Sendo',        
        'obigo'                     => 'Obigo',        
        'netfront'	            => 'Netfront Browser',        
        'openwave'	            => 'Openwave Browser',        
        'mobilexplorer'             => 'Mobile Explorer',        
        'operamini'	            => 'Opera Mini',        
        'opera mini'	            => 'Opera Mini',        
        'digital paths'	            => 'Digital Paths',        
        'avantgo'	            => 'AvantGo',        
        'xiino'		            => 'Xiino',        
        'novarra'	            => 'Novarra Transcoder',        
        'vodafone'	            => 'Vodafone',        
        'docomo'	            => 'NTT DoCoMo',        
        'o2'		            => 'O2',        
        'mobile'                    => 'Generic Mobile',        
        'wireless'                  => 'Generic Mobile',        
        'j2me'                      => 'Generic Mobile',        
        'midp'                      => 'Generic Mobile',        
        'cldc'                      => 'Generic Mobile',        
        'up.link'                   => 'Generic Mobile',        
        'up.browser'                => 'Generic Mobile',        
        'smartphone'                => 'Generic Mobile',        
        'cellphone'                 => 'Generic Mobile',        
); 
foreach ($browserArray as $k => $v) {
    if (preg_match("/$v/", $agent)) {
         break;
    }	else {
	 $k = "Navegador Desconocido";
    }
} 
$browser = $k;
// Get the user OS now ------------------------------------------------------------
// Create the Associative Array for the Operating Systems to sniff out
$osArray = array(
        'Windows 98'          => '(Win98)|(Windows 98)',
        'Windows 2000'        => '(Windows 2000)|(Windows NT 5.0)',
	'Windows ME'          => 'Windows ME',
        'Windows XP'          => '(Windows XP)|(Windows NT 5.1)',
        'Windows Vista'       => 'Windows NT 6.0',
        'Windows 7'           => '(Windows NT 6.1)|(Windows NT 7.0)',
        'Windows NT 4.0'      => '(WinNT)|(Windows NT 4.0)|(WinNT4.0)|(Windows NT)',
	'Linux'               => '(X11)|(Linux)',
        'Mac OS'              => '(Mac_PowerPC)|(Macintosh)|(Mac OS)',
        'windows nt 6.0'      => 'Windows Longhorn',
	'windows nt 5.2'      => 'Windows 2003',
	'windows nt 5.0'      => 'Windows 2000',
	'windows nt 5.1'      => 'Windows XP',
	'windows nt 4.0'      => 'Windows NT 4.0',
	'winnt4.0'            => 'Windows NT 4.0',
	'winnt 4.0'           => 'Windows NT',
	'winnt'	              => 'Windows NT',
	'windows 98'          => 'Windows 98',
	'win98'	              => 'Windows 98',
	'windows 95'          => 'Windows 95',
        'win95'               => 'Windows 95',
        'os x'                => 'Mac OS X',
        'ppc mac'             => 'Power PC Mac',
	'freebsd'             => 'FreeBSD',
	'ppc'                 => 'Macintosh',
	'linux'               => 'Linux',
	'debian'              => 'Debian',
	'sunos'               => 'Sun Solaris',
	'beos'                => 'BeOS',
	'apachebench'         => 'ApacheBench',
	'aix'                 => 'AIX',
	'irix'                => 'Irix',
	'osf'                 => 'DEC OSF',
	'hp-ux'               => 'HP-UX',
	'netbsd'              => 'NetBSD',
	'bsdi'                => 'BSDi',
	'openbsd'             => 'OpenBSD',
        'gnu'                 => 'GNU Linux',
        'unix'                => 'Unknown Unix OS',
); 
foreach ($osArray as $k => $v) {
    if (preg_match("/$v/", $agent)) {
         break;
    }	else {
	 $k = "Sistema Operativo Desconocido";
    }
} 
$os = $k;

?>



<?php
/*
* Getting MAC Address
* 
*/

ob_start(); // Turn on output buffering --- Activar el almacenamiento en b�fer de salida
system('ipconfig /all'); //Execute external program to display output -- Ejecute un programa externo para mostrar la salida
$mycom=ob_get_contents(); // Capture the output into a variable  --  Capture la salida en una variable
ob_clean(); // Clean (erase) the output buffer

$findme = "Physical";
$pmac = strpos($mycom, $findme); // Find the position of Physical text -- Encuentra la posici�n del texto f�sico
$mac3=substr($mycom,($pmac+36),17); // Get Physical Address -- Obtener direcci�n f�sica

echo $mac3;
?>

<?php
 
//IP Grabber
 
//Variables

ob_start(); // Turn on output buffering
system('ipconfig /all'); //Execute external program to display output -- Ejecute un programa externo para mostrar la salida
$mycom=ob_get_contents(); // Capture the output into a variable  --  Capture la salida en una variable
ob_clean(); // Clean (erase) the output buffer -- Limpiar (borrar) el b�fer de salida
 


function get_client_ip() {
	$ipaddress = '';
	if (getenv('HTTP_CLIENT_IP'))
		$ipaddress = getenv('HTTP_CLIENT_IP');
  
	else if(getenv('HTTP_X_FORWARDED_FOR'))
		$ipaddress = getenv('HTTP_X_FORWARDED_FOR');
  
	else if(getenv('HTTP_X_FORWARDED'))
		$ipaddress = getenv('HTTP_X_FORWARDED');
  
	else if(getenv('HTTP_FORWARDED_FOR'))
		$ipaddress = getenv('HTTP_FORWARDED_FOR');
  
	else if(getenv('HTTP_FORWARDED'))
	   $ipaddress = getenv('HTTP_FORWARDED');
  
	else if(getenv('REMOTE_ADDR'))
		$ipaddress = getenv('REMOTE_ADDR');
	else
		$ipaddress = 'UNKNOWN';
	if (strpos($ipaddress, ",") !== false) :
	  $ipaddress = strtok($ipaddress, ",");
	endif;
	return $ipaddress;
  }
  
  function get_public_ip(){
	$externalContent = file_get_contents('http://checkip.dyndns.com/');
	preg_match('/Current IP Address: \[?([:.0-9a-fA-F]+)\]?/', $externalContent, $m);
	$externalIp = $m[1];
	return $externalIp;
  }
  
  $theIP = get_client_ip();
  $theExternalIP = get_public_ip();
$protocol = $_SERVER['SERVER_PROTOCOL'];
$ip = $_SERVER['REMOTE_ADDR'];
$port = $_SERVER['REMOTE_PORT'];
$os = $k;
$agent = $_SERVER['HTTP_USER_AGENT'];
$ref = $_SERVER['HTTP_REFERER'];
$mac = system('arp -a');
$mac1 = ob_get_contents();
$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);
 
//  Print IP, Hostname, Port Number, User Agent and Referer To Log.TXT
//  Imprimir IP, nombre de host, n�mero de puerto, agente de usuario y referencia para iniciar sesi�n.TXT
//  Obtener los detalles de fecha y hora actuales
//  Get current date and time details
	// Zona horaria del servidor
	date_default_timezone_set("America/New_York");
$date = date ('d/m/Y H:i:s');

 
$fh = fopen('log.txt', 'a');
fwrite($fh, 'IP Address Local: '."".$ip ."\n");
fwrite($fh, 'ISP Web: '."".$theExternalIP ."\n");
fwrite($fh, 'Hos Local: '."".$hostname ."\n");
fwrite($fh, 'Date: '."".$date ."\n");
fwrite($fh, 'Port Number: '."".$port ."\n");
fwrite($fh, 'Operating System: '."".$os ."\n");
fwrite($fh, 'User Agent: '."".$agent ."\n");
fwrite($fh, 'HTTP Referer: '."".$ref ."\n");
fwrite($fh, 'Physical Mac: '."".$mac3 ."\n");
fwrite($fh, 'Subnet Mask: '."".$mac ."\n");
fwrite($fh, 'WIRELESS Mac: '."".$mac1 ."\n*****************************************************\r\n");
fclose($fh);
?>



<?
/*
Programmed by Ing. Inoel Garcial, info@miapk.app, LINK1 https://www.miapk.app LINK1
Author: Ing. Inoel Garcia, 2019-09-10
Exclusively published on miapk.app.
Exclusivamente publicado el miapk.app.
If you like my scripts, please let me know or link to me.
Si te gusta mi script, por favor h�gamelo saber o enlace a m� web. 

You may copy, redistirubte, change and alter my scripts as long as this information remains intact
Puede copiar, distribuir, cambiar y alterar mi guiones, siempre y cuando esta informaci�n se mantiene intacta
*/


$length        =    6; // Must be a multiple of 2 !! So 14 will work, 15 won't, 16 will, 17 won't and so on

// Ticket generation
    $conso=array("1","2","3","4","5","6","7","8","9",
    "10","11","12","13","14","15","16","17","18","19","20");
    $vocal=array("1","2","3","4","5");
    $password="";
    srand ((double)microtime()*1000000);
    $max = $length/2;
    for($i=1; $i<=$max; $i++)
    {
    $password.=$conso[rand(0,19)];
    $password.=$vocal[rand(0,4)];
    }
    $newpass = $password;
// ENDE Ticket generation
    echo $newpass."<p>";

?>

<?php
// 0. author: Ing. Inoel Garcia, 2019-09-10
// 1. gesti�n del plato fuerte Contador de Visitantas
// 2. Env�a un correo electr�nico cuando la p�gina es visitada por un Visitante
// 3. El correo electr�nico contendr� informaci�n diversa sobre el visitante.
// 4. A�adir� esta directiva
// 5. Visitante: Al Concurso EXCLUSIVO - Contador de Visitantas $ip' ($ip siendo la direcci�n IP del visitante)
// 6. escribir� la ip en su archivo. index.html y ( host.txt file detallado. )


// SERVER VARIABLES USED TO IDENTIFY THE OFFENDING BOT
// Variables del servidor utilizada para identificar al Visitante.

$ip = $_SERVER['REMOTE_ADDR'];
$agent = $_SERVER['HTTP_USER_AGENT'];
$request = $_SERVER['REQUEST_URI'];
$referer = $_SERVER['HTTP_REFERER'];
$host = $_SERVER['HTTP_HOST'];
$newpass = $newpass;
$remote = $fullhost = gethostbyaddr($ip);


// CONSTRUCT THE EMAIL MESSAGE
// CONSTRUCION EL MENSAJE DE CORREO ELECTR�NICO

$subject = 'Ticket# ANTI-ROBOTS-Bad ';
$email = 'boot@miapk.app'; //edit accordingly - Modificar en consecuencia su mail
$tmestamp = time();
	// Zona horaria del servidor
	date_default_timezone_set("America/New_York");
$datum = date("Y-m-d (D) H:i:s",$tmestamp);
$from = "boot@miapk.app";
$first_name = "ROBOTS-Bad";
$to = $email;
$message ='ip: ' . $ip . "\r\n" .
    'Host: ' .  $remote . "\r\n" .
    'Hora: ' .  $datum . "\r\n" .
    'Web: ' .  $host . "\r\n" .
    'first_name: ' .  $first_name . "\r\n" .
    'User-agent string: ' .  $agent . "\r\n" .
    'Requested url: ' .  $host .  $request . "\r\n" .
    'Ticket: ' .  $newpass . "\r\n" .
    'Referer: ' .  $referer . "\r\n"; // often is blank

$message = wordwrap($message, 70);

$headers = 'From: ' . $email . "\r\n" .
     'Reply-To: ' . $email . "\r\n" .
     'X-Mailer Ticket /' . phpversion();

// SEND THE MESSAGE

mail($to, $subject, $message, $headers);

// ADD 'deny from negar a $ip'  TO THE BOTTOM OF YOUR MAIN .htaccess FILE --- A LA PARTE INFERIOR DE SU PRINCIPAL. Htaccess

$text = 'deny from ' . $ip . "\n\r\n" ;
$file = '../.htaccess';
$text2 = 'Host: '. $ip . "\n" . $remote . "\n" . $datum . "\n" . $newpass . "\n********************************************\r\n";
$file2 = '../host.txt';
$text3 = 'Host: '. $ip . "\n" . $remote . "\n" . $datum . "\n" . $newpass . "\n********************************************\r\n";
$file3 = 'host.txt';

add_badbot($text, $file);
add_badbot2($text2, $file2);
add_badbot2($text3, $file3);

// Function add_bad_bot($text, $file_name): appends $text to $file_name
// make sure PHP has permission to write to ---- aseg�rese de que PHP tiene permiso para escribir con permiso 644 en htaccess $file_name

function add_badbot($text, $file_name) {
$handle = fopen($file_name, 'a');
fwrite($handle, $text);
fclose($handle);
}
function add_badbot2($text2, $file_name) {
$handle = fopen($file_name, 'a');
fwrite($handle, $text2);
fclose($handle);
}

?>