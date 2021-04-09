<?php include("robot2.php"); ?>"
<?php
//  Author:       Inoel Garcia 
//  Date:         4th January 2010
//  Last update:  10th January 2020
//
//  This transaction is intended to trap software agents (robots) that do not obey the rules defined 
//  in the robots.txt file (see http://www.robotstxt.org/). It records the details of the event; 
//  updates the .htaccess to bar access to the web site from the invoking IP address; and sends a
//  message to a given email address giving details of the event.
//
//  The robot trap is set by including a line in the robots.txt file which disallows access to a 
//  special directory, say robottrap.
//
//    User-agent: *
//    Disallow: /mail/
//    Disallow: /robot/mail/
//
//  See http://copen.atspace.tv/robots.txt for an example. Note that the new robots.txt file 
//  should be uploaded at tleast 24 hours before setting the trap as described below, to allow valid
//  robots to clear their cache of the old version. 
//
//  This transaction (robottrap.php) should be stored in the /robot/mail/ directory, and invoked,
//  preferably as both the first link and the last link, from the main page of your entry page in 
//  the form:
// 
//    <a href="/robot/mail/robottrap.php"></a> 
//
//  Note that there is no link text between <a> and </a>, meaning that only robots will find the 
//  link (although some so-called web accelerators may do so as well). 
//
//  Once the robot has invoked the transaction, the transaction first records the details of the 
//  in a text file located in a directory of your choice. The following details are stored:
// 
//    Date and time accessed
//    IP address
//    Domain name resolution of IP address
//    User agent 
//
//  You may need first to create an file called robotfile.txt in your chosen directory, and give it  
//  write access. Note, it is assumed that the directory is somewhere below the man website 
//  directory in the hierarchy. T
//
//  The transaction then updates the Apache .htaccess file to deny further access to the web site 
//  from that IP address. It assumes that the last lines of the Apache file are in the following 
//  format, and the new IP address is added to the end:
//
//    # Deny access to sites who have repeatedly broken the robot rules (automatically updated)
//    Order Allow,Deny
//    Allow from All
//    Deny from 173.227.230.236
//    Deny from 38.100.21.19
//
//  See http://copen.atspace.tv/mail/htaccess.shtml for an example of an .htaccess file.
//
//  You may need to give the .htaccess file write access first.
//
//  The transaction finally sends an email to the specified email address to report that a robot has
//  been trapped.
//
//  See also the script index2.php which issues a report of trapped robots, listed from the 
//  text file discussed above. An example of its use can be found here:
//
//    http://copen.atspace.tv/mail/index2.php
//
//  You can test the functionality of this script by invoking the transaction directly, but you will 
//  have to edit your .htaccess file afterwards, as your IP address will now be banned!
// 
//  ************************************************************************************************
// ESPANOL
// 
// 
// Esta transacci�n est� destinada a atrapar agentes de software (robots) que no obedecen las reglas definidas
// en el archivo robots.txt (consulte http://www.robotstxt.org/). Registra los detalles del evento;
// actualiza el .htaccess para prohibir el acceso al sitio web desde la direcci�n IP que lo invoca; y env�a un
// mensaje a una direcci�n de correo electr�nico determinada dando detalles del evento.
//
// La trampa del robot se establece al incluir una l�nea en el archivo robots.txt que no permite el acceso a un
// directorio especial, digamos robottrap.
//
//    User-agent: *
//    Disallow: /mail/
//    Disallow: /robot/mail/
//
// Consulte http://copen.atspace.tv/robots.txt para ver un ejemplo. Tenga en cuenta que el nuevo archivo robots.txt
// debe cargarse al menos 24 horas antes de establecer la trampa como se describe a continuaci�n, para permitir
// robots para borrar su cach� de la versi�n anterior.
//
// Esta transacci�n (robottrap.php) debe almacenarse en el directorio /robot/mail/ e invocarse,
// preferiblemente como primer enlace y �ltimo enlace, desde la p�gina principal de su p�gina de entrada en
//  la forma:
//
// <a href="/robot/mail/robottrap.php"> </a>
//
// Tenga en cuenta que no hay texto de enlace entre <a> y </a>, lo que significa que solo los robots encontrar�n el
// enlace (aunque algunos de los denominados aceleradores web tambi�n pueden hacerlo).
//
// Una vez que el robot ha invocado la transacci�n, la transacci�n primero registra los detalles del
// en un archivo de texto ubicado en un directorio de su elecci�n. Se almacenan los siguientes detalles:
//
// Fecha y hora de acceso
//    Direcci�n IP
// Resoluci�n de nombre de dominio de la direcci�n IP
//    Agente de usuario
//
// Es posible que primero deba crear un archivo llamado robotfile.txt en el directorio elegido y darle
// acceso de escritura. Tenga en cuenta que se supone que el directorio est� en alg�n lugar debajo del sitio web man
// directorio en la jerarqu�a. T
//
// La transacci�n luego actualiza el archivo .htaccess de Apache para denegar m�s acceso al sitio web
// desde esa direcci�n IP. Asume que las �ltimas l�neas del archivo Apache est�n en lo siguiente
// formato, y la nueva direcci�n IP se agrega al final:
//
// # Denegar el acceso a sitios que hayan infringido repetidamente las reglas del robot (actualizado autom�ticamente)
// Orden Permitir, Denegar
// Permitir de todos
// Denegar desde 173.227.230.236
// Denegar desde 38.100.21.19
//
// Consulte http://copen.atspace.tv/mail/htaccess.shtml para ver un ejemplo de un archivo .htaccess.
//
// Es posible que primero deba otorgar acceso de escritura al archivo .htaccess.
//
// La transacci�n finalmente env�a un correo electr�nico a la direcci�n de correo electr�nico especificada para informar que un robot ha
// ha sido atrapado.
//
// Vea tambi�n el script index2.php que emite un informe de robots atrapados, enumerados en el
// archivo de texto discutido anteriormente. Un ejemplo de su uso se puede encontrar aqu�:
//
// http://copen.atspace.tv/mail/index2.php
//
// Puede probar la funcionalidad de este script invocando la transacci�n directamente, pero lo har�
// tienes que editar tu archivo .htaccess despu�s, �ya que tu direcci�n IP ahora estar� prohibida!
//
//  ************************************************************************************************

//  The following lines of code should be modified to reflect your requirements
//  ===========================================================================

//  Las siguientes l�neas de c�digo deben modificarse para reflejar sus requisitos
// ================================================ ===========================

//  The mail address to which details of the naughty robots should be sent. replace with your email address
//  La direcci�n de correo electr�nico a la que se deben enviar los detalles de los traviesos robots. reemplazar con su direcci�n de correo electr�nico


//  The location of the robot text file as an offset from your root. It should match the same 
//  directory specified in the index2.php transaction. To place the data file in the home 
//  directory leave it as '/'. The directory should have write acesss. You may need first to create  
//  an empty file called robotfile.txt in this directory and give it write access.

// La ubicaci�n del archivo de texto del robot como un desplazamiento de su ra�z. Deber�a coincidir con el mismo
// directorio especificado en la transacci�n index2.php. Para colocar el archivo de datos en el hogar
// directorio d�jelo como '/'. El directorio debe tener accesos de escritura. Es posible que primero necesite crear
// un archivo vac�o llamado robotfile.txt en este directorio y darle acceso de escritura.



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
//  A�ade la informaci�n al archivo del robot con los campos separados por "|" car�cter
$fp = fopen ($filename1, 'a+'); 
fwrite ($fp, "$date|$ipaddress|$domainname|$useragent|\n"); 
fclose ($fp);



//  Disabled Send the mail message to say that a robot has been trapped.
//  Desactivado Env�a el mensaje de correo para decir que un robot ha sido atrapado.
$message  = "The following user agent has fallen into the robot trap: \n\n";
$message  = "  Date:           $date \n";
$message .= "  IP address:     $ipaddress \n";
$message .= "  Domain name:    $domainname \n";
$message .= "  User agent :    $useragent \n";


// Exit the transaction
exit;
?>
