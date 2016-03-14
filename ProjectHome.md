gsicr-gsi0com\_sql\_injection\_discover is a small tool that allows a single inyection of sql code, if is successful the result is saved in a log


```
	###############################################################################################################
	#   Author:james jara
	#   Date:  26/08/2012
	#   Version 0.1
	#
	#   #############   #############    ##
	#   ##              ##               ##
	#   ##              ##
	#   ##              #############    ##
	#   ##     ######              ##    ##
	#   ##         ##   ##         ##    ##
	#   ##         ##   ##         ##    ##
	#   #############   #############    ##
	#   gsicr-gsi0com_sql_injection_discover is a small tool that allows a single inyection of sql code,
	#   if is successful the result is saved in a log
	#
	#   Usage:
	#   php gsi0.com_sql_injection_discover.php -i<inyections> -e<errors> -t<target url>
	###############################################################################################################

//Please use as CLI

$gsi0com_sql_injection_discover = new gsi0com_sql_injection_discover();	
	
// Use this comodin {inyectme}	
$gsi0com_sql_injection_discover->setTargetUrl($target);
$gsi0com_sql_injection_discover->setSqliDorks($inyections);
$gsi0com_sql_injection_discover->setSqliErrors($errors);
			
$gsi0com_sql_injection_discover->start();

```