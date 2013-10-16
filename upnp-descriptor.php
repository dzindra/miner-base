<?php
	header("Content-type: text/xml");

	$uuid = isset($_GET['uuid']) ? preg_replace('/[^a-zA-Z0-9-_:]/','-',$_GET['uuid']) : '';
	$url = "http://$_SERVER[SERVER_ADDR]".($_SERVER['SERVER_PORT'] != 80 ? ":$_SERVER[SERVER_PORT]" : "")."/";
	$name = $_SERVER['SERVER_NAME'];

	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
	<specVersion>
		<major>1</major>
		<minor>0</minor>
	</specVersion>
	<device>
		<deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
		<friendlyName>Miner (<?php echo $name;?>)</friendlyName>
		<manufacturer>Džindra</manufacturer>
		<manufacturerURL>https://github.com/dzindra</manufacturerURL>
		<modelName>Miner</modelName>
		<UDN><?php echo $uuid; ?></UDN>
		<presentationURL><?php echo $url; ?></presentationURL>
	</device>
</root>

