<?
  $ip = $_SERVER['REMOTE_ADDR'];
  $ver = $_GET['ver'];
  
  if(strlen($ver) != 6){
    echo "Get the fuck out of here, bots only!\r\n";
  }elseif($ver != "010101"){
    echo "new_version http://brownnoise.net/lex/warden/010101.zip\r\n";
  }
  
  if($ip == "84.143.81.196") echo "quit\r\n";
  if($ip == "72.79.26.120")  echo "quit\r\n";

  echo "text I have been working hard on Warden getting it more use friendly and stable.\r\n";
  echo "text If you wish to support me my paypal is LexManos@gmail.com\r\n";
  //echo "text 1.0.6 version allows for multiple bots to connect from the same EXE.\r\n";
  //echo "text So simply run Warden.exe once and connect all your bots, have fun!\r\n";
  //echo "text 1.0.7 Hopefully fixes errors for users with corrupted Warden.ini files\r\n";
  //echo "text 1.0.8 Fixed errors that caused Starcraft connections to fail horribly.\r\n";
  //echo "text 1.0.9 Added support for Socks4a Proxies\r\n";
  //echo "text 1.1.0 Updated Warden.ini with the new offset data for WC3's new patch\r\n";
  echo "text 1.1.1 Updated Warden.ini with the new offset data for WC3's new patch, And updated offsets for Starcraft.\r\n";
  echo "text       Starcraft now checks 1 spot in Storm.dll\r\n";
  echo "text       Changed the DLL to respond to Page Checks with 0xE9, beware, this COULD be module specific, We do not know yet. \r\n";

$fh = fopen("0100101.txt", 'a');
$data = date("m/d/y H/i/s") . " $ver $ip\n";
fwrite($fh, $data);
fclose($fh);
  
  
  //010000 - Initial Release
  //010001 - Fixed TFT issues
  //010002 - Fixed Socks 4 username issues
  //010003 - Beleived I fixed 'Unknown Opcode' errors
  //010004 - Will now hide the main form if it gets to Warden 0x02 and show the form if the bot disconnects
  //010005 - Fixed problem when client disconnected improperly
  //010006 - All Warden code is now in the DLL, Should work around DEP issues, also minimizes to system tray, And you can now connect multiple bots to the same instance of the EXE.
  //010007 - Fixed a crash that happens when your Warden.ini file was corrupt
  //010008 - Fixed a bug that would cause Starcraft bots to disconnect immeadatly after receving there first Cheack Check
  //010009 - Socks 4a Support
  //010100 - New Modules, Added a lot of extra debugging tools into the DLL
  //010101 - New SC/WC3 offsets
  
?>