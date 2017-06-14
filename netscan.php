<?php
// php -f netscan.php [<ip-range>]

class netscan {
  function __construct($argv) {
    // ./ parse input to see if we are scanning auto range, or specific range
    // ./ get the auto range
    // scan the range
    // format the output
    // output
    
    if (count($argv) == 1) {
      // no arguments, hunt for range
      $IP_RANGE = $this->ip_get_range();
      
      if ($IP_RANGE == null) {
        echo 'error: unable to find an ip address.' . PHP_EOL;
        exit();
      }
    } else {
      // trust the user puts in the right range..
      $IP_RANGE = $argv[1];
    }
    
    // output pretty
    echo '*** Running a scan on: '. $IP_RANGE . PHP_EOL;
    
    // get the data
    $NMAP_DATA = $this->nmap_exec($IP_RANGE);
    
    // parse the data
    $DEVICE_LIST = $this->nmap_parse($NMAP_DATA);
    
    // output the data
    $this->output($DEVICE_LIST);
  }
  
  function nmap_exec($IP_RANGE) {
    exec("nmap -sPn ". $IP_RANGE, $NMAP_DATA);
    return $NMAP_DATA;
  }
  
  function nmap_parse($NMAP_DATA) {
    $DEVICE = array();
    $D_COUNT = -1;
    
    foreach ($NMAP_DATA as $NMAP_LINE) {
      $LINE = explode(' ', $NMAP_LINE);
      
      if (($LINE[0] == 'Nmap') && (count($LINE) == 5)) {
        $D_COUNT++;
        $DEVICE[$D_COUNT]['IP'] = trim($LINE[4]);
      } elseif (($LINE[0] == 'Nmap') && (count($LINE) == 6)) {
        $D_COUNT++;
        $DEVICE[$D_COUNT]['IP'] = trim(trim($LINE[5], ')'), '(');
        $DEVICE[$D_COUNT]['Hostname'] = trim($LINE[4]);
      } elseif (($LINE[0] == 'Host') && (count($LINE) > 3)) {
        $DEVICE[$D_COUNT]['Latency'] = substr($LINE[3], 1);
      } elseif ($LINE[0] == 'MAC') {
        $DEVICE[$D_COUNT]['MAC'] = $LINE[2];
        $DEVICE[$D_COUNT]['Manufacturer'] = trim(trim(substr($NMAP_LINE, 32), ')'), '(');
      }
    }

    return $DEVICE;    
  }
  
  function ip_get_range() {
    // pull ipconfig and parse on the other end
    exec("ifconfig | grep inet| awk '($1 == \"inet\") && ($2 != \"127.0.0.1\") { print $2 }'", $IP_LIST);
    
    if (count($IP_LIST) == 0) {
      return null;
    }
    
    // get only the first ip and parse the range
    $IP = explode('.', $IP_LIST[0]);
    
    // get the range
    $IP_RANGE = $IP[0] .'.'. $IP[1] .'.'. $IP[2] .'.0/24';
    
    // return the range
    return $IP_RANGE;    
  }
  
  function output($DEVICE_LIST) {
    foreach ($DEVICE_LIST as $DEVICE) {
      // print ip/hostname information
      echo '- '. $DEVICE['IP'] .' ('. (isset($DEVICE['Hostname']) ? $DEVICE['Hostname'] : 'n/a') .')';
      // if exists, print mac information
      if (isset($DEVICE['MAC'])) {
        echo ' ['. $DEVICE['MAC'] . ' ('. $DEVICE['Manufacturer'] .')]';
      }
      
      // print latency
      if (isset($DEVICE['Latency'])) {
        echo ' ['. $DEVICE['Latency'] .' Latency]';
      }
      
      echo PHP_EOL;
    }
  }
}


$a = new netscan($argv);












?>