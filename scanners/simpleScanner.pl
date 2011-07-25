#!/usr/bin/perl

use LWP::UserAgent;
use strict;
use Getopt::Std;

my %args;
getopts('c:o:v', \%args);
  
printReport("\nSimple Web Application Scanner\n v1.0 - <brian\@reeldeel.com>\n");

if ($#ARGV < 1) { 
 die "\nsimpleScanner.pl [-o <file>] [-c <cookie data>] [-v] inputfile http://hostname\n\n-c: Use HTTP Cookie\n-o: Output File\n-v: Be Verbose\n"; 
}

# Open input file
open(IN, "< $ARGV[0]") or die"ERROR => Can't open file $ARGV[0].\n";    
my @requestArray = <IN>;

my ($oRequest,$oResponse, $oStatus, %dirLog, %paramLog);

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
     my $paramRequest = $methodAndFile."?".$testData;

     ## Perform input validation tests
     my $sqlVuln = sqlTest($paramRequest);
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
 ($sqlRequest) = @_;

 # Replace the "---PLACEHOLDER---" string with our test string
 $sqlRequest =~ s/---PLACEHOLDER---/te'st/;
 # Make the request and get the response data
 ($sqlStatus, $sqlResults) = makeRequest($sqlRequest);

 # Check to see if the output matches our vulnerability signature.
 my $sqlRegEx = qr /(OLE DB|SQL Server|Incorrect Syntax|ODBC Driver|ORA-|SQL command not|Oracle Error Code|CFQUERY|MySQL|Sybase| DB2 |Pervasive|Microsoft Access|MySQL|CLI Driver|The string constant beginning with|does not have an ending string delimiter|JET Database Engine error)/i;
 if (($sqlResults =~ $sqlRegEx) && ($oResponse !~ $sqlRegEx)) {
  $sqlVulnerable = 1;
  printReport("\n\nALERT: Database Error Message Detected:\n=> $sqlRequest\n\n");
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
