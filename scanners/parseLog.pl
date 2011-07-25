#!/usr/bin/perl

use strict;

if ($#ARGV < 0) {
  die "Usage: $0 LogFile\n";
}

open(IN, "< $ARGV[0]") or die "ERROR: Can't open file $ARGV[0].\n";

# Change the input record separator to select entire log entries
$/ = "=" x 54;
my @logData = <IN>;

# Loop through each request and parse it
my ($request, $logEntry, @requests);
foreach $logEntry (@logData) {

  # Create an array containing each line of the raw request
  my @logEntryLines = split(/\n/, $logEntry);
  
  # Create an array containing each element of the first request line
  my @requestElements = split (/ /, $logEntryLines[1]);
  
  # Only parse GET and POST requests
  if ($requestElements[0] eq "GET" || $requestElements[0] eq "POST") {
    if ($requestElements[0] eq "GET" ) {
      print $requestElements[0]." ".$requestElements[1]."\n";
    }
    
    # POST request data is appended after the question mark
    if ($requestElements[0] eq "POST") {
      print $requestElements[0]." ".$requestElements[1]."?".$logEntryLines[-3]."\n";
    }
  } # End check for GET or POST
} # End of loop for input file entries
