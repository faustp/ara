#!/usr/bin/perl

use IO::File;
use LWP::UserAgent;
use HTTP::Request::Common qw(GET);
use Time::Format qw(%time %strftime %manip);
use Cwd;
$path=Cwd::realpath();

my $ua = LWP::UserAgent->new;
$ua->agent('Mozilla/8.0');

open(LOG, ">>$path/run_logs2.txt");
$time{$format};
$time{$format, $unixtime};
$datenew = "$time{'mm-dd-yyyy'}";
$stime= $time{'hh:mm:ss'};
$fdate = "$time{'yyyymmddhhmm'}";
$fname = "$path"."/data/input/URL_".$fdate.".txt";
print "$fname\n";
open(vt,">$fname");
print LOG "START:\t$datenew $stime\n";

#================ Split date and time ========================#

sub datecall
{
	if($date =~ m/([0-9]{2})\-([0-9]{2})\-([0-9]{4})/i){
		$year = $3;
		$mon = $1;
		$day = $2;
	}

}

$time1= "$time{'hh'}";

#====================Check the time==========================#
if ($time1 <= 7){
	#if time is <=7, -1 in day
	$date = "$time{'mm-dd-yyyy', time-24*60*60}";
	&datecall;
}
elsif ($time1 == 8){
	#if time is 8 the IDsample.txt remove the content
	open(ID,">IDList2.txt");
	print ID "";
	close ID;
	$date = "$time{'mm-dd-yyyy'}";
	&datecall;
}
else{
	#$date = "$time{'mm-dd-yyyy', time-24*60*60}";
	$date = "$time{'mm-dd-yyyy'}";
	
	&datecall;
}
	open(ID,"IDList2.txt");
	chomp(@listid = <ID>);
	close ID;
	
	#================================CRAWL THE MAIN SITE TO GET THE LIST OF MAILs============================#
	$nsite = "http://lists.clean-mx.com/pipermail/viruswatch/$year$mon$day/date.html";
	#http://lists.clean-mx.com/pipermail/viruswatch/20130605/date.html
	#http://lists.clean-mx.com/pipermail/viruswatch/$year$mon$day/date.html
	print LOG "SITE:\t$nsite\n";
	my $req = GET "$nsite";
	print "Get $nsite\n";
	my $res = $ua->request($req);
	$content = $res->content;
	$status=$res->status_line;
	print LOG "STATUS:\t$status\n";

	@content1 = split (/\<ul\>/, $content),"\n";
	@content2 = split (/\<LI\>/, $content1[2]),"\n";
	
	foreach $list(@content2){
		if ($list =~ m/\<A\sHREF\=\"([0-9]{6,})\.html\"\>(.*)/i){
			$id = $1;
			$subjct = $2;
			$subjct=~s/\t/ /;
			print "$id\n";
			$testid = grep /$id/, @listid;
			if($testid == 0){
				print "ID not found: $id\tTime to crawl\n";
				#=====================================Access the Mails site =====================================#
				#$nsite = "http://lists.clean-mx.com/pipermail/viruswatch/20130605/$id.html";
				$nsite = "http://lists.clean-mx.com/pipermail/viruswatch/$year$mon$day/$id.html";
				print "$nsite\n";
				my $req = GET "$nsite";
				print "Get $nsite\n";
				my $res = $ua->request($req);
				$contentid = $res->content;
				if ($res->is_error()){
					
				}else{
					push (@listid, $id);
				}
				
				@contentid1 = split (/<PRE>/, $contentid),"\n";
				@contentid2 = split (/\n/, $contentid1[1]),"\n";
				
				if($contentid2[0]=~ m/A non\-text attachment was scrubbed/i){
					    $contentid2[5]=~s/URL\: &lt\;\<A HREF=\"([^\"]+).+/$1/i;
						#print "$contentid2[5]\n";
						
						$nsite = $contentid2[5];
						#print "$nsite\n";
						my $req = GET "$nsite";
						print "Get THE non text attachment $nsite\n";
						my $res = $ua->request($req);
						$contentobj = $res->content;
						@contentid3 = split (/\n/, $contentobj),"\n";
						foreach $line2(@contentid3){
						
							if($line2 =~ m/(.*)\t(.*)\t(.*)\t(.*)\t(.*)\t(.*)\t(.*)\t(.*)\t(.*)/i){
							    
								$des = $1;
								$det = $2;
								$ctry = $4;
								$dnshost =$5;
								$ip = $6;
								#$dom = $9;
								$url = "$9";
								#$c = grep /$url/, @dup;
								#if($c == 0){
								print vt "$url\n";
								#push (@dup, $url);
								#}	
							}	
						
						}
						
						
				}else
				{
						foreach $line (@contentid2){
						
						
							if($line =~ m/(.*)\t(.*)\t(.*)\t(.*)\t(\<A\sHREF\=\".*\"\>(.*)\<\/A\>)?\t(.*)\t(.*)\t(.*)\t(\<A\sHREF\=\".*\"\>(.*)\<\/A\>(.*))/i){
								$des = $1;
								$detect = $2;
								$ctry = $4;
								$dnshost =$6;
								$ip = $7;
								#$dom = $9;
								$url = "$11$12";
								#$b = grep /$url/, @dup;
                                                                #if($b == 0){
                                                                print vt "$url\n";
                                                                #push (@dup, $url);
                                                                #}

							}
						}
				}
			}
		}
	}

	
close vt;

#------------------ CHECKING DATA TO RUN TO VT API--------
@listid = sort(@listid);
open(ID,">IDList2.txt");
foreach (@listid)
{
	print ID "$_\n";
}
close ID;

open(che, "$fname");
chomp(@data = <che>);
$total = @data;
close che;
print "TOTAL URLS: $total\n";
if ($total == 0)
{
	print "No URLs found\n";4321
}
else
{
	system("python ara.py -a $fname");
}
#-----------------------------------------------
