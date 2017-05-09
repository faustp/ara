#!/usr/bin/python

__version__ = '1.0 (Beta)';

class Options:
	def __init__(self,):
		pass;
	def __del__(self,):
		pass;
	def printHelp(self,):
		help = """\n\n
						Examples:
							ara.py -c [-vtf|-vtu]  		#Perform score calibration for VTF module
							ara.py -c [-vtf|-vtu] -f	#Force to perform score calibration (Note: Previous score board will be erased) 
							ara.py -a      			#Perform actual analysis of URL (URL input must be on this file "input/urls.txt")
							ara.py -v [-vtf|-vtu|-vtfu] -tr	#View VTF|VTU|VTFU module prefered threshold
							ara.py -v [-vtf|-vtu] -sb 	#View the ScoreBoard of VTF|VTU module

						Other Options:
							--help		#Give this help list
							--usage		#Give a short usage message
							--version 	#Print program version \n\n""";
		print(help);
	def printVersion(self,):
		print('1.0 Beta');
	def printUsage(sel,):
		usage = """\n\nProj ARA - is a POC  that perform scoring mechanism to detect possible malicious and FP URLs.\nIt also perform score calibration to measure the credibility of every AV found in VirusTotal Website by providing predictive sample set\n\n""";
		print(usage);
