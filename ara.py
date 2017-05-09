#!/usr/bin/python

import sys
import os
import requests
import json
import urllib
import datetime
import time
import urlnorm
from package import WebAPI
from score_calibration import ScoreCalibration
from package import XLSWriter
from package import SendMail
from package import Options

### Main ###
arg = len(sys.argv)-1;
if arg>0:
	procType = sys.argv[1].lower().strip();
	webAPI = WebAPI();
	sampleType = "-url";
	scoreCalib = ScoreCalibration();
	opt = Options();
	vtfScans ="";
	vtuScans ="";
	resultCollection ={};
	retry=3;
	located = False;
	if procType == '-a':
		if (sampleType =="-url"):
			fname = sys.argv[2].strip();
			try:
				ins = open(fname,"r");
				retry=0;
				located = True;
			except Exception as ex:
				retry-=1;
				time.sleep(1);
				print "Unable to locate input URLs: ", ex;
				print "Closing application...";
				print "Done."
				exit();
			for line in ins:
				try:
					line = urlnorm.norm(line);
				except Exception as ex:
					continue;
				retry = 3;
				while(retry>0):
					jsontxt_url = webAPI.urlVTAPIQuery(line);
					if(jsontxt_url!=0):
						retry = 0
						try:
							responseCodeVTU = int(jsontxt_url['response_code']);
						except Exception as ex:
							continue;
						if (responseCodeVTU == 1):
							sha256 = str(jsontxt_url['filescan_id']).split("-")[0];
							vtuScans = jsontxt_url['scans'];
							print "VTU: ", jsontxt_url['scans'];
							jsontxt_file = webAPI.sha1VTAPIQuery(sha256.strip())
							if(jsontxt_file!=0):
								try:
									responseCodeVTF = jsontxt_file['response_code'];
								except Exception as ex:
									continue;
								if(responseCodeVTF==1):
									vtfScans = jsontxt_file['scans'];
									print "VTF :",  vtfScans, "\n";
								else:
									print "No record in VTF"
							else:
								print "Possible http connectin";
							result = scoreCalib.scoring(responseCodeVTU,responseCodeVTF,vtuScans,vtfScans);
							resultCollection[line] = result;
						elif (responseCodeVTU == 0):
							print "send data to cassandra to get sha1";
							print "then send to VT again to get records";
						else:
							print "Cannot define process for response_code: " + responseCode;
					# call scoring method
					else:
						retry -=1;
						print "Possible http connection problem";
						print "trying to connect...";
			sorted(resultCollection.keys());
			xl = XLSWriter();
			resultFolder = str(os.path.dirname(__file__)) + "/data/result/";
			fname = xl.write(resultCollection,resultFolder);
			sm = SendMail(fname);
			sm.send();
			ins.close;
		elif (sampleType == '-sha1'):
			ins = open(sampleFolderLoc,"r");
			for line in ins:
				print line;
				jsontxt = webAPI.sha1VTAPIQuery(line);
				responseCode = init(jsontxt['response_code']);
				if (responseCode == 1):
					print "";
				elif (responseCode == 0):
					print "Response code 0";					
				else:
					 print "Cannot define process for response_code: " + responseCode;
				del jsontxt;
			ins.close;
		print("\nDone");
	elif procType == '-c':
		baseSampleFolder = str(os.path.dirname(__file__)) + "/data/samples/";
		moduleType = sys.argv[2].lower().strip();
		try:
			if(sys.argv[3].lower().strip() == "-f"):
				forceCalibrate = True;
		except:
			forceCalibrate = False;
		if (moduleType =="-vtu"):
			'''VTU module score calibration'''
			malFileSample = baseSampleFolder + moduleType.replace("-","") + "/malicious.txt";
			normalFileSample = baseSampleFolder + moduleType.replace("-","") + "/normal.txt";
			try:
				malURLSample = open(malFileSample,"r");
				normalURLSample = open(normalFileSample,"r");
				malURLCollection = [];
				normalURLCollection =[];
				for malUrl in malURLSample:
					malURLCollection.append(malUrl.strip());
				for normalUrl in normalURLSample:
					normalURLCollection.append(normalUrl.strip());
				malURLSample.close;
				normalURLSample.close;
			except Exception as e:
				print "Error locating URL samples.", e;
				exit();
			if(len(malURLCollection)> 0 and len(normalURLCollection)>0):
				scoreCalib.calibrate(moduleType, forceCalibrate, malURLCollection, normalURLCollection);
			else:
				print "Cannot start Score calibration make sure the sample Malicious and Normal URLs are both available.";
				exit();
		elif (moduleType == "-vtf"):
			'''VTS module calibration'''
			malFileSample = baseSampleFolder + moduleType.replace("-","") + "/malicious.txt";
			normalFileSample = baseSampleFolder + moduleType.replace("-","") + "/normal.txt";
			try:
				malSha1Sample = open(malFileSample,"r");
				normalSha1Sample = open(normalFileSample,"r");
				malSha1Collection = [];
				normalSha1Collection =[];
				for malSha1 in malSha1Sample:
					malSha1Collection.append(malSha1.strip());
				malSha1Sample.close;
				for normalSha1 in normalSha1Sample:
					normalSha1Collection.append(normalSha1.strip());
				normalSha1Sample.close;
			except:
				print "Error locating Sha1 samples.";
				exit();
			if(len(malSha1Collection)> 0 and len(normalSha1Collection)>0):
				scoreCalib.calibrate(moduleType, forceCalibrate, malSha1Collection, normalSha1Collection);
			else:
				print "Cannot start Score calibration make sure the sample Malicious and Normal URLs are both available.";
				exit();
		else:
			print "Cannot identify module type";
			print "-vtu : VirusTotal URL module";
			print "-vts : VirusTotal SHA1 module\n";
		print ("\nDone");
	elif procType == '-v':
		if(arg==3):
			mod = sys.argv[2];
			ref = sys.argv[3];
			if(mod =="-vtf"):
				if(ref == "-sb"):
					scoreCalib.showScoreBoard(mod);
				elif (ref =="-tr"):
					scoreCalib.generateVTFThreshold();
			elif(mod =="-vtu"):
				if(ref == "-sb"):
					scoreCalib.showScoreBoard(mod);
				elif (ref =="-tr"):
					scoreCalib.generateVTUThreshold();
			elif(mod=="-vtfu"):
				if(ref=="-tr"):
					scoreCalib.generateVTFUThreshold();
		else:
			print "Too many parameters";
	elif procType == '--help':
		opt.printHelp();
	elif procType == '--version':
		opt.printVersion();
	elif procType == '--usage':
		opt.printUsage();
	else:
		print "Cannot identify process";
		print "-c : Score calibration";
		print "-a : Analyze\n";	
else:
	print "Required parameter is missing: <application_name> <filepath> <process_type>";
