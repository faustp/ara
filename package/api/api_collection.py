#!/usr/bin/python

import requests
import json

class WebAPI:
	'''Web API Collection for VirusTotal and Cassandra '''
	def __init__(self):
		pass;
	def __del__(self):
		pass;
	def urlVTAPIQuery(self,url):
		try:
			vtResp = requests.post("http://www.virustotal.com/vtapi/v2/url/report?apikey=06b4898a1fbfd17bdfd2114e002fbccbeca61e8a86d988d1f693daaa8fc5369e&resource=" + url);
			if (vtResp.status_code==200):
				res = json.loads(vtResp.text);
				vtResp.close();
				return res;
			else:
				return 0;
		except Exception as ex:
			return 0;

	def sha1VTAPIQuery(self, sha1):
		try:
			vtResp = requests.post("http://www.virustotal.com/vtapi/v2/file/report?apikey=06b4898a1fbfd17bdfd2114e002fbccbeca61e8a86d988d1f693daaa8fc5369e&allinfo=1&resource=" + sha1);
			if (vtResp.status_code==200):
				res = json.loads(vtResp.text);
				vtResp.close();
				return res;
			else:
				return 0;
		except Exception as ex:
			return 0;

	def sha1CasAPIQuery(self,sha1):
        	casResp = requests.get("http://150.70.97.76:8383/api/v2/cas?sha1="+ sha1);
        	urlList = json.loads(casRep.text)['url'];
        	return urlList;

	def urlCasAPIQuery(sha1,url):
        	casResp = requests.get("http://150.70.97.76:8383/api/v2/cas?sha1="+ url);
        	sha1List = json.loads(casResp.text)['hash'];
        	return sha1List;
