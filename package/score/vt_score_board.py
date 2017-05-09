#!/usr/bin/python

import json

class VTScoreBoard:
	def __init__(self):
		self.detected = 0;
		self.detectionRate = 0;
	        self.fp = 0;
        	self.fpRate = 0;
        	self.credibility = 0;
	def __del__(self):
      		class_name = self.__class__.__name__;
      		print class_name, "Object has been properly disposed.";
	def toString(self):
                return '\'{\"detected\":'+ str(self.detected) +',\"detection_rate\":'+str(self.detectionRate)+',\"fp\":'+str(self.fp)+',\"fp_rate\":'+str(self.fpRate)+',\"credibility\":'+str(self.credibility)+'}\'';
	def to_JSON(self):
		return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
