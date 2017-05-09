#!/usr/bin/env python

import json

class ScoreRef:
    
    def __init__(self):
	pass;
    def __del__(self):
       	class_name = self.__class__.__name__;
    def init(self, avList, score):
	self.avList = avList;
	self.score = score;
    def to_JSON(self):
	return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=1);

