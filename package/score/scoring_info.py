#!/usr/bin/env python

import json
class ScoringInfo:
    avList =[];
    score =0.0;
    module ="";
    status ="";
    def __init__(self, ):
        pass;
    def __del__(self, ):
        pass;
    def to_JSON(self):
	return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=1);
    

