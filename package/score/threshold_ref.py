#!/usr/bin/env python

import json

class ThresholdRef:
    tscore = 0;
    missed = 0;
    percentMissed = 0;
    fp=0;
    percentFP=0;
    def __init__(self,):
        pass;
    def __del__(self):
        pass;
    def to_JSON(self):
	return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=1);