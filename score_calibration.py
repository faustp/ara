#!/usr/bin/env python

from package import VTScoreBoard
from package import WebAPI
from package import ScoringInfo
from package import ScoreRef
from package import ThresholdRef
import prettytable
import json
import sys, os

baseFolderScoring = str(os.path.dirname(__file__)) + "/data/scoring/";
vtuScoreBoard = baseFolderScoring + "VTU_ScoreBoard.txt";
vtuScoreBoard = baseFolderScoring + "VTU_ScoreBoard.txt";
vtuMalScoreRef =baseFolderScoring + "VTU_MalScoreRef.txt";
vtuNonMalScoreRef = baseFolderScoring +"VTU_NonmalScoreRef.txt";
vtfScoreBoard =baseFolderScoring +"VTF_ScoreBoard.txt";
vtfMalScoreRef = baseFolderScoring +"VTF_MalScoreRef.txt";
vtfNonMalScoreRef = baseFolderScoring +"VTF_NonmalScoreRef.txt";
thresholdRef = baseFolderScoring + "ThresholdRef.txt";

class ScoreCalibration:
    remaining =0;
    
    def __init__(self,):
        pass;
    def __del__(self,):
        pass;
        
    def calibrate(self, moduleType , forceCalibrate, malSampleCollection = [],normalSampleCollection = []):
        ''' calibrationType: <-mal> for malicious and <-nonmal> for nonmalicious for both URL & SHA1'''
        ''' moduleType: <-vtu> for VirusTotalURL module and <-vts> for VirustotalSHA1 module'''
        ''' dataCollection: list of URLs/SHA1 that will be used for score calibration'''
        moduleType = str(moduleType);
        malSampleSize = len(malSampleCollection);
        normalSampleSize = len (normalSampleCollection);
        scoreCalib = ScoreCalibration();
        if (moduleType == "-vtu"):
            if(forceCalibrate):
                #Erase all Scoring data (VTUScoreBoard, VTUScoreRef and ThresholdRef)
                scoreCalib.generateScoreBoard(moduleType, malSampleCollection, normalSampleCollection);
                scoreCalib.generateVTUThreshold();
                scoreCalib.generateVTFUThreshold();
            else:
                scoreCalib.generateVTUThreshold();
                scoreCalib.generateVTFUThreshold();
        elif (moduleType == "-vtf"):
            if(forceCalibrate):
                #Erase all Scoring data (VTFScoreBoard, VTFScoreRef and ThresholdRef)
                scoreCalib.generateScoreBoard(moduleType, malSampleCollection, normalSampleCollection);
                scoreCalib.generateVTFThreshold();
                scoreCalib.generateVTFUThreshold();
            else:
                scoreCalib.generateVTFThreshold();
                scoreCalib.generateVTFUThreshold();
        else:
            print "Unrecognized module."
            exit();    
        #s.generateThreshold(baseFolderScoring,fnameScoreBoard,moduleType);
    def initScoreRef(self, calibrationType, moduleType, scoreRefCollection = ()):
        if(moduleType =="-vtu"):
            if(calibrationType =="-mal"):
                scoreRefFile = baseFolderScoring + moduleType.replace("-","").upper() + "_"+ calibrationType.replace("-","").title() + "ScoreRef.txt";  
            elif(calibrationType =="-nonmal"):
                scoreRefFile =  baseFolderScoring + moduleType.replace("-","").upper() + "_"+ calibrationType.replace("-","").title() + "ScoreRef.txt";  
        elif(moduleType == "-vtf"):
            if(calibrationType =="-mal"):
                scoreRefFile = baseFolderScoring + moduleType.replace("-","").upper() + "_"+ calibrationType.replace("-","").title() + "ScoreRef.txt";  
            elif(calibrationType =="-nonmal"):
                scoreRefFile =  baseFolderScoring + moduleType.replace("-","").upper() + "_"+ calibrationType.replace("-","").title() + "ScoreRef.txt"; 
        print "Populating score reference for " + moduleType.replace("-","").upper() + calibrationType;
        try:
            os.remove(scoreRefFile);
            json.dump(scoreRefCollection, open(scoreRefFile,"w"));
        except:
            json.dump(scoreRefCollection, open(scoreRefFile,"w"));
        return scoreRefFile;
    
    def updateScoreBoard(self, calibrationType, scoreBoardName ,scoreCollection = {}):
        try:
            json_txt = json.load(open(scoreBoardName));
            if(calibrationType =="-mal"):  
                for avName,scans in json_txt.items():
                    finalScore = json.loads(scans);
                    if(scoreCollection.has_key(avName)):
                        rawScore = json.loads(scoreCollection.get(avName));
                        finalScore['detected'] = rawScore['detected'];
                        finalScore['detectionRate'] = rawScore['detectionRate'];
                        finalScore['credibility'] = "%.2f" % (float(finalScore['detectionRate'])- float(finalScore['fpRate']));
                        scoreCollection[avName] = json.dumps(finalScore);
                    else:
                        scoreCollection[avName] =json.dumps(finalScore);       
            elif(calibrationType =="-nonmal"):
                for avName,scans in json_txt.items():
                    finalScore = json.loads(scans);
                    if(scoreCollection.has_key(avName)):
                        rawScore = json.loads(scoreCollection.get(avName));
                        finalScore['fp'] = rawScore['fp'];
                        finalScore['fpRate'] = rawScore['fpRate'];
                        finalScore['credibility'] = "%.2f" % (float(finalScore['detectionRate'])- float(finalScore['fpRate']));
                        scoreCollection[avName] = json.dumps(finalScore)
                    else:
                        scoreCollection[avName] =json.dumps(finalScore);   
            json.dump(scoreCollection, open(scoreBoardName,"w"));
        except:
            json.dump(scoreCollection, open(scoreBoardName,"w"));
        return scoreBoardName;
    
    def generateThreshold(self,baseFolderScoring,fnameScoreBoard, moduleType):
        print "Generating Threshold base from score board";
        fnameThreshold = baseFolderScoring + "/Threshold.txt";
        json_sc = json.load(open(fnameScoreBoard));
        moduleType = moduleType.replace("-","").strip().lower();
        thresholdCol = {};
        thresholdScore=0.0;
        sumCS = 0.0;
        totalAV = len(json_sc);
        for key,val in json_sc.items():
            sumCS += float(json.loads(val)['credibility']);
        thresholdScore ="%.2f"%(float(sumCS)/ float(totalAV));
        thresholdCol[moduleType] = thresholdScore;
        try:
            json_threshold =json.load(open(fnameThreshold));
            json_threshold[moduleType] = thresholdScore;
            if(json_threshold.has_key('vtf') and json_threshold.has_key('vtu')):
                vtsuThreshold = float(json_threshold['vtu']) + float(json_threshold['vts']);
                json_threshold['vtsu'] = vtsuThreshold;
            json.dump(json_threshold, open(fnameThreshold,"w"));
        except:
            json.dump(thresholdCol, open(fnameThreshold,"w"));
    
    def generateScoreRef(self, updatedScoreBoard, updatedScoreRef):
        print "generating Score Reference"
        json_sb = json.load(open(updatedScoreBoard));
        json_sr =  json.load(open(updatedScoreRef));
        avCount = len(json_sb);
        for key, val in json_sr.items():
            totalScoreRef =0;
            for av in json.loads(val)['avList']:
                if(json_sb.has_key(av)):
                    totalScoreRef +=float(json.loads(json_sb[av])['credibility']);
            newVal=json.loads(val);
            newVal['score']= "%.2f" %(float(totalScoreRef)/ avCount);
            json_sr[key] = json.dumps(newVal);
            del totalScoreRef, newVal;
        json.dump(json_sr, open(updatedScoreRef,"w"));
        del json_sb,json_sr;
        
    def generateVTUThreshold(self, ): 
        try:
            json_VTUScoreBoard = json.load(open(vtuScoreBoard));
            json_VTUMalScoreRef = json.load(open(vtuMalScoreRef));
            json_VTUNonMalScoreRef =json.load(open(vtuNonMalScoreRef));
            totalAV = len(json_VTUScoreBoard);
            malSampleSize = len(json_VTUMalScoreRef);
            normalSampleSize = len(json_VTUNonMalScoreRef);
            totalVTUScore =0;
            totalVTUCS = 0.0;
            for key,val in json_VTUScoreBoard.items():
                totalVTUScore += float(json.loads(val)['credibility']);
            totalVTUCS = float(totalVTUScore)/totalAV;
            noOfMalMissed= 0;
            noOfFP=0;
            print "VTUScore :","%.2f" %totalVTUCS;
            print "Malicious SampleSize: ",malSampleSize;
            print "Normal SampleSize: ",normalSampleSize;
            print "Total Av: ", totalAV, "\n";
            vtu_thldBoard = {};
            for tn in range(1,10):
                noOfMalMissed=0;
                dVTUScore = round((float(totalVTUCS) / float(tn)),2);
                for url, malVal in json_VTUMalScoreRef.items():
                    json_malVal = json.loads(malVal);
                    malScore = json_malVal['score'];
                    malScore=float(malScore);
                    if (float(dVTUScore)> float(malScore)):
                        noOfMalMissed +=1;
                noOfFP=0;
                for url, normVal in json_VTUNonMalScoreRef.items():
                    json_normVal = json.loads(normVal);
                    normScore = json_normVal['score'];
                    normScore = float(normScore);
                    if(float(normScore)> float(dVTUScore)):
                        noOfFP +=1;
                percentFP = "%.2f"%((noOfFP /float(normalSampleSize))*100);
                percentMissed = "%.2f" %((noOfMalMissed / float(malSampleSize))*100);
                thldRef =ThresholdRef();
                thldRef.tscore= dVTUScore;
                thldRef.missed=noOfMalMissed;
                thldRef.percentMissed=percentMissed;
                thldRef.fp=noOfFP;
                thldRef.percentFP=percentFP;
                vtu_thldBoard[tn] = thldRef.to_JSON();
                del noOfMalMissed;
            sorted(vtu_thldBoard.keys());
            preferredVTUTN = 1;
            ptable = prettytable.PrettyTable(["TN","High","Missed","%Missed","FP","%FP"]);
            for key, val in vtu_thldBoard.items():
                jsonVal =json.loads(val);
                ptable.add_row([key,jsonVal['tscore'],jsonVal['missed'],jsonVal['percentMissed'],jsonVal['fp'],jsonVal['percentFP']]);
            for i in range(1, len(vtu_thldBoard)):
                if (json.loads(vtu_thldBoard[i])['fp'] == json.loads(vtu_thldBoard[i+1])['fp']):
                    preferredVTUTN = i+1;
                else:
                    break;
            preferredVTUTN = ((((preferredVTUTN+1)/2) +9)/2);
            print ptable;
            print "PREFERED TN: ", preferredVTUTN, ",","SCORE: ", json.loads(vtu_thldBoard.get(preferredVTUTN))['tscore'];
            print "\n\n";
            try:
                jsonThreshold = json.load(open(thresholdRef));
                jsonThreshold['vtu'] = vtu_thldBoard.get(preferredVTUTN);
                json.dump(jsonThreshold, open(thresholdRef,"w"));
            except Exception as ex:
                jsonThreshold={};
                jsonThreshold['vtu']= vtu_thldBoard.get(preferredVTUTN);
                json.dump(jsonThreshold, open(thresholdRef,"w"));
            del  malSampleSize,normalSampleSize;
        except Exception as ex:
            print "Error occured while generating threshold reference for VTU", ex;
            exit();
    
    def generateVTFThreshold(self,):
        try:
            '''Generate threshold for VTF module'''
            json_VTFScoreBoard = json.load(open(vtfScoreBoard));
            json_VTFMalScoreRef = json.load(open(vtfMalScoreRef));
            json_VTFNonMalScoreRef =json.load(open(vtfNonMalScoreRef));
            totalAV = len(json_VTFScoreBoard);
            malSampleSize = len(json_VTFMalScoreRef);
            normalSampleSize = len(json_VTFNonMalScoreRef);
            totalVTFScore =0;
            totalVTFCS = 0.0;
            for key,val in json_VTFScoreBoard.items():
                totalVTFScore += float(json.loads(val)['credibility']);
            totalVTFCS = float(totalVTFScore)/totalAV;
            noOfMalMissed= 0;
            noOfFP=0;
            print "VTFScore :","%.2f" %totalVTFCS;
            print "Malicious SampleSize: ",malSampleSize;
            print "Normal SampleSize: ",normalSampleSize;
            print "Total Av: ", totalAV, "\n";
            vtf_thldBoard = {};
            for tn in range(1,10):
                noOfMalMissed=0;
                dVTFScore = round((float(totalVTFCS) / float(tn)),2);
                for url, malVal in json_VTFMalScoreRef.items():
                    json_malVal = json.loads(malVal);
                    malScore = json_malVal['score'];
                    malScore=float(malScore);
                    if (float(dVTFScore)> float(malScore)):
                        noOfMalMissed +=1;
                noOfFP=0;
                for url, normVal in json_VTFNonMalScoreRef.items():
                    json_normVal = json.loads(normVal);
                    normScore = json_normVal['score'];
                    normScore = float(normScore);
                    if(float(normScore)> float(dVTFScore)):
                        noOfFP +=1;
                percentFP = "%.2f"%((noOfFP /float(normalSampleSize))*100);
                percentMissed = "%.2f" %((noOfMalMissed / float(malSampleSize))*100);
                thldRef =ThresholdRef();
                thldRef.tscore= dVTFScore;
                thldRef.missed=noOfMalMissed;
                thldRef.percentMissed=percentMissed;
                thldRef.fp=noOfFP;
                thldRef.percentFP=percentFP;
                vtf_thldBoard[tn] = thldRef.to_JSON();
                del noOfMalMissed;
            sorted(vtf_thldBoard.keys());
            preferredVTFTN = 1;
            ptable = prettytable.PrettyTable(["TN","High","Missed","%Missed","FP","%FP"]);
            for key, val in vtf_thldBoard.items():
                jsonVal =json.loads(val);
                ptable.add_row([key,jsonVal['tscore'],jsonVal['missed'],jsonVal['percentMissed'],jsonVal['fp'],jsonVal['percentFP']]);
            for i in range(1, len(vtf_thldBoard)):
                if (json.loads(vtf_thldBoard[i])['fp'] == json.loads(vtf_thldBoard[i+1])['fp']):
                    preferredVTFTN = i+1;
                else:
                    break;
            preferredVTFTN = ((((preferredVTFTN+1)/2) +9)/2);
            print ptable;
            print "PREFERED TN: ", preferredVTFTN, ",","SCORE: ", json.loads(vtf_thldBoard.get(preferredVTFTN))['tscore'];
            try:
                jsonThreshold = json.load(open(thresholdRef));
                jsonThreshold['vtf'] = vtf_thldBoard.get(preferredVTFTN);
                json.dump(jsonThreshold, open(thresholdRef,"w"));
            except Exception as ex:
                jsonThreshold={};
                jsonThreshold['vtf']= vtf_thldBoard.get(preferredVTFTN);
                json.dump(jsonThreshold, open(thresholdRef,"w"));
            del  malSampleSize,normalSampleSize;
        except Exception as ex:
            print "Error occured while generating threshold reference for VTF", ex;
            exit();
        
    def generateVTFUThreshold(self, ):
        try:
            try:
                json_VTUScoreBoard = json.load(open(vtuScoreBoard));
                json_VTUMalScoreRef = json.load(open(vtuMalScoreRef));
                json_VTUNonMalScoreRef =json.load(open(vtuNonMalScoreRef));
                json_VTFScoreBoard = json.load(open(vtfScoreBoard));
                json_VTFMalScoreRef = json.load(open(vtfMalScoreRef));
                json_VTFNonMalScoreRef =json.load(open(vtfNonMalScoreRef));
            except Exception as ex:
                print "Cannot perform threshold generation for both VTF and VTU module: ", ex;
                exit();
            totalVTUAV = len(json_VTUScoreBoard);
            totalVTFAV = len(json_VTFScoreBoard);
            totalVTUScore =0;
            totalVTUCS = 0.0;
            for key,val in json_VTUScoreBoard.items():
                totalVTUScore += float(json.loads(val)['credibility']);
            totalVTUCS = float(totalVTUScore)/totalVTUAV;
            totalVTFScore =0;
            totalVTFCS = 0.0;
            for key,val in json_VTFScoreBoard.items():
                totalVTFScore += float(json.loads(val)['credibility']);
            totalVTFCS = float(totalVTFScore)/totalVTFAV;
            malSampleSize = len(json_VTUMalScoreRef);
            normalSampleSize = len(json_VTUNonMalScoreRef);
            vtfuCS = totalVTFCS + float(totalVTUCS);
            vtfuScore= 0.0;
            malSampleSize_VTFU = len(json_VTUMalScoreRef) + len(json_VTFMalScoreRef);
            normalSampleSize_VTFU = len(json_VTUNonMalScoreRef) + len(json_VTFNonMalScoreRef);
            print "VTFUScore: ", vtfuCS;
            print "VTFU Malicious SampleSize: ",malSampleSize_VTFU;
            print "VTFU Normal SampleSize: ",normalSampleSize_VTFU;
            vtfu_thldBoard = {};
            for tn in range(1,10):
                noOfMalMissed = 0;
                noOfFP=0;
                vtfuScorei = round(float(vtfuCS) /tn,2); 
                for url, malVal in json_VTUMalScoreRef.items():
                    json_malVal = json.loads(malVal);
                    malScore = json_malVal['score'];
                    malScore=float(malScore);
                    if (float(vtfuScorei)> float(malScore)):
                        noOfMalMissed +=1;
                for url, malVal in json_VTFMalScoreRef.items():
                    json_malVal = json.loads(malVal);
                    malScore = json_malVal['score'];
                    malScore=float(malScore);
                    if (float(vtfuScorei)> float(malScore)):
                        noOfMalMissed +=1;
                for url, normVal in json_VTFNonMalScoreRef.items():
                    json_normVal = json.loads(normVal);
                    normScore = json_normVal['score'];
                    normScore = float(normScore);
                    if(float(normScore)> float(vtfuScorei)):
                        noOfFP +=1;
                for url, normVal in json_VTUNonMalScoreRef.items():
                    json_normVal = json.loads(normVal);
                    normScore = json_normVal['score'];
                    normScore = float(normScore);
                    if(float(normScore)> float(vtfuScorei)):
                        noOfFP +=1;
                percentFP = "%.2f"%((noOfFP /float(normalSampleSize_VTFU))*100);
                percentMissed = "%.2f" %((noOfMalMissed / float(malSampleSize_VTFU))*100);
                vtfu_thldRef =ThresholdRef();
                vtfu_thldRef.tscore= vtfuScorei;
                vtfu_thldRef.missed=noOfMalMissed;
                vtfu_thldRef.percentMissed=percentMissed;
                vtfu_thldRef.fp=noOfFP;
                vtfu_thldRef.percentFP=percentFP;
                vtfu_thldBoard[tn] = vtfu_thldRef.to_JSON();
            sorted(vtfu_thldBoard.keys());
            preferedVTFUTN = 1;
            ptable = prettytable.PrettyTable(["TN","High","Missed","%Missed","FP","%FP"]);
            for key, val in vtfu_thldBoard.items():
                jsonVal =json.loads(val);
                ptable.add_row([key,jsonVal['tscore'],jsonVal['missed'],jsonVal['percentMissed'],jsonVal['fp'],jsonVal['percentFP']]);
            for i in range(1, len(vtfu_thldBoard)):
                if (json.loads(vtfu_thldBoard[i])['fp'] == json.loads(vtfu_thldBoard[i+1])['fp']):
                    preferedVTFUTN = i+1;
                else:
                    break;
            preferedVTFUTN = ((((preferedVTFUTN+1)/2) +9)/2);
            print ptable;
            print "PREFERED TN: ", preferedVTFUTN, ",","SCORE: ", json.loads(vtfu_thldBoard.get(preferedVTFUTN))['tscore'];
            try:
                jsonThreshold = json.load(open(thresholdRef));
                jsonThreshold['vtfu'] = vtfu_thldBoard.get(preferedVTFUTN);
                json.dump(jsonThreshold, open(thresholdRef,"w"));
            except Exception as ex:
                jsonThreshold={};
                jsonThreshold['vtfu']= vtfu_thldBoard.get(preferedVTFUTN);
                json.dump(jsonThreshold, open(thresholdRef,"w"));
        except Exception as ex:
            print "Error generating threshold for VTF and VTU module", ex;
    
    def scoring(self,vtuResponseCode,vtfResponseCode,vtuScans,vtfScans):
        '''Scoring method'''
        scoringReference={};
        thldBoard = json.load(open(thresholdRef));
        avList=[];
        credibility=0;
        if (vtuResponseCode==1 and vtfResponseCode==0):
            vtuCredibility=0.0;
            vtuScore =0.0;
	    for avName,val in vtuScans.items():
                detected = val['detected'];
                if(detected):
                    avList.append(avName);
            jsontxtVTUSB = json.load(open(vtuScoreBoard));
            totalAV = len(jsontxtVTUSB);
            for av in avList:
                if(jsontxtVTUSB.has_key(av)):
                    sb = jsontxtVTUSB[av];
                    vtuCredibility += float(json.loads(sb)['credibility']);
            vtuCredibility = "%.2f" % (float(vtuCredibility) /totalAV);
            vtuScore = "%.2f" % float(json.loads(thldBoard['vtu'])['tscore']);
            si = ScoringInfo();
            si.avList= avList;
            si.score = vtuCredibility;
            si.module = "VTU";
            print "VtuCredibility :",vtuCredibility, "VTU Threshold", vtuScore;
            if (vtuCredibility> vtuScore):
                si.status= "Blocked";
                print "Blocked";
            else:
                si.status = "Not Blocked"
                print "NotBlocked";
            del totalAV;
            return si.to_JSON();
	elif(vtuResponseCode==0 and vtfResponseCode==1):
            vtfCredibility =0.0;
            vtfScore =0.0;
            for avName,val in vtfScans.items():
                detected = val['detected'];
                if(detected):
                    avList.append(avName);
            jsontxtVTFSB = json.load(open(vtfScoreBoard));
            totalAV = len(jsontxtVTFSB);
            for av in avList:
                if(jsontxtVTFSB.has_key(av)):
                    sb = jsontxtVTFSB[av];
                    vtfCredibility += float(json.loads(sb)['credibility']);
            vtfCredibility = "%.2f" %(float(vtfCredibility) /totalAV);
            vtfScore = "%.2f" % float(json.loads(thldBoard['vtf'])['tscore']);
            si = ScoringInfo();
            si.avList= avList;
            si.score = vtfCredibility;
            si.module = "VTF";
            if (vtfCredibility> vtfScore):
                si.status= "Blocked";
                print "VTS Blocked";
            else:
                si.status= "Not Blocked";
                print "NotBlocked";
            del totalAV;
            return si.to_JSON();
        elif(vtuResponseCode==1 and vtfResponseCode==1):
            vtuCredibility =0.0;
            vtfCredibility =0.0;
            vtfuCredibility =0.0;
            vtfuScore =0.0;
            for avName,val in vtuScans.items():
                detected = val['detected'];
                if(detected):
                    avList.append(avName);
            jsontxtVTUSB = json.load(open(vtuScoreBoard));
            totalAV = len(jsontxtVTUSB);
            for av in avList:
                if(jsontxtVTUSB.has_key(av)):
                    sb = jsontxtVTUSB[av];
                    vtuCredibility += float(json.loads(sb)['credibility']);
            vtuCredibility = "%.2f"%(float(vtuCredibility) /totalAV);
            for avName,val in vtfScans.items():
                detected = val['detected'];
                if(detected):
                    avList.append(avName);
            jsontxtVTFSB = json.load(open(vtfScoreBoard));
            totalAV = len(jsontxtVTFSB);
            for av in avList:
                if(jsontxtVTFSB.has_key(av)):
                    sb = jsontxtVTFSB[av];
                    vtfCredibility += float(json.loads(sb)['credibility']);
            vtfCredibility = "%.2f"%(float(vtfCredibility) /totalAV);
            vtfuCredibility = float(vtuCredibility) + float(vtfCredibility);
            vtfuScore = float(json.loads(thldBoard['vtfu'])['tscore']);
            si = ScoringInfo();
            si.avList= avList;
            si.score = vtfuCredibility;
            si.module = "VTFU";
            print "VtFUCredibility :",vtfuCredibility, "VTFU Threshold", vtfuScore;
            if (vtfuCredibility>vtfuScore):
                si.status= "Blocked";
                print "VTFU Blocked";
            else:
                si.status= "Not Blocked";
                print "NotBlocked";
            del totalAV;
            return si.to_JSON();
        else:
            print "No record found in VTU and VTF";
    
    def generateScoreBoard(self,moduleType, malSampleCollection, normalSampleCollection):
        print "Performing malicious calibration for URL";
        s = ScoreCalibration();
        webAPI = WebAPI();
        if (moduleType =="-vtu"):
            scoreBoardName =  baseFolderScoring + moduleType.replace("-","").upper() + "_ScoreBoard.txt";
        elif(moduleType=="-vtf"):
            scoreBoardName =  baseFolderScoring +moduleType.replace("-","").upper() + "_ScoreBoard.txt";
        else:
            print "Unable to generate score board, cannot identify module type.";
            exit();
        scoreCollection = {};
        listScoreRef = {};
        avList = list();
        malSampleSize= len(malSampleCollection);
        remaining = len(malSampleCollection);
        for data in malSampleCollection:
            retry= 3;
            remaining = remaining -1;
            print "Remaining sample for ", moduleType.upper() , remaining;
            jsonResult = "";
            while(retry>0):
                if(moduleType=="-vtu"):
                    jsonResult = webAPI.urlVTAPIQuery(data);
                elif(moduleType=="-vtf"):
                    jsonResult = webAPI.sha1VTAPIQuery(data);
                if (jsonResult!=0):
                    retry = 0;
                    jsonResCode = int(jsonResult['response_code']);
                    if (jsonResCode == 1):
                        avList = list();
                        for avName, avResult in jsonResult['scans'].iteritems():
                            detected = avResult['detected'];
                            if (detected):
                                avList.append(avName);
                                print "Detected by: ", avName;
                                isExisting = scoreCollection.has_key(avName.strip());
                                vtScoring= VTScoreBoard();
                                if (isExisting):
                                    vtScoring = json.loads(scoreCollection.get(avName));
                                    noOfDetected = vtScoring['detected'];
                                    noOfDetected += 1;
                                    detectionRate = "%.2f" %((noOfDetected / float(malSampleSize))*100);
                                    vtScoring['detected'] = noOfDetected;
                                    vtScoring['detectionRate'] = detectionRate;
                                    vtScoring['credibility'] = "%.2f" %(float(vtScoring['detectionRate']) - float(vtScoring['fpRate']));
                                    scoreCollection[avName.strip()] = json.dumps(vtScoring);
                                else:
                                    vtScoring.detected=1;
                                    vtScoring.detectionRate= "%.2f" %((vtScoring.detected / float(malSampleSize))*100);
                                    vtScoring.credibility = "%.2f" %(float(vtScoring.detectionRate) - float(vtScoring.fpRate));
                                    scoreCollection[avName.strip()] = vtScoring.to_JSON();
                                del vtScoring, isExisting;
                            else:
                                print "Not detected by ", avName;
                        scoreRef = ScoreRef();
                        setattr(scoreRef,'avList',avList);
                        setattr(scoreRef,'score',0);
                        listScoreRef[data] = scoreRef.to_JSON();
                        del scoreRef, avList;
                    else:
                        print "No record found in VT";
                else:
                    print "http connection problem";
                    print "trying to connect";
                    retry =retry -1;
        s.updateScoreBoard("-mal",scoreBoardName ,scoreCollection);
        updatedScoreRef = s.initScoreRef("-mal", moduleType, listScoreRef);
        s.generateScoreRef(scoreBoardName, updatedScoreRef);
        del scoreCollection, listScoreRef;
        scoreCollection = {};
        listScoreRef = {};
        normalSampleSize = len(normalSampleCollection);
        remaining = len(normalSampleCollection);
        for data in normalSampleCollection:
            retry =3;
            remaining = remaining -1;
            print "Remaining sample for ", moduleType.upper() , remaining;
            while(retry>0):
                if(moduleType=="-vtu"):
                    jsonResult = webAPI.urlVTAPIQuery(data);
                elif(moduleType=="-vtf"):
                    jsonResult = webAPI.sha1VTAPIQuery(data);
                print "Remaining data: ", remaining;
                if (jsonResult!=0):
                    retry = 0;
                    jsonResCode = int(jsonResult['response_code']);
                    if (jsonResCode == 1):
                        avList = list();
                        for avName, avResult in jsonResult['scans'].iteritems():
                            detected = avResult['detected'];
                            if (detected):
                                avList.append(avName);
                                print "Detected by: ", avName;
                                isExisting = scoreCollection.has_key(avName.strip());
                                vtScoring= VTScoreBoard();
                                if (isExisting):
                                    vtScoring = json.loads(scoreCollection.get(avName));
                                    noofFP = vtScoring['fp'];
                                    noofFP += 1;
                                    fpRate = "%.2f" %((noofFP / float(normalSampleSize))*100);
                                    vtScoring['fp'] = noofFP;
                                    vtScoring['fpRate'] = fpRate;
                                    vtScoring['credibility'] = "%.2f" %(float(vtScoring['detectionRate']) - float(vtScoring['fpRate']));
                                    scoreCollection[avName.strip()] = json.dumps(vtScoring);
                                else:
                                    vtScoring.fp=1;
                                    vtScoring.fpRate= "%.2f" %((vtScoring.fp / float(normalSampleSize))*100);
                                    vtScoring.credibility = "%.2f" %(float(vtScoring.detectionRate) - float(vtScoring.fpRate));
                                    scoreCollection[avName.strip()] = vtScoring.to_JSON();
                                    del vtScoring, isExisting;
                            else:
                                print "Not detected by ", avName;
                        scoreRef = ScoreRef();
                        setattr(scoreRef,'avList',avList);
                        setattr(scoreRef,'score',0);
                        listScoreRef[data] = scoreRef.to_JSON();
                        del scoreRef, avList;
                    else:
                        print "No record found in VT";
                else:
                    print "possible http connection error";
                    print "trying to reconnect..";
                    retry=retry-1;
        s.updateScoreBoard("-nonmal",scoreBoardName ,scoreCollection);
        updatedScoreRef = s.initScoreRef("-nonmal", moduleType, listScoreRef);
        s.generateScoreRef(scoreBoardName, updatedScoreRef);
        del scoreCollection,listScoreRef;
            
    def showScoreBoard(self, scoreBoardName):
        if(scoreBoardName=="-vtu"):
            loc = vtuScoreBoard;  
        elif(scoreBoardName=="-vtf"):
            loc = vtfScoreBoard;
        jsonScoreBoard = json.load(open(loc));
        totalAV = len(jsonScoreBoard);
        totalCredibility=0.0;
        print scoreBoardName.replace("-","").upper(), "ScoreBoard:";
        ptable = prettytable.PrettyTable(["AV Name","Detected","Detection%","FP","FP%","Credibility"]);
        ptable.padding_width = 1
        ptable.align["AV Name"] = "l";
        ptable.align["Detected"] = "l";
        ptable.align["Detection%"] = "l";
        ptable.align["FP"] = "l";
        ptable.align["FP%"] = "l";
        ptable.align["Credibility"] = "l";
        for key,val in jsonScoreBoard.items():
            jsonVal =json.loads(val);
            totalCredibility +=float(jsonVal['credibility']);
            ptable.add_row([key,jsonVal['detected'],jsonVal['detectionRate'],jsonVal['fp'],jsonVal['fpRate'],jsonVal['credibility']])
        print ptable;
        print "Total AV: ", totalAV;
        print "Credibility: ", "%.2f" %(totalCredibility/totalAV);
        del ptable,jsonScoreBoard;
    
    
    
