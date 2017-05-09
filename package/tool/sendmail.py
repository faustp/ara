#!/usr/bin/env python

import smtplib
import base64,os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.MIMEBase import MIMEBase
from email import Encoders

class SendMail:
    sender = 'ARAPOC@PH.TRENDMICRO.COM';
    receiver = ['faustine_padit@trendmicro.com','christopher_talampas@trendmicro.com','paul_pajares@trendmicro.com','roel_reyes@trendmicro.com','karla_agregado@trendmicro.com'];
    def __init__(self,attachment):
        self.attachment = attachment;
        pass
    def __dell__(self,):
        pass
    def send(self,):
        try:
            fo = open(self.attachment, "rb");
            filecontent = fo.read();
            encodedcontent = base64.b64encode(filecontent);
            text = """Hello,\n\n kindly see attached file\n\n\n**********\nProject ARA POC\n**********""";
            msg = MIMEMultipart('alternative');
            msg['Subject'] = "Project ARA POC Result";
            msg['From'] = self.sender;
            msg['To'] = ", ".join(self.receiver);
            part1 = MIMEText(text, 'plain');
            part2 = MIMEBase('application', "octet-stream");
            part2.set_payload(open(self.attachment,"rb").read());
            Encoders.encode_base64(part2);
            part2.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(self.attachment));
            msg.attach(part2);
            msg.attach(part1);
            smtpObj = smtplib.SMTP('relay.trendmicro.com');
            smtpObj.sendmail(self.sender, self.receiver, msg.as_string());
            smtpObj.quit();
            smtpObj.close();
            print "Successfully sent email";
        except Exception as ex:
            print "Error: unable to send email", ex;
