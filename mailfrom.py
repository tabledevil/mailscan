#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import email
import hashlib
import sys
import re
import subprocess

def get_mailaddresses_from_field(msgfield):

    pass

emailaddresspatter_rfc5322=r'''(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'''
nodes={}
encoding='latin-1'
emailpattern=re.compile(emailaddresspatter_rfc5322,re.IGNORECASE)
basepath=sys.argv[1]
basecount=len(basepath.split(os.sep))-1
for root, dirs, files in os.walk(basepath):
    path = root.split(os.sep)
    relpath = os.sep.join(root.split(os.sep)[basecount:])
    for file in files:
        filename=root+os.sep+file
        relfilename=relpath+os.sep+file
        output=subprocess.run(["file",filename],stdout=subprocess.PIPE).stdout.decode('utf-8')
        filetype=output.split(":")[1]
        # print(file + ":" + filetype,end='')
        if True or "RFC 822 mail" in filetype:
            try:
                msg=email.message_from_file(open(filename,'r',encoding=encoding))
            except:
                continue

            list_senders=set()
            if "From" in msg.keys():
                for sender in email.header.decode_header(msg.get("From")):
                    print(sender)
                    if sender[1] is None:
                        sender=sender[0]
                    else:
                        sender=sender[0].decode(sender[1])

                    if isinstance(sender, bytes):
                        sender=sender.decode("utf-8")

                    foundmail=emailpattern.findall(sender)
                    if foundmail is not None:
                        for ma in foundmail:
                            list_senders.add(ma)
            if len(list_senders)>0:
                # print(file+":"+str(list_senders))
                pass
            else:
                print(relfilename)
                # print(filetype)

                    # print(sender)
                    # print(sender)
                # msg_from=msg.get("From").replace(";",",")
                # print(msg.get("From"))
                # decoded_type=type(email.header.decode_header(msg.get("From"))[0][0])
                # print(decoded_type)
            #     print(email.header.decode_header(msg.get("From")))
            #     print(email.header.decode_header(msg.get("From"))[0][0])
            #     if type(email.header.decode_header(msg.get("From"))[0][0]) is bytes:
            #         print(email.header.decode_header(msg.get("From"))[0][0].decode("utf-8"))
            #     else:
            #         print(email.header.decode_header(msg.get("From"))[0][0])
            # else:
                # msg_from="UNKNOWN"
                # if "Date" in msg.keys():
                #     msg_date=msg.get("Date").replace(";",",")
                # else:
                #     msg_date="UNKNOWN"
            #
            # if msg.is_multipart():
            #     i=0
            #     for part in msg.walk():
            #         if "From" in part.keys():
            #             i+=1
            #             # msg_from=msg.get("From").replace(";",",")
            #             # print("MULTI: "+part.get("From"))
            #         else:
            #             # print("MULTI: PART WITHOUT FROM")
            #             msg_from="UNKNOWN"
            #             if "Date" in msg.keys():
            #                 msg_date=msg.get("Date").replace(";",",")
            #             else:
            #                 msg_date="UNKNOWN"
                # if i>1 : print ("MAIL WITH MULTIPLE FROMS :" + relfilename)
                # for part in msg.walk():
                #     if part.get_filename() is not None:
                #         att_hash=hashlib.md5(part.get_payload(decode=True)).hexdigest()
                #         att_filename=part.get_filename().replace(";",",")
                #         att_mimetype=part.get_content_type().replace(";",",")
                #         msg_filename=relfilename.replace(";",",")
                #         print("%s;%s;%s;%s;%s;%s" % (att_filename,att_mimetype,att_hash,msg_date,msg_from,msg_filename))
                #         # print("%s;%s" % (part.get_filename(),md5.hexdigest()))
            # else:

                # pass
# =?utf-8?B?RGlyZWN0b3JhdGUgRGlyZWN0b3IgKERyLiBMw6FzemzDsyBGYXpla2FzKQ==?=
# =?utf-8?Q?Combat=20Helicopter=202017?=
