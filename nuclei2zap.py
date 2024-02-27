#!/usr/bin/env python

import sys
import yaml
import re
import argparse
import os

def checksupported(yamlraw, yamlfile):
    if "http" not in yamlfile:
        print("Template does not use http method.")
        return True
    if len(yamlfile["http"]) > 1:
        print("The template sends multiple requests, this is not supported.")
        return True
    if "raw" in yamlfile["http"][0]:
        if len(yamlfile["http"][0]["raw"]) > 1:
            print("The template sends multiple requests, this is not supported.")
            return True
    #List of variables supported by the script
    varsupported = ["BaseURL","RootURL","Hostname","Host","Port","Path","File","Scheme"]
    pattern = r'\{\{([^\}]+)\}\}'
    varused = re.findall(pattern, yamlraw)
    for variable in varused:
        if variable not in varsupported:
            print(f'Variable {variable} is not supported, template won\'t be converted.')
            return True

    for matcher in yamlfile["http"][0]["matchers"]:
        #Not supported matchers
        if matcher["type"] == "dsl" or matcher["type"] == "size" or matcher["type"] == "binary" or matcher["type"] == "xpath":
            print("Matcher type not supported.")
            return True

def path_variable(URL):
    #Looks for nuclei path variables and replacing them for template literals
    URLvariables = ['{{BaseURL}}','{{RootURL}}','{{Hostname}}','{{Host}}','{{Port}}','{{Path}}','{{File}}','{{Scheme}}']
    for var in URLvariables:
        if var == '{{BaseURL}}':
            URL = URL.replace('{{BaseURL}}','${BaseURL}')
        elif var == '{{RootURL}}':
            URL = URL.replace('{{RootURL}}','${RootURL}')
        elif var == '{{Hostname}}':
            URL = URL.replace('{{Hostname}}','${Hostname}')
        elif var == '{{Host}}':
            URL = URL.replace('{{Host}}','${Host}')
        elif var == '{{Port}}':
            URL = URL.replace('{{Port}}','${Port}')
        elif var == '{{Path}}':
            URL = URL.replace('{{Path}}','${Path}')
        elif var == '{{File}}':
            URL = URL.replace('{{File}}','${FileName}')
        elif var == '{{Scheme}}':
            URL = URL.replace('{{Scheme}}','${Scheme}')
    return URL

def replace_condition(yamlfile,template):
    #Function that will replace the condition to raise an alert
    requests = yamlfile["http"][0]
    final_conditions = []
    for matcher in requests["matchers"]:
        matchtype = matcher["type"]
        if matchtype == "status":
            status_matchs = []
            for status in matcher["status"]:
                condition = "msg.getResponseHeader().getStatusCode() == " + str(status)
                status_matchs.append(condition)
            if len(status_matchs) > 1:
                status_condition = "(" + " || ".join(status_matchs) + ")"
            else:
                status_condition = status_matchs[0]
            final_conditions.append(status_condition)
        elif matchtype == "word":
            words_matchs = []
            for word in matcher["words"]:
                #Escape and replace special characters so they don't throw an error, this is due js search function processes regex
                word = re.escape(word).replace('\\','\\\\')
                word = word.replace("\'","\\'")
                if "part" in matcher:
                    matchpart = matcher["part"]
                else:
                    matchpart = "body"
                if matchpart == "header":
                    words_matchs.append("msg.getResponseHeader().toString().search('" + word + "') != -1")
                elif matchpart == "body":
                    words_matchs.append("msg.getResponseBody().toString().search('" + word + "') != -1")
            if len(words_matchs) > 1:
                if "condition" in matcher:
                    wordscondition = matcher["condition"]
                else:
                    wordscondition = "or"
                if wordscondition == "and":
                    words_condition = "(" + " && ".join(words_matchs) + ")"
                elif wordscondition == "or":
                    words_condition = "(" + " || ".join(words_matchs) + ")"
            else:
                words_condition = words_matchs[0]
            final_conditions.append(words_condition)
        elif matchtype == "regex":
            #No changes made here since regex matches are expected to be proper regex
            regex_matchs = []
            for regx in matcher["regex"]:
                if "part" in matcher:
                    matchpart = matcher["part"]
                else:
                    matchpart = "body"
                if matchpart == "header":
                    regex_matchs.append("msg.getResponseHeader().toString().search('" + regx + "') != -1")
                elif matchpart == "body":
                    words_matchs.append("msg.getResponseBody().toString().search('" + regx + "') != -1")
            if len(regex_matchs) > 1:
                if "condition" in matcher:
                    regexcondition = matcher["condition"]
                else:
                    regexcondition = "or"
                if regexcondition == "and":
                    regex_condition = "(" + " && ".join(regex_matchs) + ")"
                elif regexcondition == "or":
                    regex_condition = "(" + " || ".join(regex_matchs) + ")"
            else:
                regex_condition = regex_matchs[0]
            final_conditions.append(regex_condition)
    if len(final_conditions) > 1:
        #Check if matchers-condition is declared, if it isn't by default is set to or (according to nuclei documentation)
        if "matchers-condition" in requests:
            matchcondition = requests["matchers-condition"]
        else:
            matchcondition = "or"
        if matchcondition == "and":
            conditionbuilder = " && ".join(final_conditions)
        elif matchcondition == "or":
            conditionbuilder = " || ".join(final_conditions)
    else:
        conditionbuilder = final_conditions[0]
    template = template.replace('{condition}',conditionbuilder)
    return template

def replace_info(yamlfile,template):
    #This function mostly fills up some info that will go into the alerts
    severity = yamlfile["info"]["severity"]
    if "description" in yamlfile["info"]:
        description = yamlfile["info"]["description"].replace("\n", "\\n")
    else:
        description = ""
    if "reference" in yamlfile["info"]:
        reference = '\\n'.join(yamlfile["info"]["reference"])
    else:
        reference = ""
    if severity.lower() == "low":
        template = template.replace("{risk}","1")
    elif severity.lower() == "medium":
        template = template.replace("{risk}","2")
    elif severity.lower() == "high" or severity.lower() == "critical":
        template = template.replace("{risk}","3")
    else:
        template = template.replace("{risk}","0")

    description = description.replace("\'","\\'")
    template = template.replace('{description}',description)
    template = template.replace('{reference}',reference)
    return template

def convert_raw(yamlfile):
    opentemplate = open("rawtemplate.js",'r')
    template = opentemplate.read()
    opentemplate.close()

    requests = yamlfile["http"][0]
    #Splits the request in header and body
    if requests["raw"][0].find("\n\n") != -1:
        rawheader, rawbody = requests["raw"][0].split("\n\n",1)
    else:
        rawheader = requests["raw"][0]
        rawbody = ""
    #Making some string replaces, otherwise the script generated will throw errors
    rawheader = rawheader.replace("\n","\\n")
    rawbody = rawbody.replace("\n", "\\n")
    rawbody = rawbody.replace("\'", "\\'")
    rawheader = path_variable(rawheader)
    template = template.replace("{RawHeader}",rawheader)
    template = template.replace("{RawBody}",rawbody)
    template = replace_condition(yamlfile,template)
    template = replace_info(yamlfile, template)

    return template

def convert_passive(yamlfile):
    opentemplate = open("passivetemplate.js",'r')
    template = opentemplate.read()
    opentemplate.close()

    template = replace_condition(yamlfile, template)
    template = replace_info(yamlfile, template)
    return template

def convert_requests(yamlfile):
    opentemplate = open("reqtemplate.js",'r')
    template = opentemplate.read()
    opentemplate.close()

    requests = yamlfile["http"][0]
    URLs = requests["path"]
    for i in range(0,len(URLs)):
        URLs[i] = '`' + URLs[i] + '`'
    URL = ','.join(URLs)

    URL = path_variable(URL)
    template = template.replace('{BaseURL}',URL)
    template = template.replace('{ReqMethod}',requests["method"])
    #Set body
    if "body" in requests:
        body = requests["body"].replace("\'","\\'")
        body = body.replace("\n","\\n")
        template = template.replace('{ReqBody}',body)
    else:
        template = template.replace('{ReqBody}',"")
    template = replace_condition(yamlfile, template)
    template = replace_info(yamlfile, template)

    #Set headers
    currentheader = 0
    headersbuilder = ""
    if "headers" in requests:
        template = template.replace('{addedHeaders}',"true")
        for header in requests["headers"]:
            headersbuilder += '"' + header + '":"' + requests["headers"][header] + '"'
            currentheader += 1
            if currentheader < len(requests["headers"]):
                headersbuilder += ","
        template = template.replace('{NucHeader}',headersbuilder)
    else:
        template = template.replace('{addedHeaders}',"false")
        template = template.replace('{NucHeader}',headersbuilder)

    #Check if the script stops after success
    if "stop-at-first-match" in requests:
        if requests["stop-at-first-match"]:
            stopatfirstmatch = "true"
        else:
            stopatfirstmatch = "false"
    else:
        stopatfirstmatch = "false"
    template = template.replace('{stop-at-first-match}',stopatfirstmatch)

    return template

def nuclei_convert(template_path, forced):
    openfile = open(template_path)
    rawfile = openfile.read()
    parsed = yaml.safe_load(rawfile)
    openfile.close()
    print(f'converting {template_path}')
    try:
        isNotSupported = checksupported(rawfile, parsed)
        #If template uses a function that is not supported won't even try to convert it
        if isNotSupported:
            if forced:
                print("Forcing generation of file.")
            else:
                return

        requests = parsed["http"][0]
        passivescript = False
        #Selects the js template to use
        if "raw" in requests:
            template = convert_raw(parsed)
        elif requests["method"].lower() == "get" and "headers" not in requests and requests["path"][0] == '{{BaseURL}}':
            passivescript = True
            template = convert_passive(parsed)
        else:
            template = convert_requests(parsed)

        if "redirects" in requests:
            if requests["redirects"]:
                redirects = "true"
            else:
                redirects = "false"
            template = template.replace("{Redirects}",redirects)
        else:
            template = template.replace("{Redirects}","false")
        #Writing file
        scriptName = parsed["id"]
        if passivescript:
            output = open("passive/" + scriptName + ".js",'w')
            output.write(template)
            output.close()
        else:
            output = open("active/" + scriptName + ".js",'w')
            output.write(template)
            output.close()

    except Exception:
        print("An error ocurred, can't convert.")
        return

def main():
	
    parser = argparse.ArgumentParser(description="Simple script to convert Nuclei templates a Bchecks to Zap scripts.")
    parser.add_argument("-t", "--templates", help="Template file o directory to convert.", action="store", required=True)
    parser.add_argument("-f", "--force", help="Try to generate a script for the files that can't be converterd completely.", action="store_true")
    args = parser.parse_args()

    if not os.path.isdir("active"):
        os.mkdir("active")
    if not os.path.isdir("passive"):
        os.mkdir("passive")
    if os.path.isfile(args.templates):
        nuclei_convert(args.templates, args.force)
    else:
        filelist = os.listdir(args.templates)
        for temp in filelist:
            if temp.find(".yaml") != -1:
                nuclei_convert(args.templates + "/" + temp, args.force)

if __name__ == '__main__':
    main()