cwe_dictionary_file=open('919.csv')
cwe_dictionary={}
cwe_dictionary_file=cwe_dictionary_file.readlines()
for i in range(len(cwe_dictionary_file)):
    if i!=0:
        ls=cwe_dictionary_file[i].split(",")
        cwe_dictionary[ls[0]]=" ".join(cwe_dictionary_file[len(ls[0]):])
import json, csv,re
totalVulnerabiltyString="Year,Mobile Vulnerablities,Total Vulnerabities"
for i in range(14,25):
    num=str(i)
    if len(num)==1:
        num="0"+num
    fileName="nvdcve-1.1-20"+num+".json"
    file=open(fileName,'r')
    data=json.load(file)
    data=data['CVE_Items']
    nuclear_data=open("nuclear_data_"+num+".txt",'w')
    totalVulnerablities=0
    possibleScada=0
    for i in data:
        #KEYS: 'cve', 'configurations', 'impact', 'publishedDate', 'lastModifiedDate'
        #cve Keys 'data_type', 'data_format', 'data_version', 'CVE_data_meta', 'problemtype', 'references', 'description'
        #problemtype keys 'problemtype_data' which leads to 'description' which leads to 'value' which has CWE info
        #description Key 'description_data' (is a list with one value a JSON) to access the value use 'value'
        CVE_ID=i['cve']['CVE_data_meta']['ID']
        CVSS_data=i['impact']
        affected_software = ""
        config=i['configurations']
        nodes=config['nodes']
        cpe23URI=''
        containsRange=False
        publishedDate=i["publishedDate"]
        found_bool=False
        for stuff in nodes:
            if "cpe_match" in stuff.keys():
                cpe_match=stuff['cpe_match']
                for more_stuff in cpe_match:
                    if "cpe23Uri" in more_stuff.keys():
                        cpe23URI=more_stuff["cpe23Uri"]
                    if "versionStartIncluding" in more_stuff.keys():
                        if more_stuff["versionStartIncluding"][:1]=="1" or more_stuff["versionStartIncluding"][:1]=="0":
                            found_bool=True
                    if "versionStartExcluding" in more_stuff.keys():
                        if more_stuff["versionStartExcluding"][:1]=="1" or more_stuff["versionStartExcluding"][:1]=="0":
                            found_bool=True
                    if "versionEndIncluding" in more_stuff.keys():
                        if more_stuff["versionEndIncluding"][:1]=="1" or more_stuff["versionEndIncluding"][:1]=="0":
                            found_bool=True
                        if not "versionStartIncluding" in more_stuff.keys() and not "versionStartExcluding" in more_stuff.keys():
                            found_bool=True
                    if "versionEndExcluding" in more_stuff.keys():
                        if more_stuff["versionEndExcluding"][:1]=="1" or more_stuff["versionEndExcluding"][:1]=="0":
                            found_bool=True
                        if not "versionStartIncluding" in more_stuff.keys() and not "versionStartExcluding" in more_stuff.keys():
                            found_bool=True
        accessVector=''
        severity=''
        complexity=''
        containsAccess=False
        containsSeverity=False
        containsComplexity=False
        foundational=False
        if "baseMetricV3" in CVSS_data.keys():
            accessVector=CVSS_data["baseMetricV3"]["cvssV3"]["attackVector"]
            severity=CVSS_data["baseMetricV3"]["cvssV3"]["baseSeverity"]
            complexity=CVSS_data["baseMetricV3"]["cvssV3"]["attackComplexity"]
            containsAccess=True
            containsSeverity=True
            containsComplexity=True
        elif "baseMetricV2" in CVSS_data.keys():
            accessVector=CVSS_data["baseMetricV2"]["cvssV2"]["accessVector"]
            severity=CVSS_data["baseMetricV2"]["severity"]
            complexity=CVSS_data["baseMetricV2"]["cvssV2"]["accessComplexity"]
            containsAccess=True
            containsSeverity=True
            containsComplexity=True
        CWE_id=""
        contains_cwe_id=False
        totalVulnerablities+=1
        if 'problemtype' in i['cve'].keys() and 'problemtype_data' in i['cve']['problemtype'] and len(i['cve']['problemtype']['problemtype_data'])>0 and len(i['cve']['problemtype']['problemtype_data'][0]['description'])>0:
            CWE_id=i['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
            contains_cwe_id=True
        summary=i['cve']['description']['description_data'][0]['value']
        arr=cpe23URI.split(":")
        if "version 1." in summary.lower() or "all version" in summary.lower() or "foundational" in summary.lower() or (len(arr)>5 and "1." == arr[5][:2] ) or (len(arr)>5 and "1." == arr[5][:2] )or found_bool:
            foundational=True
        #re.search("\sios\s",description)  or
        b=False
        if contains_cwe_id and CWE_id[4:] in cwe_dictionary:
            val=cwe_dictionary[CWE_id[4:]].lower()
        if "scada" in summary.lower() or 'scada' in cpe23URI.lower():
            nuclear_data.write(CVE_ID+'\n')
            nuclear_data.write(summary+"\n")
            if contains_cwe_id:
                nuclear_data.write(CWE_id+'\n')
            if containsAccess:
                nuclear_data.write(accessVector+'\n')
                nuclear_data.write("Severity: "+severity+'\n')
                nuclear_data.write("Complexity: "+complexity+'\n')
            nuclear_data.write("CPE 23 Uri: "+cpe23URI+'\n')
            if foundational:
                nuclear_data.write("foundational")
            else:
                nuclear_data.write("Not Foundational")
            nuclear_data.write("\nPublished Date: "+publishedDate)
            nuclear_data.write("\n\n")
            possibleScada+=1
    nuclear_data.close()
    file.close()
    print(possibleScada)
    print(totalVulnerablities)
    totalVulnerabiltyString+="\n"+num+","+str(possibleScada)+","+str(totalVulnerablities)
total_data=open("total_data.txt","w")
total_data.write(totalVulnerabiltyString)
total_data.close()