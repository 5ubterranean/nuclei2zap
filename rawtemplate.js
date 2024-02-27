// Note that new active scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page. 
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */
ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
CopyOnWriteArrayList = Java.type("java.util.concurrent.CopyOnWriteArrayList");
URI = Java.type("org.apache.commons.httpclient.URI");

stopScan = false;
function scanNode(as, msg) {
    // Debugging can be done using println like this
    //print('scan called for url=' + msg.getRequestHeader().getURI().toString());

    // Copy requests before reusing them
    msg = msg.cloneRequest();
    header = msg.getRequestHeader();
        
    BaseURL = header.getURI().getURI();
    RootURL = header.getURI().getScheme() + "://" + header.getURI().getHost() + ":" + header.getURI().getPort().toString();
    Hostname = header.getURI().getHost() + ":" + header.getURI().getPort().toString();
    Host = header.getURI().getHost();
    Port = header.getURI().getPort().toString();
    Path = header.getURI().getPath();
    FileName = header.getURI().getName();
    Scheme = header.getURI().getScheme();
    
    header.setMessage(`{RawHeader}`)
    msg.getRequestBody().setBody('{RawBody}')
    //Stores the scanned paths on a global variable so they don't get scanned again
    currentURI = msg.getRequestHeader().getURI().getURI()
    concurredScanned = new CopyOnWriteArrayList()
    alreadyScanned = ScriptVars.getGlobalCustomVar(this['zap.script.name']);
    if (alreadyScanned != null) {
        for ( i = 0; i < alreadyScanned.length; i++){
            concurredScanned.add(alreadyScanned[i])
        }
    }
    if (concurredScanned.indexOf(currentURI) != -1) {
        return;
    }
    concurredScanned.add(currentURI);
    ScriptVars.setGlobalCustomVar(this['zap.script.name'],concurredScanned);
    newURI = new URI(currentURI);
    msg.getRequestHeader().setURI(newURI);

    // sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    as.sendAndReceive(msg, {Redirects}, false);

    if ({condition}){
        addAlert(as, msg, header.getURI().getURI(), header.getURI().toString());
    }

}
    
function addAlert(as, msg, evidence, uri) {
    // risk: 0: info, 1: low, 2: medium, 3: high
    var alertRisk = {risk}
    // confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
    var alertConfidence = 2
    var alertTitle = this['zap.script.name']
    var alertDesc = '{description}'
    var alertSolution = ''
    var alertInfo = ''
    var cweId = 0
    var wascId = 0
    var tagName = ""
    var tagValue = ""
    var reference = "{reference}"
    var parameter = ""
    var attack = ""
    var inputVector = ""

    newAlert = as.newAlert();
    newAlert.setRisk(alertRisk);
    newAlert.setConfidence(alertConfidence);
    newAlert.setName(alertTitle);
    newAlert.setDescription(alertDesc);
    newAlert.setSolution(alertSolution);
    newAlert.setOtherInfo(alertInfo);
    newAlert.setCweId(cweId);
    newAlert.setWascId(wascId);
    newAlert.setMessage(msg);
    newAlert.setEvidence(evidence);
    newAlert.setUri(uri);
    newAlert.addTag(tagName, tagValue);
    newAlert.setReference(reference);
    newAlert.setParam(parameter);
    newAlert.setAttack(attack);
    newAlert.setInputVector(inputVector);
    newAlert.raise();

}



