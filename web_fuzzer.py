from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

from java.util import List, ArrayList

import random

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()

    callbacks.registerIntruderPayloadGeneratorFactory(self)

    return

  def getGeneratorName(self):
    return "WebFuzzer Payload Generator"

  def createNewInstance(self, attack): 
    return WebFuzzer(self, attack)

class WebFuzzer(IIntruderPayloadGenerator):
  def __init__(self, extender, attack):
    self._extender = extender
    self._helpers  = extender._helpers
    self._attack   = attack
    print "WebFuzzer initialized"
    self.payloadList = "/Users/dreher/Developer/SecLists/Fuzzing/XSS-BruteLogic.txt"
    self.max_payloads = self.getTotalPayloads(self.payloadList) + 1 # Total payloads plus the original one
    self.num_payloads = 1
    
    return

  def getTotalPayloads(self,fileName):
    count = 0
    for line in open(fileName).xreadlines(  ): count += 1
    return count

  def hasMorePayloads(self):
    print "hasMorePayloads called."
    if self.num_payloads == self.max_payloads:
      print "No more payloads."
      return False
    else:
      print "More payloads. Continuing."
      return True

  def getNextPayload(self,current_payload):   

    # convert into a string
    payload = "".join(chr(x) for x in current_payload)

    # call our simple mutator to fuzz the POST
    payload = self.mutate_payload(payload)

    # increase the number of fuzzing attempts
    self.num_payloads += 1

    return payload

  def reset(self):
    self.num_payloads = 0
    return

  # Simple mutation method for our payload
  def mutate_payload(self,original_payload):

    # select a random offset in the payload to mutate
    offset  = random.randint(0,len(original_payload)-1)
    payload = original_payload[:offset]

    # Lets load the payloads from a file
    payload += open(self.payloadList).readlines()[:self.num_payloads][-1].rstrip("\n")

    # add the remaining bits of the payload 
    payload += original_payload[offset:]

    return payload