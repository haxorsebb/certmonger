#!/usr/bin/python
"""
 Overly simplistic certmonger helper, conforming to
 https://git.fedorahosted.org/cgit/certmonger.git/tree/doc/helpers.txt
 and using the anchor v1 API documented at
 https://github.com/openstack/anchor/blob/master/doc/source/api.rst

 Error handling could use some work, and the configuration and client
 credentials are hard-coded below.
"""
import os
import sys

import requests

def main():
    """
    Check $CERTMONGER_OPERATION to see what we should do.  We only support the
    (mandatory) SUBMIT and (optional) IDENTIFY and FETCH-ROOTS operations, and
    only FETCH-ROOTS if the (hard-coded) server address uses the "https"
    scheme.  For every other operation, we exit with status indicating that we
    don't support it.

    If the operation isn't set, we assume we're in SUBMIT mode, and to make
    things easier to troubleshoot, if the CSR isn't provided in the
    environment, we try to read one from stdin.

    If we're in SUBMIT mode, we post the CSR to the "sign" endpoint for the
    "default" RA and read back either a certificate or an error message.

    In FETCH-ROOTS mode, we read the root certificate and relay it back.

    In IDENTIFY mode, we just output version information.

    Anything else, we don't support.
    """

    # These would be better off as command line options or settings in a
    # configuration file, but since this is just a sample, we just hard-code
    # them.
    server = "http://localhost:5016/v1/%s/default"
    user = "myusername"
    secret = "simplepassword"

    # Key off of what we're being asked to do.  We always get an instant reply,
    # so we won't ever be called to "POLL".  We don't currently have any
    # parameters that absolutely must be specified, so there's no need to list
    # them in out in a handler for "GET-NEW-REQUEST-REQUIREMENTS".  We don't
    # have a notion of enrollment profiles, so there's no need to handle
    # "GET-SUPPORTED-TEMPLATES".
    operation = os.getenv("CERTMONGER_OPERATION")

    if operation == "IDENTIFY":
        # Output some version information.
        sys.stdout.write("Anchor (anchor-submit.py 0.0)\n")
        sys.exit(0)

    if operation is None or operation == "SUBMIT":
        # Submit the signing request.  If we succeed, print it and return 0.
        pem = os.getenv("CERTMONGER_CSR")
        # Make it easier to debug this tool, and troubleshoot using this tool,
        # by attempting to read the CSR from stdin if it isn't provided in the
        # environment.  (The daemon always invokes us with the value set in the
        # environment and stdin connected to /dev/null.)
        if pem is None:
            pem = sys.stdin.read()
        payload = {}
        payload["user"] = user
        payload["secret"] = secret
        payload["encoding"] = "pem"
        payload["csr"] = pem
        response = requests.post(url=(server%"sign"), data=payload)
        if response is not None and response.ok and \
           response.text is not None and response.text != "":
            # Succeeded!  Send the PEM-formatted certificate to stdout and exit
            # with status 0 to indicate success.
            sys.stdout.write(response.text)
            sys.exit(0)
        else:
            # Rejected?  Print the error message and exit with status 2 to
            # indicate that the CA rejected our request.
            if response != None:
                sys.stdout.write(response.text.replace("\n\n", "\n").strip()+"\n")
            sys.exit(2)

    if operation == "FETCH-ROOTS":
        if server.startswith("https:"):
            # Fetch the root certificate.  The expected output format is kind of funky,
            # but since we don't have anything elaborate, we're not too upset about it.
            payload = {}
            payload["encoding"] = "pem"
            response = requests.get(url=(server%"ca"), params=payload)
            if response != None and response.ok and response.text != None and response.text != "":
                # Succeeded!  Send a suggested nickname and the PEM-formatted
                # certificate to stdout and exit with status 0 to indicate
                # success.  (If the CA starts sending us more than one
                # certificate, or switches to a different format, we'll have to
                # do some parsing, but for now this is enough.)
                sys.stdout.write("Anchor CA Root Certificate\n")
                sys.stdout.write(response.text)
                sys.exit(0)
            else:
                # Rejected?  Print the error message and exit with status 2 to
                # indicate that the CA rejected our request, though that really
                # shouldn't happen.
                if response != None:
                    sys.stdout.write(response.text.replace("\n\n", "\n").strip()+"\n")
                sys.exit(2)
        else:
            # We don't support fetching roots from non-authenticated sources,
            # so indicate that we don't support fetching them.
            sys.exit(6)

    # We don't support this operation, whatever it is, so signal that.
    sys.exit(6)

main()
