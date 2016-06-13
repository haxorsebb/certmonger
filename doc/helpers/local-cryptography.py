#!/usr/bin/python
"""
 Sample certmonger helper, conforming to
 https://git.fedorahosted.org/cgit/certmonger.git/tree/doc/helpers.txt
 which, rather than ferrying a signing request to a CA, signs things itself
 using python-cryptography, and produces its own certificates when asked
 for a list of root certificates.
"""
import datetime
import fcntl
import os
import sys
import uuid
from cryptography import utils
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

def create_ca_key(statedir, filename, password):
    """
    Creates a new private key for the CA, storing it in the specified file in
    the specified directory, protected by the specified password.  Any key that
    was already there is overwritten.

    Returns the key.
    """
    key = rsa.generate_private_key(public_exponent=0x10001,
                                   key_size=2048,
                                   backend=default_backend())
    encryption_algorithm = serialization.BestAvailableEncryption(password)
    keystring = key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.PKCS8,
                                  encryption_algorithm=encryption_algorithm)
    kfile = open(os.path.join(statedir, filename), mode="wb")
    kfile.write(keystring)
    kfile.close()
    return key

def load_ca_key(statedir, filename, password):
    """
    Attempt to load the private key for the CA from the specified file in the
    specified directory, decrypting it with the specified password.  If we fail
    to read it due to an IOError, assume it hasn't been created yet and call
    create_ca_key() to generate it.

    Returns the key.
    """
    try:
        kfile = open(os.path.join(statedir, filename), mode="rb")
        keystring = kfile.read()
        kfile.close()
        key = serialization.load_pem_private_key(keystring,
                                                 password,
                                                 backend=default_backend())
    except IOError:
        key = create_ca_key(statedir, filename, password)
    return key

def save_ca_cert(statedir, certfile, cert):
    """
    Saves a certificate in PEM form in the specified file in the specified
    directory.

    Returns nothing.
    """
    cfile = open(os.path.join(statedir, certfile), mode="wb")
    cfile.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
    cfile.close()

def save_ca_serial(statedir, serialfile, serial):
    """
    Saves a serial number in big endian binary form in the specified file in
    the specified directory.

    Returns nothing.
    """
    sfile = open(os.path.join(statedir, serialfile), mode="wb")
    sfile.write(utils.int_to_bytes(serial))
    sfile.close()

def create_ca_cert(cakey, subject, serial):
    """
    Creates a CA certificate for the specified private key with the specified
    subject and serial number.  If the serial number is not specified, generate
    a UUID and treat it as a 128-bit serial number.  If the subject name is not
    specified, generate a UUID and use it both as a serial number and to
    construct a subject name.

    The root certificate has a validity period of one year.

    Returns the new certificate and the serial number as an integer.
    """
    if subject is None:
        certuuid = uuid.uuid4()
        certuuidstring = str(certuuid).encode('ascii').decode('ascii')
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Local Signing Authority"),
                             x509.NameAttribute(NameOID.COMMON_NAME, certuuidstring)])
        serial = utils.int_from_bytes(certuuid.bytes, 'big')
    if serial is None:
        certuuid = uuid.uuid4()
        certuuidstring = str(certuuid).encode('ascii').decode('ascii')
        serial = utils.int_from_bytes(certuuid.bytes, 'big')
    now = datetime.datetime.utcnow()
    certpubkey = cakey.public_key()
    certski = x509.SubjectKeyIdentifier.from_public_key(certpubkey)
    certaki = x509.AuthorityKeyIdentifier.from_issuer_public_key(certpubkey)
    certku = x509.KeyUsage(True, False, False, False, False, True, True, False, False)
    certbasic = x509.BasicConstraints(ca=True, path_length=None)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now.replace(year=now.year+1))
    builder = builder.public_key(certpubkey)
    builder = builder.add_extension(certski, False)
    builder = builder.add_extension(certaki, False)
    builder = builder.add_extension(certku, False)
    builder = builder.add_extension(certbasic, True)
    cert = builder.sign(cakey, hashes.SHA256(), default_backend())
    return cert, serial

def create_ca_cert_and_serial(statedir, cakey, certfile, serialfile):
    """
    Creates a new CA certificate for the specified private key, saving them
    both to specified files in the specified directory.

    Returns the new certificate and the serial number as an integer.
    """
    (cert, serial) = create_ca_cert(cakey, None, None)
    save_ca_cert(statedir, certfile, cert)
    save_ca_serial(statedir, serialfile, serial)
    return cert, serial

def load_ca_cert_and_key_and_serial(statedir, keyfile, password, certfile, serialfile):
    """
    Reads the private key, CA certificate, and last-used serial number from the
    specified directory and files.  If the private key hasn't been created yet,
    creates it first.  If the certificate hasn't been created yet, generate a
    new one and a new serial number.

    If the certificate has less than half a year left before it goes invalid,
    generate a new key, use it to generate a new root certificate, and save it
    as the first in a file of possibly more than one certificate.

    Returns the signing certificate, its private key, and the last-used serial
    number as an integer.
    """
    cakey = load_ca_key(statedir, keyfile, password)
    try:
        cfile = open(os.path.join(statedir, certfile), mode="rb")
        oldcerts = cfile.read()
        cert = x509.load_pem_x509_certificate(oldcerts, backend=default_backend())
        cfile.close()
        cfile = open(os.path.join(statedir, serialfile), mode="rb")
        serial = utils.int_from_bytes(cfile.read(), 'big')
        cfile.close()
    except IOError:
        (cert, serial) = create_ca_cert_and_serial(statedir, cakey, certfile, serialfile)
        return cert, cakey, serial
    now = datetime.datetime.utcnow()
    if now.month > 6:
        threshold = now.replace(year=now.year+1, month=now.month-6)
    else:
        threshold = now.replace(month=now.month+6)
    if cert.not_valid_after < threshold:
        # Running out of time -> generate a new key and cert, and save the
        # old cert(s) in the bundle.
        newkey = create_ca_key(statedir, keyfile+".new", password)
        newcert, newserial = create_ca_cert(newkey, cert.subject, serial + 1)
        save_ca_cert(statedir, certfile+".new", newcert)
        cfile = open(os.path.join(statedir, certfile+".new"), mode="ab")
        cfile.write(oldcerts)
        cfile.close()
        os.rename(os.path.join(statedir, keyfile+".new"),
                  os.path.join(statedir, keyfile))
        os.rename(os.path.join(statedir, certfile+".new"),
                  os.path.join(statedir, certfile))
        save_ca_serial(statedir, serialfile, newserial)
        return newcert, newkey, newserial
    else:
        return cert, cakey, serial

def submit(statedir, password):
    """
    The main handler for SUBMIT operations.

    Take the signing request and build a certificate using the requested
    subject name and public key.  Add any requested extensions that we're not
    going to add on our own, then add the ones that we know values for.  Sign
    the result with a not-valid-after date that matches that of the signing
    certificate.

    Outputs the new certificate in PEM form on stdout and returns 0 to indicate
    success.
    """
    csr = x509.load_pem_x509_csr(os.environ[u"CERTMONGER_CSR"].encode('utf8'),
                                 backend=default_backend())
    cacert, cakey, serial = load_ca_cert_and_key_and_serial(statedir,
                                                            "ca.key",
                                                            password,
                                                            "ca.crt",
                                                            "ca.srl")
    extensions = []
    for ext in csr.extensions:
        if ext.oid != x509.ExtensionOID.BASIC_CONSTRAINTS:
            if ext.oid != x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                if ext.oid != x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                    extensions = extensions + [ext]
    builder = x509.CertificateBuilder(extensions=extensions)
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(cacert.subject)
    builder = builder.serial_number(serial + 1)
    now = datetime.datetime.utcnow()
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(cacert.not_valid_after)
    pubkey = csr.public_key()
    builder = builder.public_key(pubkey)
    ski = x509.SubjectKeyIdentifier.from_public_key(pubkey)
    builder = builder.add_extension(ski, False)
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key())
    builder = builder.add_extension(aki, False)
    basic = x509.BasicConstraints(ca=False, path_length=None)
    builder = builder.add_extension(basic, True)
    issued = builder.sign(cakey, hashes.SHA256(), default_backend())
    issuedbytes = issued.public_bytes(encoding=serialization.Encoding.PEM)
    save_ca_serial(statedir, "ca.srl", serial + 1)
    sys.stdout.write(issuedbytes.decode('utf8'))
    return 0

def identify():
    """
    The main handler for IDENTIFY operations.

    Outputs version information and exit with status 0 to indicate success.
    """
    sys.stdout.write("Local Signing Authority (local-cryptography.py 0.0)\n")
    return 0

def fetch_roots(statedir, password):
    """
    The main handler for FETCH-ROOTS operations.

    After ensuring we have at least one signing certificate, we scan the file
    in which we store the roots and output the PEM-formatted certificates, one
    by one, preceded by suggested nicknames to be used when they're saved to
    NSS databases.

    We're loading them from local disk, so we assume that their values are
    authenticated.  If we were retrieving them over a network, we'd have to
    make sure to read them over an authenticated channel in order to avoid
    potentially allowing a malicious party to inject their own certificate into
    the list of trusted certificates.

    Exit with status 0 to indicate success.
    """
    load_ca_cert_and_key_and_serial(statedir, "ca.key", password,
                                    "ca.crt", "ca.srl")
    try:
        cfile = open(os.path.join(statedir, "ca.crt"), mode="rb")
    except OSError:
        return 0
    certlines = cfile.readlines()
    cfile.close()
    certdata = bytes()
    which = 1
    for certline in certlines:
        certdata = certdata + certline
        if certline.decode('utf8').startswith("-----END CERTIFICATE-----"):
            if len(certdata) > 0:
                try:
                    cert = x509.load_pem_x509_certificate(certdata, backend=default_backend())
                    if which > 1:
                        sys.stdout.write("Local Signing Authority #%d\n" % which)
                    else:
                        sys.stdout.write("Local Signing Authority\n")
                    certbytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
                    sys.stdout.write(certbytes.decode('utf8'))
                    which = which + 1
                except IOError:
                    pass
            certdata = bytes()
    return 0

def main():
    """
    Consult $CERTMONGER_OPERATION to figure out what we're being asked to do.

    If the variable isn't set, assume it was meant to be "SUBMIT".
    If we have "SUBMIT" as a value, try to read the signing request from the
    environment.  If we fail to read one, try to read from stdin to make using
    this tool in a troubleshooting environment a little bit easier.

    We're hard-coded to store our data in /tmp, and encrypt private keys using
    a fixed password.

    If we don't know how to do what we're being asked, exit with status 6 to
    indicate that.
    """
    # We're going to need our own key and CA certificate, so decide where we're
    # storing our state.
    statedir = "/tmp"
    # The cryptography module refuses to let us save the key without encrypting
    # it with a non-empty password, so hardwire a password.
    password = b"password"
    # Create a lock under the state directory, because we may be about to
    # rewrite some files.
    lockfile = open(os.path.join(statedir, "ca.lock"), mode="wb")
    fcntl.lockf(lockfile, fcntl.LOCK_EX)

    # Default to the "SUBMIT" operation if one isn't set, and if we're in
    # "SUBMIT" mode and didn't get a CSR, try to read one from stdin.  This
    # isn't required by the daemon (it always sets the environment variable,
    # and connects our stdin to /dev/null), but it makes manual testing and
    # troubleshooting much, much easier.
    if os.getenv(u"CERTMONGER_OPERATION", "") == "":
        os.environ[u"CERTMONGER_OPERATION"] = u"SUBMIT"
    if os.getenv(u"CERTMONGER_OPERATION", u"SUBMIT") == u"SUBMIT":
        if os.getenv(u"CERTMONGER_CSR", "") == "":
            os.environ[u"CERTMONGER_CSR"] = sys.stdin.read()
    sys.stdin.close()

    # If the requested operation is one we support, do that.
    if os.getenv(u"CERTMONGER_OPERATION", "") == "IDENTIFY":
        sys.exit(identify())
    if os.getenv(u"CERTMONGER_OPERATION", "") == "SUBMIT":
        sys.exit(submit(statedir, password))
    if os.getenv(u"CERTMONGER_OPERATION", "") == "FETCH-ROOTS":
        sys.exit(fetch_roots(statedir, password))

    # The requested operation is not something we support.
    sys.exit(6)

main()
