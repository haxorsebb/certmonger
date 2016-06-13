#!/usr/bin/python
"""
 Basic certmonger helper, conforming to
 https://git.fedorahosted.org/cgit/certmonger.git/tree/doc/helpers.txt
 that calls a helper program, either locally or on another machine,
 while optionally logging inputs and outputs.
"""
import json
import os
import subprocess
import sys
import syslog

def remote(env, rsh, rcmd, log, priority):
    """
    Utility function to use 'rsh' to run 'rcmd' remotely, with the values in the
    'env' dictionary set in the environment.  If 'log' is True, it will log the
    variables and stderr that it gets back at the specified 'priority'.  Return the
    exit status and stdout contents.
    """
    # Encode the variables into a JSON document to make it easier to pass their
    # values along.
    envdoc = json.dumps(env, separators=(',', ':'))
    if log:
        for key in env.keys():
            syslog.syslog(priority,
                          "remote-submit: ENV: environment variable: %s=%s" %
                          (key, env[key]))

    # One-liner to decode a document, set variables, and then run the specified remote command.
    rargs = rcmd.split()
    script = "import json, os, sys; " + \
             "e = json.loads(sys.stdin.read()); " + \
             "[os.putenv(k,e[k]) for k in e]; " + \
             "os.execvp('%s',%s)" % (rargs[0], repr(rargs[:]))

    # Run that one liner remotely, and pipe the JSON document to its stdin.
    # Whether we need to quote the one-liner or not depends on whether or not
    # we're passing the command to rsh/ssh or just running it directly.
    if len(rsh.split()) == 0:
        quote = ""
    else:
        quote = "\""
    args = rsh.split() + ["python", "-c", quote+script+quote]
    sub = subprocess.Popen(args, shell=False,
                           stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           close_fds=True)
    stdout, stderr = sub.communicate(envdoc.encode('utf-8'))
    while sub.returncode is None:
        sub.wait()

    # Send back whatever the remote end gave us on stdout, and relay the exit
    # status.  The daemon called us with stdin and stderr connected to
    # /dev/null, so there's no need to bother with either of them.
    if log:
        syslog.syslog(priority, "remote-submit: OUT: result exit status: %d" % sub.returncode)
        if len(stdout) > 0:
            syslog.syslog(priority,
                          "remote-submit: STDOUT: result data (%d bytes):\n%s" %
                          (len(stdout), stdout.decode('utf-8')))
        else:
            syslog.syslog(priority, "remote-submit: STDOUT: (no result data)")
    for line in stderr.decode('utf-8').split("\n"):
        if len(line) > 0:
            syslog.syslog(priority, "remote-submit: STDERR: %s" % line)
    return sub.returncode, stdout

def get_certmonger_vars():
    """
    Returns a dictionary of the environment variables that tell the helper
    what's going on.  By convention, the variables that are relevant to helpers
    all start with CERTMONGER_, and this will continue to be the case as new
    variables are added.
    """
    env = {}
    for key in os.environ.keys():
        if key.startswith("CERTMONGER_"):
            env[key] = os.environ[key]
    return env

def main():
    """
    Wraps up the relevant environment variables in a JSON structure, uses a
    remote shell to run a python one-liner that sets those variables in its
    environment and then executes a specified binary, which we assume is a
    certmonger helper, and relays back the binary's exit status and output.

    A certmonger helper expects all of its input data to be in the environment,
    and communicates results using stdout and its exit status, so this is
    enough to run a helper remotely.

    Configuration is hard-coded.
    """
    # Configuration.  Note that the 'rsh' command is run as root by certmonger,
    # unattached to the context in which 'getcert' was run, so it can't prompt
    # for passwords or pass phrases.  Set 'rsh' to "" to run the helper
    # locally.
    rsh = "ssh centralbox"
    rcmd = "/usr/libexec/certmonger/local-submit"
    log = True
    priority = syslog.LOG_INFO

    # Default to the "SUBMIT" operation if one isn't set, and if we're in
    # "SUBMIT" mode and didn't get a CSR, try to read one from stdin.  This
    # isn't required by the daemon (it always sets the environment variable,
    # and connects our stdin to /dev/null), but it makes manual troubleshooting
    # much, much easier.
    env = get_certmonger_vars()
    if env.get("CERTMONGER_OPERATION") is None or env["CERTMONGER_OPERATION"] == "":
        env["CERTMONGER_OPERATION"] = "SUBMIT"
    if env["CERTMONGER_OPERATION"] == "SUBMIT":
        if env.get("CERTMONGER_CSR") is None or env["CERTMONGER_CSR"] == "":
            env["CERTMONGER_CSR"] = sys.stdin.read()
    sys.stdin.close()

    # Run the helper remotely, passing it the variables that we care about, and
    # relay its stdout and exit status.
    (code, stdout) = remote(env, rsh, rcmd, log, priority)
    sys.stdout.write(stdout.decode('utf-8'))
    sys.exit(code)

main()
