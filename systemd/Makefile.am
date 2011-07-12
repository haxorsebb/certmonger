if SYSTEMD
unitsdir = @SYSTEMDSYSTEMUNITDIR@
units_DATA = certmonger.service certmonger.path
servicedir = @SYSTEMBUSSERVICESDIR@
service_DATA = org.fedorahosted.certmonger.service
endif
if TMPDIR
tmpfilesdir = $(sysconfdir)/tmpfiles.d
tmpfiles_DATA = certmonger.conf
endif
