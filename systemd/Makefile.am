if SYSTEMD
unitsdir = @SYSTEMDSYSTEMUNITDIR@
units_DATA = certmonger.service
#units_DATA += certmonger.path
#servicedir = @SYSTEMBUSSERVICESDIR@
#service_DATA = org.fedorahosted.certmonger.service
endif
if TMPFILES
tmpfilesdir = $(prefix)/lib/tmpfiles.d
tmpfiles_DATA = certmonger.conf
endif
