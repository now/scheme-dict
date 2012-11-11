## Process this file with automake to create Makefile.in

sitedir = @GUILE_SITE@

bin_SCRIPTS = scheme-dict

install-data-local:
	$(mkinstalldirs) $(sitedir)
	$(mkinstalldirs) $(sitedir)/crypt $(sitedir)/inet $(sitedir)/util
	$(INSTALL_DATA) crypt/*.scm $(sitedir)/crypt
	$(INSTALL_DATA) inet/*.scm $(sitedir)/inet
	$(INSTALL_DATA) util/*.scm $(sitedir)/util
