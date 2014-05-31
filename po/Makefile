POTFILES=$(wildcard ../lib/*.pm) $(wildcard ../lib/GUI/*.pm) ../tinyca2
CATALOGS=de.mo es.mo cs.mo fr.mo sv.mo

all: $(CATALOGS)

.po.mo:
	msgfmt -o $@ $<
	install -m 644 $@ ../locale/`basename $@ .mo`/LC_MESSAGES/tinyca2.mo

%.po: tinyca2.pot
	msgmerge -vU $@ tinyca2.pot

tinyca2.pot: $(POTFILES)
	xgettext --add-comments \
		--keyword=_ \
		--keyword=N_ \
		--language=C \
		-o tinyca2.pot \
		$(POTFILES); \

clean:
	rm -f $(CATALOGS)
	rm -f tinyca2.pot

.SUFFIXES: .po .pot .mo
